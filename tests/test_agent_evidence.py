import json

import pytest

from candix.agent.contracts import Contract, Field, catalogue, register, validate
from candix.agent.evidence_chain import EvidenceChain, build_chain, export_markdown
from candix.agent.graph import AssetGraph
from candix.agent.memory import Lesson, MemoryStore
from candix.agent.models import Goal, Intent, Phase, TaskResult
from candix.agent.report_bridge import BridgeOptions, proof_markdown, render_many, to_model
from candix.agent.retrieval import Snippet, build_context
from candix.agent.simulator import estimate_intent, simulate
from candix.agent.skills import SkillRegistry
from candix.agent.triage import merge_priority, triage


# ------------------------------------------------------------------ evidence
def test_chain_detects_tampering():
    chain = EvidenceChain()
    chain.bind_finding({"id": "f1", "title": "XSS", "severity": "high", "url": "http://a/q"})
    chain.bind_exchange(finding_id="f1", endpoint_id="ep", request={"url": "http://a/q"}, response={"status": 200})
    assert chain.verify() == []
    chain.records[0].body["url"] = "http://a/other"
    assert chain.verify()


def test_chain_redacts_auth_headers():
    chain = EvidenceChain()
    record = chain.bind_exchange(
        finding_id="f1",
        endpoint_id="ep",
        request={"url": "http://a", "headers": {"Authorization": "Bearer secret", "Accept": "*/*"}},
        response={"status": 200, "headers": {"Set-Cookie": "sid=abc"}},
    )
    headers = record.body["request"]["headers"]
    assert headers["Authorization"] == "[redacted]"
    assert headers["Accept"] == "*/*"
    assert record.body["response"]["headers"]["Set-Cookie"] == "[redacted]"


def test_chain_roundtrip_and_bundle(tmp_path):
    chain = EvidenceChain()
    chain.bind_fact({"id": "x1", "claim": "endpoint is public", "source": "tool_output"})
    path = chain.save(tmp_path / "chain.json")
    loaded = EvidenceChain.load(path)
    assert loaded.verify() == []
    assert loaded.kinds() == {"fact": 1}
    assert loaded.bundle()["count"] == 1


def test_chain_markdown_export():
    chain = EvidenceChain()
    chain.bind_proof({"claim": "goal", "summary": "proved"})
    text = export_markdown(chain)
    assert "Evidence chain" in text
    assert chain.head()[:12] in text


def test_build_chain_from_result():
    result = TaskResult(goal=Goal(statement="g"))
    result.findings.append({"id": "f1", "title": "SQLi", "severity": "high", "url": "http://a/p?id=1"})
    result.proofs.append({"claim": "g", "summary": "ok"})
    chain = build_chain(result)
    assert chain.kinds() == {"finding": 1, "proof": 1}
    assert chain.verify() == []


# ------------------------------------------------------------------ contracts
def test_contract_validation_and_coercion():
    contract = Contract("t", [Field("status", "int"), Field("body", "str", required=False)])
    register(contract)
    ok = validate("t", {"status": "200"})
    assert ok.ok and ok.payload["status"] == 200
    bad = validate("t", {"body": 1})
    assert not bad.ok
    assert any("status" in problem for problem in bad.problems)


def test_contract_catalogue_lists_tools():
    tools = {entry["tool"] for entry in catalogue()}
    assert {"detect.run", "exploit.run", "goal.prove"} <= tools


# ------------------------------------------------------------------ triage
def test_triage_merges_duplicates_and_ranks():
    findings = [
        {"id": "1", "title": "Reflected XSS in search", "severity": "high", "url": "http://a/s?q=", "verified": True},
        {"id": "2", "title": "Reflected XSS in search query", "severity": "high", "url": "http://a/s?q=", "parameter": "q"},
        {"id": "3", "title": "Missing security headers", "severity": "low", "url": "http://a/"},
    ]
    result = triage(findings)
    assert result.duplicates == 1
    assert result.ranked[0].finding["severity"] == "high"
    assert result.risk > 0
    assert result.grade in {"A", "B", "C", "D", "E", "F"}


def test_triage_empty_is_neutral():
    result = triage([])
    assert result.risk == 0.0
    assert result.grade == "n/a"
    assert result.to_dict()["summary"]


def test_merge_priority_annotates_findings():
    annotated = merge_priority([{"id": "1", "title": "SQLi", "severity": "critical", "url": "http://a"}])
    assert annotated[0]["priority"] > 0
    assert annotated[0]["priority_reasons"]


# ------------------------------------------------------------------ report bridge
def make_result() -> TaskResult:
    result = TaskResult(goal=Goal(statement="assess"))
    result.intents.append(Intent("crawl", phase=Phase.RECON, tool="recon.crawl", status="done", result="4 pages"))
    result.findings.append(
        {"id": "f1", "title": "XSS", "severity": "high", "url": "http://a/?q=1", "verified": True, "description": "x"}
    )
    result.proofs.append({"claim": "assess", "summary": "proved", "title": "proof"})
    result.stop_reason = "goal proven"
    return result


def test_report_bridge_renders_multiple_formats():
    result = make_result()
    snapshot = {"budget": {"turns": 1}, "coverage": {"endpoints": 2}, "triage": {"risk": 12.0}}
    outputs = render_many(result, ["markdown", "json", "sarif", "junit"], snapshot)
    assert set(outputs) == {"markdown", "json", "sarif", "junit"}
    assert all(len(body) > 20 for body in outputs.values())
    model = to_model(result, snapshot, options=BridgeOptions(title="Lab"))
    assert model.findings and model.proofs
    assert model.stats["agent"]["stop_reason"] == "goal proven"


def test_report_bridge_unknown_format_is_contained():
    output = render_many(make_result(), ["nonsense"])
    assert output["nonsense"].startswith("error:")


def test_proof_markdown_includes_request():
    text = proof_markdown(
        {"title": "IDOR", "summary": "read foreign profile", "request": {"url": "http://a/u?id=2", "method": "GET"}}
    )
    assert "GET http://a/u?id=2 HTTP/1.1" in text


# ------------------------------------------------------------------ simulator
def test_simulator_estimates_and_flags_blocked():
    session = None
    from candix.agent.policy import RiskPolicy

    policy = RiskPolicy()
    crawl = Intent("crawl", phase=Phase.RECON, tool="recon.crawl", arguments={"max_pages": 5})
    exploit = Intent("exploit", phase=Phase.EXPLOIT, tool="exploit.run", arguments={"max_attempts": 2})
    simulation = simulate([crawl, exploit], policy=policy)
    assert simulation.requests >= 5
    assert len(simulation.blocked()) == 1
    assert estimate_intent(crawl, policy=policy).seconds > 0


# ------------------------------------------------------------------ retrieval
def test_retrieval_selects_relevant_snippets():
    snippets = [
        Snippet("lesson", "exclude reflected payloads from xss matching"),
        Snippet("fact", "login returns 200 for any password"),
        Snippet("journal", "detect.run failed: timeout"),
    ]
    text = build_context("xss false positive", result=None, facts=[], skills=[])
    assert isinstance(text, str)
    from candix.agent.retrieval import Retriever

    chosen = Retriever().select("xss reflection", snippets)
    assert chosen[0].text.startswith("exclude")


# ------------------------------------------------------------------ memory/skills
def test_memory_store_learns_and_ranks(tmp_path):
    store = MemoryStore(tmp_path / "memory.json")
    store.add(Lesson("prefer a control request before reporting xss"))
    store.add(Lesson("the lab rate limits after 50 requests"))
    store.reward("prefer a control request before reporting xss", win=True)
    hits = store.search("xss control request")
    assert hits and "xss" in hits[0].text
    store.save()
    assert MemoryStore(tmp_path / "memory.json").search("xss")


def test_skill_registry_loads_repo_skills():
    registry = SkillRegistry.load("skills")
    assert len(registry.skills) >= 5
    assert registry.validate() == []
    selected = registry.select("prove an idor on the api", phase="detect")
    assert selected and selected[0].name
