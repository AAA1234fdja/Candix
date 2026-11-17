import json

from candix.agent.audit import audit, gate, markdown as audit_markdown
from candix.agent.diffing import compare, from_files, regression_gate, summary_table
from candix.agent.evidence_chain import EvidenceChain
from candix.agent.facts import Fact, FactSource
from candix.agent.insights import bottlenecks, collect, compare as compare_profiles, export_markdown
from candix.agent.metrics_export import Metrics, cost_per_finding, from_result, summary as metrics_summary, zero_fill
from candix.agent.models import Goal, Intent, Phase, TaskResult
from candix.agent.prompting import Brief, check_brief, planner_brief, reflection_brief, worker_brief
from candix.agent.session import AgentSession, AgentSettings
from candix.agent.state_io import StateError, SessionState, capture, merge_states, pending_intents, restore, summary
from candix.agent.todolist import DONE, Todo, TodoList, from_prompt
from candix.core.config import Config


def make_session(goal="assess"):
    return AgentSession.create(["http://127.0.0.1:9"], config=Config.profile("lab"), settings=AgentSettings(goal=goal, use_llm=False))


# ------------------------------------------------------------------ state
def test_state_roundtrip_preserves_graph_and_facts():
    session = make_session()
    session.assets.add_endpoint("GET", "http://x/a?q=1")
    session.blackboard.facts.add(Fact("endpoint is public", FactSource.TOOL_OUTPUT, subject="http://x/a"))
    state = capture(session, intents=[Intent("crawl", phase=Phase.RECON, tool="recon.crawl", status="failed")])
    assert "1 endpoint" in summary(state) or "endpoint(s)" in summary(state)

    restored = make_session()
    applied = restore(restored, state)
    assert applied["facts"] == 1
    assert restored.assets.coverage()["endpoints"] == 1
    assert len(restored.blackboard.facts.facts) == 1
    assert [intent.title for intent in pending_intents(state)] == ["crawl"]


def test_state_save_load(tmp_path):
    state = SessionState(run_id="r1", goal="g", targets=["http://a"])
    path = state.save(tmp_path / "state.json")
    loaded = SessionState.load(path)
    assert loaded.run_id == "r1"
    assert loaded.version >= 1


def test_state_rejects_future_version(tmp_path):
    path = tmp_path / "state.json"
    path.write_text(json.dumps({"version": 999}), encoding="utf-8")
    try:
        SessionState.load(path)
    except StateError:
        return
    raise AssertionError("expected StateError")


def test_state_merge_keeps_newer_facts():
    first = SessionState(run_id="a", facts=[{"claim": "one"}])
    second = SessionState(run_id="b", facts=[{"claim": "two"}], attempts={"recon.crawl": 3})
    merged = merge_states(first, second)
    assert {item["claim"] for item in merged.facts} == {"one", "two"}
    assert merged.attempts["recon.crawl"] == 3


# ------------------------------------------------------------------ todos
def test_todolist_priority_and_completion(tmp_path):
    todos = TodoList(tmp_path / "todos.json")
    low = todos.add("check headers", priority=0.2)
    high = todos.add("retry detect.run", priority=0.9)
    assert todos.next() is high
    claimed = todos.claim_next()
    assert claimed is high and claimed.attempts == 1
    todos.complete(claimed, evidence=["journal:42"])
    assert claimed.status == DONE
    assert todos.prompt_block().count("-") == 1
    assert todos.summary().startswith("2 todo(s)")
    low.park("waiting for approval")
    assert low.blocked_by


def test_todolist_persists(tmp_path):
    path = tmp_path / "todos.json"
    first = TodoList(path)
    first.add("keep me")
    second = TodoList(path)
    assert len(second.items) == 1


def test_todolist_seed_from_result_and_prompt():
    result = TaskResult(goal=Goal(statement="g"))
    result.intents.append(Intent("crawl", phase=Phase.RECON, tool="recon.crawl", status="failed", result="timeout"))
    result.lessons.append({"text": "detect.run was slow"})
    todos = TodoList()
    assert todos.seed_from_result(result) >= 1
    assert from_prompt("- do the thing properly\n- another long action") == ["do the thing properly", "another long action"]


# ------------------------------------------------------------------ insights
def test_insights_identify_budget_and_proof_gaps():
    result = TaskResult(goal=Goal(statement="g"))
    result.stop_reason = "turn budget exhausted (6)"
    result.intents.append(Intent("detect", phase=Phase.DETECT, tool="detect.run", status="done"))
    result.findings.append({"id": "1", "title": "XSS", "severity": "high", "category": "xss", "url": "http://a"})
    report = collect(result)
    kinds = {insight.kind for insight in report.insights}
    assert "budget" in kinds and "proof" in kinds
    assert report.tool_calls == 1
    assert "tool call" in report.summary()
    assert "Insights" in export_markdown(report)


def test_insights_compare_profiles():
    first = collect(TaskResult(goal=Goal(statement="g")))
    result = TaskResult(goal=Goal(statement="g"))
    result.intents.append(Intent("crawl", phase=Phase.RECON, tool="recon.crawl", status="done"))
    second = collect(result)
    diff = compare_profiles(first, second)
    assert "recon.crawl" in diff["added_tools"]
    assert bottlenecks(second)


# ------------------------------------------------------------------ diffing
def test_diffing_detects_new_and_fixed():
    before = [{"title": "A", "severity": "low", "url": "u", "category": "c"}]
    after = [
        {"title": "A", "severity": "high", "url": "u", "category": "c"},
        {"title": "B", "severity": "medium", "url": "v", "category": "c"},
    ]
    diff = compare(before, after)
    assert [change.finding["title"] for change in diff.new] == ["B"]
    assert [change.finding["title"] for change in diff.escalated] == ["A"]
    assert diff.counts()["new"] == 1
    ok, reason = regression_gate(diff, fail_on="high")
    assert not ok and "escalated" in reason
    assert "change,count" in summary_table(diff)
    assert "| new |" in diff.markdown()


def test_diffing_from_files(tmp_path):
    first = tmp_path / "a.json"
    second = tmp_path / "b.json"
    first.write_text(json.dumps({"findings": [{"title": "A", "severity": "low", "url": "u", "category": "c"}]}), encoding="utf-8")
    second.write_text(json.dumps({"findings": []}), encoding="utf-8")
    diff = from_files(first, second)
    assert diff.counts()["fixed"] == 1


# ------------------------------------------------------------------ audit
def test_audit_flags_out_of_scope_and_secrets():
    chain = EvidenceChain()
    chain.bind_finding({"id": "f1", "title": "X"})
    result = audit(
        targets=["http://app.example"],
        attempted_urls=["http://app.example/a", "http://other.example/b"],
        tool_calls={"detect.run": 5},
        caps={"detect.run": 2},
        prompts=["-----BEGIN OPENSSH PRIVATE KEY-----"],
        evidence=chain,
    )
    kinds = {violation.kind for violation in result.violations}
    assert {"scope", "budget", "data"} <= kinds
    ok, reason = gate(result, max_severity="medium")
    assert not ok and "violation" in reason
    assert "| scope_respected | fail |" in audit_markdown(result)


def test_audit_clean_case():
    result = audit(targets=["http://app.example"], attempted_urls=["http://app.example/a"])
    assert result.clean
    assert gate(result)[0]


# ------------------------------------------------------------------ metrics
def test_metrics_export_prometheus():
    result = TaskResult(goal=Goal(statement="g"))
    result.intents.append(Intent("crawl", phase=Phase.RECON, tool="recon.crawl", status="done"))
    result.findings.append({"id": "1", "title": "XSS", "severity": "high"})
    metrics = from_result(result, extra_labels={"run": "r1"})
    text = metrics.prometheus()
    assert "candix_agent_findings" in text
    assert 'run="r1"' in text
    assert metrics_summary(metrics).endswith("series")
    assert cost_per_finding(metrics) == 0.0
    zero_fill(metrics, ["missing_metric"])
    assert any(sample.name == "missing_metric" for sample in metrics.samples)
    assert metrics.openmetrics().endswith("# EOF\n")


# ------------------------------------------------------------------ prompting
def test_planner_brief_contains_state():
    from candix.agent.graph import AssetGraph
    from candix.agent.planner import PlannerState

    graph = AssetGraph()
    graph.add_endpoint("GET", "http://a/x?q=1")
    state = PlannerState(goal="assess", targets=["http://a"], coverage=graph.coverage(), attempted=["recon.crawl"], remaining_turns=3)
    brief = planner_brief(state, assets=graph)
    assert brief.system
    assert "coverage" in brief.user
    assert check_brief(brief) == []


def test_worker_and_reflection_briefs():
    brief = worker_brief(Intent("crawl", phase=Phase.RECON, tool="recon.crawl"), goal="assess")
    assert "crawl" in brief.user
    result = TaskResult(goal=Goal(statement="assess"))
    result.stop_reason = "goal proven"
    assert reflection_brief(result).tokens > 0
    assert check_brief(Brief())


def test_brief_ceiling_is_enforced():
    from candix.agent.planner import PlannerState

    state = PlannerState(goal="g" * 5000, targets=["http://a"], remaining_turns=3)
    brief = planner_brief(state, max_tokens=120)
    assert brief.tokens <= 200
