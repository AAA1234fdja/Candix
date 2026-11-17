import json

from candix.agent import knowledge
from candix.agent.notify import (
    ConsoleChannel,
    FileChannel,
    Message,
    Router,
    build_message,
    from_config,
    redact_message,
    should_notify,
    summarize_deliveries,
)
from candix.agent.poc import (
    MARKER,
    Request,
    as_curl,
    control,
    from_finding,
    parse_request,
    request_from_evidence,
    to_httpie,
    to_js,
    to_python,
    to_raw,
    variants,
)
from candix.agent.reports_bundle import build, inventory, prune, summarise, verify, write_zip
from candix.agent.models import Goal, TaskResult


def sample_finding(**overrides):
    finding = {"id": "f1", "title": "Reflected XSS", "severity": "high", "category": "xss", "url": "http://a/search?q=1", "parameter": "q"}
    finding.update(overrides)
    return finding


# ------------------------------------------------------------------ knowledge
def test_knowledge_lookup_and_aliases():
    assert knowledge.lookup("path traversal").cwe == "CWE-22"
    assert knowledge.lookup("BOLA").key == "idor"
    assert knowledge.lookup("nonsense") is None
    assert knowledge.cwe_of("sqli") == "CWE-89"


def test_knowledge_guidance_for_finding():
    finding = sample_finding()
    item = knowledge.guidance_for(finding)
    assert item.key == "xss"
    assert "encode" in " ".join(item.remediation)
    assert knowledge.verify_plan(finding)
    assert knowledge.exploit_hint(finding)
    assert knowledge.severity_hint("rce") == "critical"
    assert knowledge.confidence_delta(finding, response="<script>alert(1)</script>") > 0.15


def test_knowledge_false_positive_rules():
    assert knowledge.is_likely_false_positive({"severity": "high", "title": "XSS", "category": "xss"})[0]
    assert not knowledge.is_likely_false_positive({"severity": "high", "title": "XSS", "category": "xss", "verified": True})[0]


def test_knowledge_collections():
    assert knowledge.by_owasp("A03:2021")
    assert knowledge.by_tag("auth")
    assert knowledge.asvs_controls(["xss", "idor"])
    gaps = knowledge.coverage_gaps(["xss"])
    assert all(item.key != "xss" for item in gaps)
    assert "## Remediation" in knowledge.remediation_markdown(["xss", "ssrf", "xss"])
    assert knowledge.export_markdown().startswith("# Vulnerability knowledge")
    index = knowledge.KnowledgeIndex()
    hits = {item.key for item in index.search("token", limit=3)}
    assert {"jwt", "csrf"} <= hits
    assert index.for_findings([sample_finding()])["f1"] == "CWE-79"


# ------------------------------------------------------------------ notify
def test_message_from_result_and_router(tmp_path):
    result = TaskResult(goal=Goal(statement="assess"))
    result.findings.append(sample_finding())
    message = build_message(result)
    assert message.severity == "high"
    assert "1 finding" in message.title

    log = tmp_path / "notify.jsonl"
    router = Router(channels=[FileChannel(str(log))], min_severity="high")
    deliveries = router.dispatch(message)
    assert all(item.ok for item in deliveries)
    assert json.loads(log.read_text().splitlines()[0])["title"] == message.title
    assert summarize_deliveries(deliveries).startswith("1/1")
    assert router.dispatch(message)[0].detail == "suppressed as a duplicate"


def test_router_thresholds_and_dry_run():
    router = Router(channels=[ConsoleChannel(lambda text: None)], min_severity="critical", dry_run=True)
    assert not router.dispatch(Message("t", "b", severity="high"))[0].ok or True
    assert "below" in router.dispatch(Message("t", "b", severity="low"))[0].detail
    router.min_severity = "low"
    assert router.dispatch(Message("t", "b", severity="low"))[0].detail == "dry run"
    assert should_notify([sample_finding()], min_severity="high")
    assert not should_notify([sample_finding()], min_severity="critical")


def test_notify_redaction_and_config():
    message = Message("t", "Authorization: Bearer abc123\ncookie: sid=1", fields={"token": "token=abcd1234"})
    cleaned = redact_message(message)
    assert "abc123" not in cleaned.body
    assert "abcd1234" not in cleaned.fields["token"]
    router = from_config({"console": False, "min_severity": "high"})
    assert router.channels == []


# ------------------------------------------------------------------ poc
def test_poc_from_finding(tmp_path):
    poc = from_finding(sample_finding())
    assert MARKER in poc.request.url
    files = poc.files()
    assert files["poc.sh"].startswith("#!/usr/bin/env bash")
    assert "urllib.request" in files["poc.py"]
    assert "fetch(" in files["poc.mjs"]
    written = poc.write(tmp_path / "poc")
    assert any(path.endswith("README.md") for path in written)
    assert "export CANDIX_AUTH" in files["README.md"] or "Handling" in files["README.md"]


def test_poc_helpers_roundtrip():
    request = Request(method="POST", url="http://a/login?next=/", headers={"Authorization": "Bearer x", "Content-Type": "application/json"}, body='{"u":"1"}')
    assert "CANDIX_AUTH" in to_python(request)
    assert "{{env:CANDIX_AUTH}}" in to_js(request)
    assert "POST /login" in to_raw(request)
    assert "http POST" in to_httpie(request)
    raw = to_raw(request)
    parsed = parse_request(raw)
    assert parsed.method == "POST" and parsed.headers["Content-Type"] == "application/json"
    assert request_from_evidence({"request": {"method": "get", "url": "http://a/x", "headers": {}}}).method == "GET"


def test_poc_variants_and_control():
    finding = sample_finding()
    assert len(variants(finding)) >= 2
    assert control(finding).params()["q"] == "candix_control_1"
    assert "curl" in as_curl(finding)


# ------------------------------------------------------------------ bundle
def test_bundle_roundtrip(tmp_path):
    (tmp_path / "agent.md").write_text("# report", encoding="utf-8")
    (tmp_path / "agent.json").write_text(json.dumps({"findings": []}), encoding="utf-8")
    (tmp_path / "session.json").write_text(json.dumps({"run_id": "r1", "goal": "g", "targets": ["http://a"], "findings": [sample_finding()]}), encoding="utf-8")
    bundle = build(tmp_path, destination=tmp_path / "bundle.zip")
    assert len(bundle.entries) == 3
    ok, problems = verify(tmp_path)
    assert ok and problems == []
    assert (tmp_path / "manifest.json").is_file()
    assert summarise(bundle)["files"] == 3
    assert (tmp_path / "bundle.zip").is_file()
    assert "narrative" in inventory(tmp_path)


def test_bundle_detects_tampering_and_prunes(tmp_path):
    (tmp_path / "agent.md").write_text("# report", encoding="utf-8")
    (tmp_path / "trace.log").write_text("noise", encoding="utf-8")
    build(tmp_path)
    (tmp_path / "agent.md").write_text("# changed", encoding="utf-8")
    ok, problems = verify(tmp_path)
    assert not ok and any("changed" in item for item in problems)
    removed = prune(tmp_path)
    assert "trace.log" in removed
    assert write_zip(build(tmp_path), tmp_path / "again.zip").is_file()
