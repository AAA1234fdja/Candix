import json

import pytest

from candix.agent.api_spec import Operation, Spec, ingest, parse_json_spec, parse_spec, parse_yaml_lite
from candix.agent.compliance import CONTROLS, evaluate, cwe_index, remediation_order
from candix.agent.graph import AssetGraph
from candix.agent.playbooks import BUILTIN, Playbook, PlaybookError, PlaybookPlanner, PlaybookRegistry, Step, values_for
from candix.agent.planner import HeuristicPlanner, PlannerState
from candix.agent.replay_kit import env_template, index, package, write
from candix.agent.scorecard import build, critical_gaps, from_result
from candix.agent.models import Goal, TaskResult
from candix.agent.web import Fetch, looks_like_soft_404, normalize_path
from candix.agent.web_probe import classify, findings_for, Discovery
from candix.agent.ws_probe import ATTACKER_ORIGINS, Result as WsResult, Attempt, findings_for as ws_findings, ws_url


# ------------------------------------------------------------------ api spec
SPEC = {
    "openapi": "3.0.1",
    "info": {"title": "Demo", "version": "2"},
    "servers": [{"url": "https://api.example.com"}],
    "paths": {
        "/users/{id}": {
            "get": {
                "operationId": "getUser",
                "summary": "Fetch a user",
                "parameters": [{"name": "id", "in": "path", "required": True}],
            },
            "delete": {"operationId": "deleteUser"},
        },
        "/login": {
            "post": {
                "requestBody": {"content": {"application/json": {"schema": {"properties": {"username": {}, "password": {}}}}}}
            }
        },
    },
    "components": {"securitySchemes": {"bearer": {"type": "http"}}, "schemas": {"User": {"type": "object"}}},
}


def test_parse_json_spec_builds_operations():
    spec = parse_json_spec(SPEC, "https://api.example.com/openapi.json")
    assert spec.count == 3
    assert spec.servers == ["https://api.example.com"]
    assert spec.security_schemes == {"bearer": "http"}
    assert "User" in spec.schemas
    login = [operation for operation in spec.operations if operation.path == "/login"][0]
    assert login.request_fields == ["password", "username"]
    assert spec.summary().startswith("3 operation(s)")


def test_yaml_spec_is_parsed():
    text = """
openapi: 3.0.0
info:
  title: Y
  version: "1"
paths:
  /ping:
    get:
      summary: Ping
      parameters:
        - name: verbose
          in: query
"""
    record = Fetch(url="https://a/openapi.yaml", status=200, headers={"content-type": "text/yaml"}, body=text)
    spec = parse_spec(record)
    assert spec is not None
    assert spec.operations[0].path == "/ping"
    assert spec.operations[0].parameters[0]["name"] == "verbose"


def test_ingest_adds_endpoints_and_parameters():
    graph = AssetGraph()
    spec = parse_json_spec(SPEC, "https://api.example.com/spec")
    counts = ingest(spec, graph, base="https://api.example.com")
    assert counts["endpoints"] >= 3
    assert counts["parameters"] >= 3
    assert graph.coverage()["parameters"] >= 3


def test_parse_spec_rejects_non_spec_body():
    record = Fetch(url="https://a/x", status=200, headers={"content-type": "text/html"}, body="<html>hi</html>")
    assert parse_spec(record) is None


# ------------------------------------------------------------------ web probe
def test_classify_sensitive_paths():
    assert classify("/.env")[1] == "high"
    assert classify("/db/dump.sql")[1] == "critical"
    assert classify("/about")[1] == ""


def test_web_probe_findings_only_for_sensitive_paths():
    rows = [
        Discovery(path="/.env", url="http://a/.env", status=200, length=40, marker="environment file", severity="high"),
        Discovery(path="/about", url="http://a/about", status=200, length=90),
    ]
    findings = findings_for(rows)
    assert len(findings) == 1
    assert findings[0]["severity"] == "high"


def test_soft_404_detection():
    reference = Fetch(url="http://a/x", status=200, body="x" * 200)
    same = Fetch(url="http://a/y", status=200, body="x" * 198)
    other = Fetch(url="http://a/y", status=200, body="x" * 500)
    assert looks_like_soft_404(same, reference)
    assert not looks_like_soft_404(other, reference)


def test_normalize_path():
    assert normalize_path("a/b") == "/a/b"
    assert normalize_path("/a") == "/a"


# ------------------------------------------------------------------ websocket
def test_ws_url_conversion():
    assert ws_url("https://a/b") == "wss://a/b"
    assert ws_url("http://a:8080/b?q=1") == "ws://a:8080/b?q=1"


def test_ws_findings_for_cross_origin():
    result = WsResult(endpoint="ws://a/ws", attempts=[Attempt("ws://a/ws", ATTACKER_ORIGINS[0], ok=True, status=101, accepted=True)])
    titles = [finding["title"] for finding in ws_findings(result)]
    assert "WebSocket accepts cross-origin handshakes" in titles


# ------------------------------------------------------------------ playbooks
def test_builtin_playbooks_are_valid():
    registry = PlaybookRegistry(BUILTIN)
    assert len(registry.names()) >= 4
    for name in registry.names():
        assert registry.get(name).validate() == []


def test_playbook_expands_placeholders():
    registry = PlaybookRegistry(BUILTIN)
    intents = registry.get("recon-sweep").expand(values_for(["https://app.example.com"]))
    assert intents
    assert intents[0].arguments["url"] == "https://app.example.com"
    assert intents[0].origin == "playbook"


def test_playbook_requires_values():
    playbook = Playbook(name="x", steps=[Step("http.request", arguments={"url": "{url}"})])
    with pytest.raises(PlaybookError):
        playbook.expand({})


def test_playbook_planner_seeds_then_falls_back():
    registry = PlaybookRegistry(BUILTIN)
    planner = PlaybookPlanner(registry.get("recon-sweep"), HeuristicPlanner())
    state = PlannerState(goal="assess", targets=["https://a"], coverage={"endpoints": 0}, remaining_turns=3)
    first = planner.decide(state)
    assert first.source == "playbook"
    assert len(first.intents) >= 3
    second = planner.decide(state)
    assert second.source != "playbook"


def test_playbook_registry_rejects_broken_playbook():
    with pytest.raises(PlaybookError):
        PlaybookRegistry([Playbook(name="broken", steps=[])])


def test_playbook_registry_loads_json(tmp_path):
    payload = {"name": "custom", "steps": [{"tool": "http.request", "arguments": {"url": "{url}"}}]}
    (tmp_path / "custom.json").write_text(json.dumps(payload), encoding="utf-8")
    registry = PlaybookRegistry()
    assert registry.load_directory(tmp_path) == 1
    assert registry.get("custom").steps[0].tool == "http.request"


# ------------------------------------------------------------------ scorecard
def test_scorecard_scores_coverage():
    graph = AssetGraph()
    node = graph.add_endpoint("GET", "http://a/x")
    graph.add_parameter(node.id, "q")
    card = build(
        findings=[{"id": "1", "title": "XSS", "severity": "high", "category": "xss", "verified": True}],
        assets=graph,
        attempted_tools={"recon.crawl", "recon.fingerprint", "detect.run", "http.request"},
        proofs=1,
        evidence=2,
        verified=1,
    )
    assert 0 < card.score <= 100
    assert card.grade in "ABCDEF"
    assert "| Category |" in card.markdown()
    assert card.to_dict()["summary"]


def test_scorecard_gaps_name_the_next_tool():
    card = build(findings=[], assets=None, attempted_tools=set())
    gaps = critical_gaps(card, limit=2)
    assert gaps and all("run " in hint for hint in gaps)


def test_scorecard_from_result():
    result = TaskResult(goal=Goal(statement="g"))
    result.findings.append({"id": "1", "title": "XSS", "severity": "high", "category": "xss", "verified": True})
    result.proofs.append({"claim": "g"})
    card = from_result(result, None, evidence=1)
    assert card.score > 0


# ------------------------------------------------------------------ compliance
def test_compliance_maps_findings_to_controls():
    report = evaluate([{"id": "1", "title": "XSS", "severity": "high", "category": "xss"}])
    assert len(report.statuses) == len(CONTROLS)
    assert any(status.control.id == "V5.3" for status in report.failed)
    assert report.score() < 100
    assert "failed" in report.to_dict()
    assert "| Control |" in report.markdown()


def test_compliance_cwe_index_and_order():
    findings = [
        {"id": "1", "title": "SQLi", "severity": "critical", "category": "sqli", "cwe": ["CWE-89"]},
        {"id": "2", "title": "Headers", "severity": "low", "category": "headers", "cwe": ["CWE-16"]},
    ]
    assert cwe_index(findings)["CWE-89"] == 1
    ordered = remediation_order(findings)
    assert ordered[0]["title"] == "SQLi"


# ------------------------------------------------------------------ replay kit
def test_replay_package_generates_scripts(tmp_path):
    payload = {
        "title": "IDOR",
        "request": {
            "url": "http://a/users?id=2",
            "method": "GET",
            "headers": {"Authorization": "Bearer secret", "Accept": "*/*"},
        },
    }
    bundle = package(payload)
    curl = bundle.curl()
    assert "Authorization" not in curl
    assert "Accept" in curl
    files = write([bundle], tmp_path)
    assert len(files) == 4
    assert any(path.endswith(".sh") for path in files)
    assert "## 1. IDOR" in index([bundle])
    assert "AUTHORIZATION=changeme" in env_template([bundle])


def test_replay_package_reads_nested_exchange():
    bundle = package({"title": "x", "exchange": {"request": {"url": "http://a", "method": "POST", "body": "a=1"}}})
    assert bundle.method == "POST"
    assert "--data-raw 'a=1'" in bundle.curl()


def test_playbook_requires_endpoints_before_seeding():
    from candix.agent.playbooks import default_registry
    from candix.agent.planner import Decision, HeuristicPlanner, PlannerState

    class Fallback:
        def decide(self, state):
            return Decision("plan", "fallback", [], 0.5, "test")

    registry = default_registry()
    playbook = registry.get("injection-sweep")
    planner = __import__("candix.agent.playbooks", fromlist=["PlaybookPlanner"]).PlaybookPlanner(playbook, Fallback(), values={"url": "http://a"})
    empty = PlannerState(goal="g", targets=["http://a"], remaining_turns=3)
    assert planner.decide(empty).reasoning == "fallback"

    from candix.agent.graph import AssetGraph

    graph = AssetGraph()
    graph.add_endpoint("GET", "http://a/x?q=1")
    filled = PlannerState(goal="g", targets=["http://a"], coverage=graph.coverage(), remaining_turns=3)
    decision = planner.decide(filled)
    assert decision.source == "playbook"
    assert [intent.tool for intent in decision.intents][:1] == ["detect.run"]


def test_every_builtin_playbook_expands_with_values():
    from candix.agent.playbooks import default_registry, values_for

    registry = default_registry()
    values = values_for(["http://a"], goal="assess")
    for name in registry.names():
        playbook = registry.get(name)
        intents = playbook.expand(values)
        assert intents, name
        assert all(intent.tool for intent in intents)
