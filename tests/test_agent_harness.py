import ast
import json
from pathlib import Path

import pytest

from candix.agent.graph import AssetGraph
from candix.agent.harness import Harness, HarnessSettings, status
from candix.agent.intercept import CommandGate, TargetGate
from candix.agent.models import Goal, TaskResult
from candix.agent.planner import HeuristicPlanner, PlannerState
from candix.agent.tools import Tool, ToolContext, ToolRegistry

ROOT = Path(__file__).resolve().parents[1]


def finding(**overrides):
    payload = {
        "id": "f1",
        "title": "Reflected XSS",
        "severity": "high",
        "category": "xss",
        "url": "https://app.example/search?q=1",
        "parameter": "q",
    }
    payload.update(overrides)
    return payload


def make_result(*findings):
    result = TaskResult(goal=Goal(statement="assess the target"))
    result.findings.extend(findings or [finding()])
    result.stop_reason = "goal proven"
    return result


def echo_tool(calls):
    def handler(ctx, args):
        calls.append(dict(args))
        return {"summary": "ran", "ok": True}

    return handler


def registry_with(calls, name="http.request"):
    return ToolRegistry([Tool(name, "test tool", echo_tool(calls), {"type": "object", "properties": {}})])


# ------------------------------------------------------------------ tool gate
def lab_session(tmp_path, **overrides):
    from candix.agent.policy import AutonomyLevel
    from candix.agent.session import AgentSession, AgentSettings
    from candix.core.config import Config
    from candix.core.scope import Engagement, build_authorization
    from candix.lab import build_server

    server = build_server("127.0.0.1", 0)
    server.start()
    config = Config.profile("lab")
    config.set("scan.max_rps", 200.0)
    document = build_authorization(
        engagement="harness",
        client="harness",
        operator="pytest",
        authorized_by="pytest",
        include=[f"127.0.0.1:{server.port}"],
        max_rps=200.0,
    )
    settings = AgentSettings(
        goal="map the lab",
        autonomy=AutonomyLevel.AUTO,
        use_llm=False,
        approve_mode="auto",
        artifacts_dir=str(tmp_path),
        **overrides,
    )
    session = AgentSession.create(
        [server.base_url],
        config=config,
        engagement=Engagement.from_document(document),
        settings=settings,
    )
    return server, session


def test_session_puts_the_gate_in_the_tool_path(tmp_path):
    server, session = lab_session(tmp_path, gate_max_risk=5)
    try:
        result = session.registry.execute("http.request", {"url": server.base_url + "/"}, session.tool_context)
    finally:
        server.stop()
    assert result.ok is False
    assert result.decision is not None and result.decision.rule == "risk"
    assert session.harness.blocked and session.harness.blocked[0]["kind"] == "risk"
    counters = session.tool_context.telemetry.snapshot()["counters"]
    assert counters["tools.blocked"] == 1


def test_session_allows_the_same_call_with_the_default_ceiling(tmp_path):
    server, session = lab_session(tmp_path)
    try:
        result = session.registry.execute("http.request", {"url": server.base_url + "/"}, session.tool_context)
    finally:
        server.stop()
    assert result.ok is True
    assert session.harness.blocked == []


def test_session_finish_writes_harness_artifacts(tmp_path):
    server, session = lab_session(tmp_path)
    server.stop()
    result = make_result()
    summary = session.harness.finish(result)
    assert summary["poc"] >= 1
    assert (tmp_path / "review.json").is_file()
    snapshot = session.snapshot(result)
    assert snapshot["harness"]["review"]["total"] == 1

def test_gate_blocks_out_of_scope_tool_calls():
    harness = Harness(targets=["https://app.example"], settings=HarnessSettings(artifacts=""))
    calls = []
    registry = registry_with(calls)
    context = ToolContext(interceptor=harness)
    result = registry.execute("http.request", {"url": "https://evil.test/x"}, context)
    assert result.ok is False
    assert "outside the declared scope" in result.error
    assert calls == []
    assert context.telemetry.snapshot()["counters"]["tools.blocked"] == 1
    assert harness.blocked and harness.blocked[0]["kind"] == "target"


def test_gate_allows_in_scope_requests():
    harness = Harness(targets=["https://app.example"], settings=HarnessSettings())
    calls = []
    context = ToolContext(interceptor=harness)
    result = registry_with(calls).execute("http.request", {"url": "https://app.example/x"}, context)
    assert result.ok is True
    assert calls and harness.blocked == []


def test_gate_blocks_on_risk_threshold():
    harness = Harness(targets=["https://app.example"], settings=HarnessSettings(max_risk=20))
    calls = []
    context = ToolContext(interceptor=harness)
    result = registry_with(calls, name="made.up.tool").execute("made.up.tool", {}, context)
    assert result.ok is False
    assert result.decision.rule == "risk"
    assert calls == []


def test_gate_fails_closed_when_it_crashes():
    class Broken:
        def check_tool(self, name, arguments):
            raise RuntimeError("gate exploded")

    calls = []
    context = ToolContext(interceptor=Broken())
    result = registry_with(calls).execute("http.request", {"url": "https://app.example/x"}, context)
    assert result.ok is False
    assert "gate failed" in result.error
    assert calls == []


def test_gate_can_be_disabled_and_reports_nothing():
    harness = Harness(targets=["https://app.example"], settings=HarnessSettings(gate=False))
    assert harness.check_tool("http.request", {"url": "https://evil.test"}) is None
    calls = []
    context = ToolContext(interceptor=harness)
    assert registry_with(calls).execute("http.request", {"url": "https://evil.test/x"}, context).ok is True


def test_command_gate_denylist_allowlist_and_targets():
    harness = Harness(targets=["https://app.example"], settings=HarnessSettings(allowed_prefixes=("notify-send",)))
    assert harness.check_command("rm -rf /").allowed is False
    assert harness.check_command("notify-send hi").allowed is True
    assert harness.check_command("curl https://metadata.google.internal/").allowed is False
    assert harness.check_command("python3 -c 'import os'").rule == "denylist"
    blocked = harness.check_command("notify-send hi", targets=["https://evil.test"])
    assert blocked.allowed is False and blocked.rule == "target"
    assert harness.gate_summary()["blocked"] == 4


def test_target_gate_flags_metadata_and_private_ranges():
    open_gate = TargetGate()
    assert open_gate.check("169.254.169.254").rule == "metadata"
    assert open_gate.check("metadata.google.internal").rule == "metadata"
    assert open_gate.check("192.168.1.1").rule == "private"
    cidr = TargetGate(allow=("10.0.0.0/8",))
    assert cidr.check("10.1.2.3:8080").allowed is True
    assert cidr.check("192.168.1.1").rule == "scope"


# --------------------------------------------------------------------- todos
def test_events_keep_the_todo_list_honest(tmp_path):
    harness = Harness(settings=HarnessSettings(artifacts=str(tmp_path)))
    harness.on_event("intent.start", {"title": "Crawl the landing page", "tool": "recon.crawl"})
    harness.on_event("intent.start", {"title": "Probe the API", "tool": "web.probe"})
    harness.on_event("intent.finish", {"title": "Crawl the landing page", "ok": True, "summary": "12 endpoints"})
    harness.on_event("intent.blocked", {"title": "Probe the API", "reason": "outside scope"})
    states = {item.text: item.status for item in harness.todos.items}
    assert states["Crawl the landing page"] == "done"
    assert states["Probe the API"] == "parked"
    assert "done=1" in harness.todos.summary()
    assert (tmp_path / "todos.json").is_file()
    assert harness.plan_extras(AssetGraph(), [])["todos"]


def test_todo_list_carries_failures_into_the_next_run(tmp_path):
    harness = Harness(settings=HarnessSettings(artifacts=str(tmp_path)))
    result = make_result()
    result.lessons = [{"text": "slow: tool.detect.run"}]
    harness.finish(result)
    assert any("detect.run" in item.text or "lesson" in item.tags for item in harness.todos.items)


# ------------------------------------------------------------------- targets
def test_plan_extras_rank_endpoints_for_the_planner():
    harness = Harness(targets=["https://app.example"])
    graph = AssetGraph()
    node = graph.add_endpoint("POST", "https://app.example/product?id=1")
    graph.add_parameter(node.id, "id")
    graph.add_endpoint("GET", "https://app.example/static/logo.css")
    extras = harness.plan_extras(graph, [finding(url="https://app.example/product?id=1")])
    urls = [row["url"] for row in extras["next_targets"]]
    assert urls[0] == "https://app.example/product?id=1"


def test_planner_state_carries_targets_and_todos_in_the_prompt():
    state = PlannerState(
        goal="assess",
        targets=["https://app.example"],
        next_targets=[{"url": "https://app.example/p?id=1", "score": 4.2}],
        todos="- (0.50) crawl the landing page",
    )
    prompt = state.to_prompt()
    assert "next_targets" in prompt and "landing page" in prompt


def test_heuristic_planner_probes_the_best_ranked_endpoint():
    state = PlannerState(
        goal="assess",
        targets=["https://app.example"],
        coverage={"endpoints": 3},
        attempted=["detect.run:Run the detector catalogue"],
        next_targets=[{"url": "https://app.example/product?id=1", "score": 4.2}],
        remaining_turns=4,
    )
    decision = HeuristicPlanner().decide(state)
    assert decision.intents[1].tool == "web.probe"
    assert decision.intents[1].arguments["url"] == "https://app.example/product?id=1"


# -------------------------------------------------------------------- finish
def test_finish_writes_poc_review_todos_and_notifies(tmp_path):
    log = tmp_path / "notify.jsonl"
    settings = HarnessSettings(artifacts=str(tmp_path), notify={"file": str(log), "console": False})
    harness = Harness(targets=["https://app.example"], settings=settings)
    summary = harness.finish(make_result())
    assert summary["poc"] >= 4
    assert (tmp_path / "poc" / "01-reflected-xss" / "poc.sh").is_file()
    board = json.loads((tmp_path / "review.json").read_text())
    assert len(board["reviews"]) == 1
    assert "Finding review" in (tmp_path / "review.md").read_text()
    assert (tmp_path / "todos.json").is_file()
    assert summary["notify"]["delivered"] == 1
    assert "Reflected XSS" in log.read_text()
    assert summary["artifacts"]["poc"].endswith("poc")


def test_finish_skips_notification_below_the_severity_floor(tmp_path):
    log = tmp_path / "notify.jsonl"
    settings = HarnessSettings(artifacts=str(tmp_path), notify={"file": str(log), "console": False}, notify_min_severity="critical")
    summary = Harness(targets=["https://app.example"], settings=settings).finish(make_result(finding(severity="high")))
    assert summary["notify"]["delivered"] == 0
    assert not log.exists()


def test_finish_survives_a_broken_artifact_directory(tmp_path):
    blocker = tmp_path / "blocked"
    blocker.write_text("not a directory", encoding="utf-8")
    harness = Harness(targets=["https://app.example"], settings=HarnessSettings(artifacts=str(blocker)))
    summary = harness.finish(make_result())
    assert summary["poc"] == 0 and "poc_error" in summary
    assert summary["review"]["total"] == 1


def test_notify_never_posts_to_an_out_of_scope_command(tmp_path):
    from candix.agent.notify import CommandChannel, Message

    gate = CommandGate(targets=["https://app.example"])
    channel = CommandChannel(["curl", "https://evil.test/hook"], gate=gate)
    delivery = channel.send(Message(title="x", body="y", severity="high"))
    assert delivery.ok is False and "blocked" in delivery.detail


# ----------------------------------------------------------------------- cli
def test_cli_gate_blocks_and_allows():
    from candix.cli.main import main

    assert main(["gate", "rm -rf /"]) == 10
    assert main(["gate", "cat", "notes.txt", "--allow-prefix", "cat"]) == 0
    assert main(["gate", "curl http://169.254.169.254/latest", "--json"]) == 0


def test_cli_harness_lists_wiring(capsys):
    from candix.cli.main import main

    assert main(["harness", "--target", "https://app.example", "--target", "169.254.169.254"]) == 0
    output = capsys.readouterr().out
    assert "gate" in output and "wired" in output
    assert "block 169.254.169.254" in output


def test_cli_review_reads_and_approves(tmp_path):
    from candix.cli.main import main

    Harness(targets=["https://app.example"], settings=HarnessSettings(artifacts=str(tmp_path))).finish(make_result())
    assert main(["review", str(tmp_path), "--json"]) == 0
    assert main(["review", str(tmp_path), "--approve", "--reviewer", "ana"]) == 0
    board = json.loads((tmp_path / "review.json").read_text())
    assert board["reviews"][0]["status"] == "approved"


# ---------------------------------------------------------------- invariants
def test_every_capability_is_importable():
    rows = status()
    assert len(rows) >= 15
    assert all(row["state"] == "wired" for row in rows), [row for row in rows if row["state"] != "wired"]


def test_no_agent_module_is_an_orphan():
    """A capability nobody imports is a capability the harness does not have."""

    package = ROOT / "candix"
    modules = {path.stem for path in (package / "agent").glob("*.py") if path.stem != "__init__"}
    imported: set[str] = set()
    for path in package.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                module = node.module or ""
                if module.startswith("candix.agent"):
                    imported.add(module.split(".")[-1])
                    if path.parent.name == "agent" and not module.startswith("candix."):
                        imported.update(alias.name for alias in node.names)
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.Import):
                imported.update(alias.name.split(".")[-1] for alias in node.names)
    orphans = sorted(module for module in modules if module not in imported)
    assert orphans == []
