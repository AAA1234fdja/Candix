import pytest

from candix.agent.models import Decision, Intent, IntentStatus, Phase
from candix.agent.planner import HeuristicPlanner, LLMPlanner, PlannerState
from candix.agent.policy import AutonomyLevel
from candix.agent.session import AgentSession, AgentSettings
from candix.agent.worker import DeterministicWorker
from candix.core.config import Config
from candix.core.scope import Engagement, build_authorization
from candix.lab import build_server


@pytest.fixture(scope="module")
def lab():
    server = build_server("127.0.0.1", 0)
    server.start()
    yield server
    server.stop()


def make_session(lab, *, exploit: bool = False, turns: int = 4) -> AgentSession:
    config = Config.profile("lab")
    config.set("scan.max_rps", 200.0)
    document = build_authorization(
        engagement="tests",
        client="tests",
        operator="pytest",
        authorized_by="pytest",
        include=[f"127.0.0.1:{lab.port}"],
        allow_exploit=exploit,
        max_rps=200.0,
    )
    engagement = Engagement.from_document(document)
    settings = AgentSettings(
        goal="map the lab and prove what you can",
        autonomy=AutonomyLevel.AUTO,
        exploit=exploit,
        max_turns=turns,
        use_llm=False,
        approve_mode="auto",
    )
    return AgentSession.create([lab.base_url], config=config, engagement=engagement, settings=settings)


class ScriptedPlanner:
    def __init__(self, decisions):
        self.decisions = list(decisions)
        self.seen_states = []

    def decide(self, state):
        self.seen_states.append(state)
        if self.decisions:
            return self.decisions.pop(0)
        return Decision("finish", "script finished", confidence=1.0, source="script")


def test_loop_runs_crawl_and_writes_assets(lab):
    session = make_session(lab)
    events = []
    session.on_event = lambda kind, payload: events.append(kind)
    crawl = Intent(
        "Crawl the lab",
        phase=Phase.RECON,
        tool="recon.crawl",
        arguments={"url": lab.base_url, "depth": 1, "max_pages": 8},
    )
    session.planner_factory = lambda _session: ScriptedPlanner(
        [Decision("plan", "recon first", [crawl], 1.0, "script")]
    )
    result = session.run()

    assert result.stop_reason
    assert crawl.status is IntentStatus.DONE
    assert session.assets.coverage()["endpoints"] > 0
    assert "intent.finish" in events
    assert result.intents


def test_deterministic_worker_reports_failure_for_unknown_tool(lab):
    session = make_session(lab)
    worker = DeterministicWorker(session.registry)
    outcome = worker.run(Intent("nope", phase=Phase.RECON, tool="does.not.exist", arguments={}), session.tool_context)
    assert not outcome.ok
    assert "unknown tool" in outcome.error.lower()


def test_scope_guard_refuses_out_of_scope_requests(lab):
    session = make_session(lab)
    worker = DeterministicWorker(session.registry)
    outcome = worker.run(
        Intent("outside", phase=Phase.RECON, tool="http.request", arguments={"url": "http://example.org/"}),
        session.tool_context,
    )
    assert not outcome.ok
    text = (outcome.error or "").lower()
    assert "scope" in text or "denied" in text or "refus" in text


def test_exploit_tool_refuses_without_authorization(lab):
    session = make_session(lab, exploit=False)
    worker = DeterministicWorker(session.registry)
    outcome = worker.run(
        Intent("exploit", phase=Phase.EXPLOIT, tool="exploit.run", arguments={"max_attempts": 1}),
        session.tool_context,
    )
    assert not outcome.ok
    assert "exploit" in (outcome.error or "").lower()


def test_snapshot_exposes_triage_and_chain(lab):
    session = make_session(lab)
    session.planner_factory = lambda _session: ScriptedPlanner([])
    result = session.run()
    snapshot = session.snapshot(result)
    assert "triage" in snapshot
    assert snapshot["coverage"]["endpoints"] >= 0
    assert snapshot["scope_directives"]


def test_heuristic_planner_advances_after_recon():
    planner = HeuristicPlanner()
    state = PlannerState(
        goal="assess",
        targets=["http://a"],
        coverage={"endpoints": 3, "parameters": 2},
        findings=[],
        remaining_turns=5,
        exploit_enabled=False,
    )
    decision = planner.decide(state)
    assert decision.action == "plan"
    assert decision.intents[0].tool == "detect.run"


def test_heuristic_planner_stops_when_recon_found_nothing():
    planner = HeuristicPlanner()
    state = PlannerState(
        goal="assess",
        targets=["http://a"],
        coverage={"endpoints": 0},
        attempted=["recon.crawl:Crawl the landing page", "recon.fingerprint:Fingerprint the stack"],
        remaining_turns=2,
    )
    decision = planner.decide(state)
    assert decision.action == "finish"
    assert "recon" in decision.reasoning.lower()


def test_heuristic_planner_asks_for_proof_after_facts():
    planner = HeuristicPlanner()
    state = PlannerState(
        goal="assess",
        targets=["http://a"],
        coverage={"endpoints": 4},
        findings=[{"id": "f1", "title": "XSS", "severity": "high", "url": "http://a/s", "verified": True}],
        facts=3,
        provable_facts=2,
        proofs=0,
        remaining_turns=3,
    )
    decision = planner.decide(state)
    assert decision.intents[0].tool == "goal.prove"


def test_llm_planner_falls_back_on_error():
    class Broken:
        def complete_json(self, *args, **kwargs):
            raise RuntimeError("model unavailable")

    planner = LLMPlanner(Broken(), tool_names={"recon.crawl", "recon.fingerprint"}, schemas={})
    state = PlannerState(goal="assess", targets=["http://a"], coverage={"endpoints": 0}, remaining_turns=3)
    decision = planner.decide(state)
    assert decision.source == "heuristic-fallback"
    assert decision.action == "plan"


def test_llm_planner_rejects_unknown_tools():
    class Model:
        def complete_json(self, *args, **kwargs):
            return {
                "action": "plan",
                "reasoning": "call something imaginary",
                "intents": [
                    {"title": "RCE", "phase": "exploit", "tool": "made.up.tool", "arguments": {}},
                ],
            }

    planner = LLMPlanner(Model(), tool_names={"recon.crawl"}, schemas={})
    state = PlannerState(goal="assess", targets=["http://a"], coverage={"endpoints": 0}, remaining_turns=3)
    decision = planner.decide(state)
    assert decision.action == "plan"
    assert all(intent.tool in {"recon.crawl", "recon.fingerprint"} for intent in decision.intents)
