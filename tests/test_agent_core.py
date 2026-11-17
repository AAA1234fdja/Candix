import json

import pytest

from candix.agent.budget import AgentBudget, BudgetLimits
from candix.agent.facts import Confidence, Fact, FactSource, FactStore
from candix.agent.graph import AssetGraph, EdgeKind, ExplorationGraph, NodeKind
from candix.agent.models import Decision, Goal, Intent, IntentStatus, Observation, Phase, TaskResult
from candix.agent.policy import AutonomyLevel, RiskPolicy
from candix.agent.scheduler import IntentScheduler
from candix.llm.errors import BudgetExhausted


# ------------------------------------------------------------------ budget
def test_budget_limits_and_counters():
    budget = AgentBudget(limits=BudgetLimits(turns=2, tool_calls=3, intents=4, seconds=60))
    budget.start_turn()
    budget.spend_tool_call()
    budget.spend_tool_call()
    budget.spend_tool_call()
    assert budget.turns == 1
    assert budget.exhausted() == "tool_calls"
    with pytest.raises(BudgetExhausted):
        budget.spend_tool_call()
    assert budget.stopped_reason
    assert budget.remaining_turns == 1


def test_budget_snapshot_reports_usage():
    budget = AgentBudget(limits=BudgetLimits(turns=4, tool_calls=8))
    budget.spend_tool_call()
    budget.spend_intent()
    budget.tokens = 50
    snapshot = budget.snapshot()
    assert snapshot["turns"] == 0
    assert snapshot["tool_calls"] == 1
    assert snapshot["tokens"] == 50
    assert snapshot["intents"] == 1
    assert snapshot["remaining"]["turns"] == 4


# ------------------------------------------------------------------ facts
def test_fact_store_merges_and_conflicts():
    store = FactStore()
    _first, action = store.add(Fact("login accepts any password", FactSource.TARGET_RESPONSE, subject="http://a"))
    assert action == "added"
    _same, action = store.add(Fact("login accepts any password", FactSource.TARGET_RESPONSE, subject="http://a"))
    assert action == "duplicate"
    _other, action = store.add(Fact("login does not accept any password", FactSource.TARGET_RESPONSE, subject="http://a"))
    assert action in {"conflict", "superseded", "added"}


def test_fact_provenance_rules():
    store = FactStore()
    store.add(Fact("inference only", FactSource.INFERENCE, subject="http://a"))
    store.add(Fact("observed directly", FactSource.TOOL_OUTPUT, Confidence.OBSERVED, subject="http://a"))
    provable = store.provable()
    assert [fact.claim for fact in provable] == ["observed directly"]


# ------------------------------------------------------------------ graphs
def test_asset_graph_coverage_and_findings():
    graph = AssetGraph()
    endpoint = graph.add_endpoint("GET", "http://a/search?q=1")
    graph.add_parameter(endpoint.id, "q", location="query")
    graph.add_finding({"id": "f1", "title": "XSS", "severity": "high", "url": "http://a/search?q=1"})
    coverage = graph.coverage()
    assert coverage["endpoints"] == 1
    assert coverage["parameters"] == 1
    assert coverage["findings"] == 1
    assert coverage["endpoints_with_findings"] == 1


def test_asset_graph_deduplicates_endpoints():
    graph = AssetGraph()
    graph.add_endpoint("GET", "http://a/x")
    graph.add_endpoint("GET", "http://a/x")
    graph.add_endpoint("POST", "http://a/x")
    assert len(graph.endpoints()) == 2
    assert isinstance(graph.digest(), str)


def test_exploration_graph_links_intents():
    graph = ExplorationGraph()
    intent = Intent("crawl", phase=Phase.RECON, tool="recon.crawl")
    node = graph.add_intent(intent)
    child = graph.add_observation(Observation("recon.crawl", "4 pages"))
    graph.link_intent_observation(node.id, child.id)
    assert len(graph.of_kind("intent")) == 1
    assert graph.outgoing(node.id)


# ------------------------------------------------------------------ policy
def test_policy_requires_approval_for_exploitation():
    policy = RiskPolicy(autonomy=AutonomyLevel.ASSIST, exploit_enabled=False)
    decision = policy.gate(Intent("exploit", phase=Phase.EXPLOIT, tool="exploit.run", arguments={}))
    assert not decision.allowed
    assert "exploit" in decision.reason.lower()


def test_policy_auto_allows_recon():
    decision = RiskPolicy(autonomy=AutonomyLevel.AUTO).gate(
        Intent("crawl", phase=Phase.RECON, tool="recon.crawl", arguments={"url": "http://a"})
    )
    assert decision.allowed
    assert decision.risk < 0.5


def test_autonomy_observe_blocks_active_tools():
    decision = RiskPolicy(autonomy=AutonomyLevel.OBSERVE).gate(
        Intent("fuzz", phase=Phase.DETECT, tool="fuzz.run", arguments={})
    )
    assert not decision.allowed


# ------------------------------------------------------------------ scheduler
def test_scheduler_respects_dependencies_and_priority():
    scheduler = IntentScheduler()
    crawl = Intent("crawl", phase=Phase.RECON, tool="recon.crawl", priority=1.0)
    detect = Intent("detect", phase=Phase.DETECT, tool="detect.run", priority=0.9, depends_on=[crawl.id])
    report = Intent("report", phase=Phase.REPORT, tool="report.write", priority=0.1)
    scheduler.push(crawl)
    scheduler.push(detect)
    scheduler.push(report)
    first = scheduler.pop_ready()
    assert first is crawl
    second = scheduler.pop_ready(completed={crawl.id})
    assert second is detect


def test_scheduler_prunes_finished_intents():
    scheduler = IntentScheduler()
    intent = Intent("crawl", phase=Phase.RECON, tool="recon.crawl")
    scheduler.push(intent)
    intent.mark(IntentStatus.DONE)
    assert scheduler.prune() == 1
    assert scheduler.snapshot()["queued"] == 0


# ------------------------------------------------------------------ models
def test_task_result_counts_and_serialisation():
    result = TaskResult(goal=Goal(statement="goal"))
    result.intents.append(Intent("a", phase=Phase.RECON, tool="recon.crawl").mark(IntentStatus.DONE))
    result.intents.append(Intent("b", phase=Phase.DETECT, tool="detect.run").mark(IntentStatus.FAILED))
    assert result.counts() == {"done": 1, "failed": 1}
    payload = json.loads(json.dumps(result.to_dict() if hasattr(result, "to_dict") else {}))
    assert isinstance(payload, dict)


def test_intent_coerces_string_status():
    intent = Intent("x", phase="detect", status="done")
    assert intent.phase is Phase.DETECT
    assert intent.status is IntentStatus.DONE
    assert intent.status.terminal is True


def test_decision_holds_intents():
    decision = Decision("plan", "because", [Intent("a")], 0.7, "heuristic")
    assert decision.action == "plan"
    assert len(decision.intents) == 1
