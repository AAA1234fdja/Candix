import json
import random

import pytest

from candix.agent.adaptive import AdaptiveConfig, AdaptiveController, AdaptivePlanner, Arm, Bandit
from candix.agent.anomaly import AnomalyDetector, Sample, absorb, explain, from_observation, interesting
from candix.agent.hypotheses import Hypothesis, HypothesisEngine, band_of, entropy, likelihood_ratio, logit, sigmoid
from candix.agent.hypotheses import test_for as tool_for_hypothesis
from candix.agent.learning import Learner, Prior, fingerprint
from candix.agent.models import Decision, Intent, Phase
from candix.agent.planner import HeuristicPlanner, PlannerState


def state(**overrides):
    payload = {
        "goal": "assess",
        "targets": ["http://a"],
        "coverage": {"endpoints": 2},
        "endpoints": [{"url": "http://a/api/users?id=1"}, {"url": "http://a/search?q=1"}],
        "findings": [],
        "remaining_turns": 6,
        "exploit_enabled": False,
    }
    payload.update(overrides)
    return PlannerState(**payload)


# ------------------------------------------------------------------ anomaly
def test_baseline_learns_and_flags_status_length_and_timing():
    detector = AnomalyDetector()
    for _ in range(3):
        detector.observe(Sample(url="http://a/s?q=1", status=200, length=1000, elapsed=0.1))
    found = detector.observe(Sample(url="http://a/s?q=2", status=500, length=4000, elapsed=1.5, body="sql syntax error"))
    kinds = {item.kind for item in found}
    assert {"status", "length", "timing", "error"} <= kinds
    assert detector.ranked()[0].strength >= 0.5
    assert detector.hints()


def test_stable_responses_raise_nothing():
    detector = AnomalyDetector()
    for _ in range(6):
        assert detector.observe(Sample(url="http://a/x", status=200, length=512, elapsed=0.2)) == []
    assert detector.summary().startswith("6 sample(s), no deviation")


def test_reflection_and_payload_marker():
    detector = AnomalyDetector()
    found = detector.observe(Sample(url="http://a/s?q=%3Cscript%3E", status=200, length=90, marker="<script>", body="<script>alert(1)</script>"))
    assert any(item.kind == "reflection" for item in found)
    assert interesting(detector)


def test_observation_conversion_and_explain():
    class Obs:
        payload = {"url": "http://a/s?q=1", "status": 200, "length": 100, "elapsed": 0.3, "headers": {"Server": "nginx"}, "body": "hi"}

    rows = from_observation(Obs())
    assert rows and rows[0].status == 200

    class Listing:
        payload = {"paths": [{"url": "http://a/.env", "status": 200, "length": 40}]}

    assert from_observation(Listing())[0].url.endswith(".env")

    detector = AnomalyDetector()
    absorb(detector, [Listing()])
    assert "sample" in explain(detector)


def test_detector_serialises():
    detector = AnomalyDetector()
    for _ in range(3):
        detector.observe(Sample(url="http://a/x", status=200, length=10, elapsed=0.1))
    detector.observe(Sample(url="http://a/x?b=1", status=404, length=10, elapsed=0.1))
    payload = detector.to_dict()
    assert payload["samples"] == 4
    assert payload["anomalies"]


# ------------------------------------------------------------------ hypotheses
def test_bayes_update_moves_in_the_right_direction():
    hypothesis = Hypothesis(claim="xss on /search", category="xss", prior=0.3)
    start = hypothesis.posterior
    hypothesis.update(observed=True, strength=0.8)
    assert hypothesis.posterior > start
    after_hit = hypothesis.posterior
    hypothesis.update(observed=False, strength=0.8)
    assert hypothesis.posterior < after_hit
    assert 0 < likelihood_ratio(strength=0.9)[0] < 1
    assert sigmoid(logit(0.4)) == pytest.approx(0.4, abs=1e-6)
    assert band_of(0.95) == "supported" and band_of(0.02) == "refuted"


def test_information_gain_falls_as_belief_settles():
    fresh = Hypothesis(claim="sqli on /q", category="sqli", prior=0.5)
    settled = Hypothesis(claim="sqli on /q", category="sqli", prior=0.98)
    assert fresh.information_gain() > settled.information_gain()
    assert fresh.value() > 0
    assert entropy(0.5) == pytest.approx(1.0)


def test_engine_seeds_from_endpoints_and_findings():
    engine = HypothesisEngine()
    added = engine.seed(
        endpoints=[{"url": "http://a/api/users?id=1"}, {"url": "http://a/graphql"}, {"url": "http://a/login"}],
        findings=[{"title": "XSS", "category": "xss", "url": "http://a/s?q=1", "verified": False}],
    )
    assert added >= 4
    claims = " ".join(item.claim for item in engine.items.values())
    assert "injectable" in claims and "introspection" in claims
    assert engine.summary().startswith(f"{len(engine.items)} hypothesis")


def test_engine_seeds_from_anomalies():
    class Anomaly:
        hint = "sqli"
        url = "http://a/s?q=1"
        strength = 0.8

    engine = HypothesisEngine()
    assert engine.seed_from_anomalies([Anomaly()]) == 1
    best = engine.best()
    assert best.category == "sqli" and best.prior > 0.3


def test_engine_tests_are_ranked_deduped_and_tagged():
    engine = HypothesisEngine()
    engine.seed_from_endpoints([{"url": "http://a/api/users?id=1"}])
    first = engine.next_tests(limit=1)
    second = engine.next_tests(limit=1)
    assert first and not second  # the same test is not reissued
    assert first[0].tags[0] == "hypothesis"
    assert any(tag.startswith("hypothesis:") for tag in first[0].tags)
    hypothesis = engine.get(first[0].tags[-1].split(":", 1)[1])
    assert hypothesis is not None
    engine.record(hypothesis, observed=True, strength=0.7, note="403 on neighbour id")
    assert hypothesis.posterior > hypothesis.prior


def test_same_tool_and_category_share_one_intent():
    engine = HypothesisEngine()
    engine.seed_from_endpoints([{"url": "http://a/api/users?id=2"}, {"url": "http://a/profile?id=3"}])
    intents = engine.next_tests(limit=4)
    detect = [item for item in intents if item.tool == "detect.run"]
    assert len(detect) == 1
    tagged = [tag for tag in detect[0].tags if tag.startswith("hypothesis:")]
    assert len(tagged) == 2


def test_test_for_switches_to_exploit_when_supported():
    hypothesis = Hypothesis(claim="idor", category="idor", prior=0.95)
    tool, phase, arguments = tool_for_hypothesis(hypothesis, exploit_enabled=True)
    assert tool == "exploit.run" and phase is Phase.EXPLOIT
    tool, _, _ = tool_for_hypothesis(hypothesis, exploit_enabled=False)
    assert tool == "detect.run"


def test_engine_persistence_and_markdown(tmp_path):
    engine = HypothesisEngine()
    engine.seed_from_endpoints([{"url": "http://a/auth/login"}])
    path = engine.save(tmp_path / "hypotheses.json")
    payload = json.loads(open(path).read())
    assert payload["hypotheses"]
    assert "| posterior |" in engine.markdown()


# ------------------------------------------------------------------ bandit
def test_bandit_explores_then_prefers_the_winner():
    bandit = Bandit(arms=["a", "b", "c"])
    assert set(bandit.select(limit=3)) == {"a", "b", "c"}
    for _ in range(5):
        bandit.observe("a", 1.0)
        bandit.observe("b", 0.0)
        bandit.observe("c", 0.1)
    assert bandit.select(limit=1)[0] == "a"
    assert bandit.best().name == "a"
    assert bandit.snapshot()["total_pulls"] == 15


def test_bandit_thompson_and_regression():
    bandit = Bandit(arms=["a", "b"], strategy="thompson", seed=3)
    for _ in range(4):
        bandit.observe("a", 1.0)
    picks = [bandit.select(limit=1)[0] for _ in range(40)]
    assert picks.count("a") > picks.count("b")
    bandit.regress()
    assert bandit.arms["a"].alpha < 5


def test_arm_bounds_reward():
    arm = Arm("x")
    arm.observe(5.0)
    assert arm.reward == 1.0
    arm.observe(-3.0)
    assert arm.reward == 1.0


# ------------------------------------------------------------------ controller
def test_controller_verifies_unverified_findings_first():
    controller = AdaptiveController(AdaptiveConfig())
    decision = controller.decide(state(findings=[{"title": "XSS", "url": "http://a/s?q=1", "severity": "high", "verified": False}]))
    assert decision.action == "plan"
    assert decision.intents[0].tool == "http.request"
    assert "Verify" in decision.intents[0].title
    assert controller.state.mode == "verify"


def test_controller_tests_hypotheses_once_assets_exist():
    controller = AdaptiveController(AdaptiveConfig(verify_first=False))
    decision = controller.decide(state())
    assert decision.source == "adaptive"
    assert decision.intents
    assert all(intent.tool for intent in decision.intents)


def test_controller_rejected_intents_are_not_repeated():
    controller = AdaptiveController(AdaptiveConfig(verify_first=False))
    first = controller.decide(state())
    for intent in first.intents:
        controller.reject(intent, "risk above ceiling")
    second = controller.decide(state())
    titles = {intent.title for intent in second.intents}
    assert not (titles & {intent.title for intent in first.intents})


def test_controller_falls_back_when_empty():
    controller = AdaptiveController(AdaptiveConfig())
    fallback = HeuristicPlanner()
    empty = state(coverage={"endpoints": 0}, endpoints=[])
    decision = controller.decide(empty, fallback=fallback)
    assert decision.action in {"plan", "finish"}


def test_controller_rewards_and_reports():
    controller = AdaptiveController(AdaptiveConfig())
    controller.reward("detect.run", findings=2, novelty=3)
    controller.ingest([type("O", (), {"payload": {"paths": [{"url": "http://a/x", "status": 200, "length": 10}]}})()])
    report = controller.report()
    assert report["bandit"]["arms"]
    assert "Adaptive state" in controller.markdown()
    assert controller.summary().startswith("turn")


def test_planner_protocol_and_hooks():
    planner = AdaptivePlanner(HeuristicPlanner(), config=AdaptiveConfig(verify_first=False))
    decision = planner.decide(state())
    assert isinstance(decision, Decision)
    planner.observe(decision.intents[0], ok=True, findings=1)
    planner.reject(decision.intents[0], "no")
    assert planner.report()["state"]["turn"] == 1
    assert isinstance(planner.markdown(), str)


# ------------------------------------------------------------------ learning
def test_prior_updates_and_decays():
    prior = Prior(tool="detect.run")
    start = prior.mean
    prior.observe(reward=1.0, requests=10, findings=3)
    assert prior.mean > start and prior.win_rate == 1.0
    prior.observe(reward=0.0, requests=5)
    assert prior.pulls == 2
    alpha_before = prior.alpha
    prior.decay(factor=0.5)
    assert prior.alpha < alpha_before


def test_learner_roundtrip_and_seeding(tmp_path):
    path = tmp_path / "priors.json"
    learner = Learner(path=path, targets=["http://a:8080"])
    assert not learner.known()
    learner.record("detect.run", reward=0.9, requests=10, findings=4)
    learner.record_run({"web.probe": {"reward": 0.0, "requests": 3}})
    assert learner.save().endswith("priors.json")
    again = Learner(path=path, targets=["http://a:8080"])
    assert again.known()
    assert again.expected_reward("detect.run") > 0.5
    bandit = Bandit()
    seeded = again.seed_bandit(bandit)
    assert seeded >= 1
    assert "| tool | mean |" in again.markdown()


def test_learner_is_scoped_per_target(tmp_path):
    learner = Learner(path=tmp_path / "p.json", targets=["http://a"])
    learner.record("detect.run", reward=1.0)
    other = Learner(path=tmp_path / "p.json" if False else str(tmp_path / "p.json"), targets=["http://b"])
    assert not other.known()
    assert fingerprint(["http://a"]) != fingerprint(["http://b"])


def test_learner_disabled_and_outcomes():
    learner = Learner(path="/tmp/never-written.json", targets=["http://a"], enabled=False)
    learner.record("detect.run", reward=1.0)
    assert learner.save() == ""
    assert not learner.known()
    outcomes = Learner(path="/tmp/never-written.json", targets=["http://a"], enabled=False).outcomes(
        [{"tool": "detect.run", "calls": 4, "findings": 2, "errors": 0}, {"tool": "web.probe", "calls": 0}]
    )
    assert outcomes["detect.run"]["reward"] == 0.5
    assert "web.probe" not in outcomes


# ------------------------------------------------------------------ integration
def test_session_runs_in_adaptive_mode(tmp_path):
    from candix.agent.session import AgentSession, AgentSettings
    from candix.core.config import Config
    from candix.core.scope import Engagement, build_authorization
    from candix.lab import build_server

    server = build_server("127.0.0.1", 0)
    server.start()
    try:
        document = build_authorization(
            engagement="adaptive",
            client="tests",
            operator="pytest",
            authorized_by="pytest",
            include=[f"127.0.0.1:{server.port}"],
            allow_exploit=False,
            max_rps=200.0,
        )
        settings = AgentSettings(
            goal="find what is exposed and prove it",
            exploit=False,
            max_turns=6,
            use_llm=False,
            approve_mode="auto",
            adaptive=True,
            adaptive_strategy="ucb",
            priors_path=str(tmp_path / "priors.json"),
        )
        session = AgentSession.create(
            [server.base_url],
            config=Config.profile("lab"),
            engagement=Engagement.from_document(document),
            settings=settings,
        )
        planner = session.build_planner()
        assert planner.name == "adaptive"
        result = session.run()
        assert result.intents
        snapshot = session.snapshot(result)
        assert snapshot["adaptive"]["bandit"]["arms"]
        assert snapshot["adaptive"]["hypotheses"]["hypotheses"] is not None
        assert snapshot["priors"]["target"]
        assert (tmp_path / "priors.json").is_file()
    finally:
        server.stop()
