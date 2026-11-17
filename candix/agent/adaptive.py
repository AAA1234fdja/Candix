"""Spend the next request where it buys the most.

Three pieces: a bandit that tracks which technique pays off against this target,
a controller that chooses between exploring, exploiting and verifying, and a
planner that speaks the same protocol as the others so the loop does not care.
"""

from __future__ import annotations

import json
import math
import random
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from candix.agent.anomaly import Anomaly, AnomalyDetector, absorb, explain as explain_anomalies
from candix.agent.hypotheses import Hypothesis, HypothesisEngine, explain as explain_hypothesis
from candix.agent.models import Decision, Intent, Phase

CANDIDATE_ARMS: tuple[str, ...] = (
    "recon.crawl",
    "recon.fingerprint",
    "web.probe",
    "api.spec",
    "graphql.query",
    "auth.flow",
    "jwt.inspect",
    "detect.run",
    "fuzz.run",
    "exploit.run",
)

ARM_PHASE: dict[str, Phase] = {
    "recon.crawl": Phase.RECON,
    "recon.fingerprint": Phase.RECON,
    "web.probe": Phase.RECON,
    "api.spec": Phase.RECON,
    "graphql.query": Phase.RECON,
    "auth.flow": Phase.DETECT,
    "jwt.inspect": Phase.DETECT,
    "detect.run": Phase.DETECT,
    "fuzz.run": Phase.DETECT,
    "exploit.run": Phase.EXPLOIT,
}


def _phase_of(arm: str) -> Phase:
    return ARM_PHASE.get(arm, Phase.DETECT)


@dataclass
class Arm:
    name: str
    pulls: int = 0
    reward: float = 0.0
    wins: int = 0
    alpha: float = 1.0
    beta: float = 1.0
    last: float = 0.0

    @property
    def mean(self) -> float:
        return self.reward / self.pulls if self.pulls else 0.0

    def ucb(self, total: int, *, c: float = 0.7) -> float:
        if self.pulls == 0:
            return float("inf")
        bonus = c * math.sqrt(math.log(max(2, total)) / self.pulls)
        return self.mean + bonus

    def thompson(self, *, rng: random.Random) -> float:
        return rng.betavariate(self.alpha, self.beta)

    def observe(self, value: float) -> None:
        self.pulls += 1
        self.reward += max(0.0, min(1.0, value))
        if value >= 0.5:
            self.wins += 1
            self.alpha += max(0.1, value)
        else:
            self.beta += max(0.1, 1.0 - value)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "pulls": self.pulls,
            "mean_reward": round(self.mean, 3),
            "wins": self.wins,
            "alpha": round(self.alpha, 2),
            "beta": round(self.beta, 2),
        }


class Bandit:
    """UCB1 by default, Thompson sampling when exploration needs to be sharper."""

    def __init__(self, arms: Iterable[str] = CANDIDATE_ARMS, *, strategy: str = "ucb", seed: int = 7) -> None:
        self.strategy = strategy
        self.arms: dict[str, Arm] = {name: Arm(name) for name in arms}
        self.rng = random.Random(seed)

    @property
    def total(self) -> int:
        return sum(arm.pulls for arm in self.arms.values())

    def select(self, *, limit: int = 3, exclude: Iterable[str] = ()) -> list[str]:
        banned = set(exclude)
        pool = [arm for name, arm in self.arms.items() if name not in banned]
        if not pool:
            return []
        if self.strategy == "thompson":
            ranked = sorted(pool, key=lambda arm: -arm.thompson(rng=self.rng))
        else:
            ranked = sorted(pool, key=lambda arm: -arm.ucb(self.total))
        return [arm.name for arm in ranked[:limit]]

    def observe(self, name: str, value: float) -> None:
        arm = self.arms.get(name)
        if arm is not None:
            arm.observe(value)

    def best(self) -> Arm | None:
        if not self.arms:
            return None
        return max(self.arms.values(), key=lambda arm: (arm.mean, arm.pulls))

    def regress(self, *, factor: float = 0.9) -> None:
        for arm in self.arms.values():
            arm.alpha = 1.0 + (arm.alpha - 1.0) * factor
            arm.beta = 1.0 + (arm.beta - 1.0) * factor

    def snapshot(self) -> dict[str, Any]:
        return {"strategy": self.strategy, "total_pulls": self.total, "arms": [arm.to_dict() for arm in sorted(self.arms.values(), key=lambda item: -item.mean)]}

    def save(self, path: str | Path) -> str:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(self.snapshot(), indent=2), encoding="utf-8")
        return str(target)


@dataclass
class AdaptiveConfig:
    explore_ratio: float = 0.3
    max_tests: int = 3
    min_value: float = 0.06
    stagnation_limit: int = 2
    verify_first: bool = True
    strategy: str = "ucb"
    reward_findings: float = 1.0
    reward_novelty: float = 0.35
    seed: int = 7


@dataclass
class AdaptiveState:
    turn: int = 0
    mode: str = "explore"
    progress_marker: tuple[int, int, int] = (0, 0, 0)
    stalls: int = 0
    rewards: list[float] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"turn": self.turn, "mode": self.mode, "stalls": self.stalls, "rewards": [round(item, 3) for item in self.rewards[-20:]]}


def _marker(state: Any) -> tuple[int, int, int]:
    coverage = getattr(state, "coverage", {}) or {}
    return (
        int(coverage.get("endpoints", 0) or 0),
        len(getattr(state, "findings", []) or []),
        int(getattr(state, "facts", 0) or 0),
    )


class AdaptiveController:
    """Chooses the mode, then the intents that mode asks for."""

    def __init__(self, config: AdaptiveConfig | None = None, *, engine: HypothesisEngine | None = None, bandit: Bandit | None = None, detector: AnomalyDetector | None = None) -> None:
        self.config = config or AdaptiveConfig()
        self.engine = engine or HypothesisEngine()
        self.bandit = bandit or Bandit(strategy=self.config.strategy, seed=self.config.seed)
        self.detector = detector or AnomalyDetector()
        self.state = AdaptiveState()
        self.endpoints_seen: set[str] = set()
        self.blocked: set[str] = set()

    # ------------------------------------------------------------ feedback
    def ingest(self, observations: Iterable[Any]) -> list[Anomaly]:
        found = absorb(self.detector, observations)
        if found:
            self.engine.seed_from_anomalies(found)
        return found

    def note_endpoints(self, endpoints: Iterable[dict[str, Any]]) -> int:
        fresh = 0
        rows: list[dict[str, Any]] = []
        for endpoint in endpoints:
            url = str(endpoint.get("url", ""))
            if not url or url in self.endpoints_seen:
                continue
            self.endpoints_seen.add(url)
            rows.append(endpoint)
            fresh += 1
        if rows:
            self.engine.seed_from_endpoints(rows)
        return fresh

    def reward(self, arm: str, *, findings: int = 0, novelty: int = 0, ok: bool = True) -> float:
        value = 0.0
        if ok:
            value += min(self.config.reward_findings, findings * 0.5)
            value += min(self.config.reward_novelty, novelty * 0.05)
            value += 0.1
        self.bandit.observe(arm, value)
        self.state.rewards.append(value)
        return value

    # ------------------------------------------------------------ modes
    def mode_for(self, state: Any, *, exploit_enabled: bool = False) -> str:
        marker = _marker(state)
        if marker == self.state.progress_marker:
            self.state.stalls += 1
        else:
            self.state.stalls = 0
            self.state.progress_marker = marker
        if self.state.stalls >= self.config.stagnation_limit:
            return "explore"
        unverified = [item for item in state.findings if not item.get("verified")]
        if self.config.verify_first and unverified:
            return "verify"
        if exploit_enabled and self.engine.supported():
            return "exploit"
        if self.engine.ranked(limit=1):
            best = self.engine.best()
            if best is not None and best.value() >= self.config.min_value:
                return "test" if marker[0] else "explore"
        return "explore"

    def reject(self, intent: Intent, reason: str = "") -> None:
        """Remember refusals so the same dead end is not retried every turn."""

        self.blocked.add(f"{intent.tool}:{intent.title}")
        self.state.stalls += 1

    def _dedupe(self, intents: list[Intent], state: Any) -> list[Intent]:
        seen = set(getattr(state, "attempted", []) or [])
        kept: list[Intent] = []
        for intent in intents:
            signature = f"{intent.tool}:{intent.title}"
            if signature in seen or signature in self.blocked:
                continue
            if any(item.title == intent.title and item.tool == intent.tool for item in kept):
                continue
            kept.append(intent)
        return kept

    def _explore_intents(self, state: Any, *, limit: int) -> list[Intent]:
        banned = set()
        intents: list[Intent] = []
        for arm in self.bandit.select(limit=limit + 2, exclude=banned):
            if arm == "exploit.run" and not getattr(state, "exploit_enabled", False):
                continue
            intents.append(self._intent_for_arm(arm, state))
            if len(intents) >= limit:
                break
        return intents

    def _intent_for_arm(self, arm: str, state: Any) -> Intent:
        targets = list(getattr(state, "targets", []) or [])
        first = targets[0] if targets else ""
        findings = list(getattr(state, "findings", []) or [])
        unverified = [item.get("url", "") for item in findings if not item.get("verified")]
        if arm == "recon.crawl":
            return Intent("Adaptive crawl", "bandit chose recon", Phase.RECON, arm, {"url": first, "depth": 2, "max_pages": 30}, priority=0.5, origin="adaptive")
        if arm == "recon.fingerprint":
            return Intent("Adaptive fingerprint", "bandit chose fingerprinting", Phase.RECON, arm, {"url": first}, priority=0.35, origin="adaptive")
        if arm == "web.probe":
            return Intent("Adaptive exposure probe", "bandit chose known-path probing", Phase.RECON, arm, {"url": first}, priority=0.45, origin="adaptive")
        if arm == "api.spec":
            return Intent("Adaptive API discovery", "bandit chose spec discovery", Phase.RECON, arm, {"url": first}, priority=0.45, origin="adaptive")
        if arm == "graphql.query":
            return Intent("Adaptive GraphQL check", "bandit chose introspection", Phase.RECON, arm, {"url": first}, priority=0.4, origin="adaptive")
        if arm == "auth.flow":
            return Intent("Adaptive auth review", "bandit chose authentication", Phase.DETECT, arm, {"url": first}, priority=0.45, origin="adaptive")
        if arm == "jwt.inspect":
            return Intent("Adaptive token review", "bandit chose token inspection", Phase.DETECT, arm, {"url": first}, priority=0.4, origin="adaptive")
        if arm == "fuzz.run":
            return Intent("Adaptive fuzzing", "bandit chose a mutation campaign", Phase.DETECT, arm, {"iterations": 60, "strategy": "balanced"}, priority=0.55, origin="adaptive")
        if arm == "exploit.run":
            return Intent("Adaptive exploitation", "bandit chose verification by proof", Phase.EXPLOIT, arm, {"max_attempts": 1, "min_severity": "high"}, priority=0.7, origin="adaptive")
        arguments: dict[str, Any] = {"max_findings": 8}
        url = unverified[0] if unverified else ""
        if url:
            arguments["urls"] = [url]
        return Intent("Adaptive detection", "bandit chose the detector catalogue", Phase.DETECT, "detect.run", arguments, priority=0.5, origin="adaptive")

    def _verify_intents(self, state: Any, *, limit: int) -> list[Intent]:
        intents: list[Intent] = []
        for finding in state.findings:
            if finding.get("verified"):
                continue
            url = str(finding.get("url", ""))
            if not url:
                continue
            intents.append(
                Intent(
                    title=f"Verify: {str(finding.get('title', 'finding'))[:40]} @ {url.split('//')[-1][:40]}",
                    description="re-request the endpoint and compare",
                    phase=Phase.VERIFY,
                    tool="http.request",
                    arguments={"url": url, "method": str(finding.get("method", "GET") or "GET")},
                    priority=0.75,
                    tags=["verify"],
                    origin="adaptive",
                )
            )
            if len(intents) >= limit:
                break
        return intents

    def _exploit_intents(self, state: Any, *, limit: int) -> list[Intent]:
        intents: list[Intent] = []
        for hypothesis in self.engine.supported()[:limit]:
            intents.append(
                Intent(
                    title=f"Exploit: {hypothesis.claim[:60]}",
                    description=f"posterior {hypothesis.posterior:.2f}",
                    phase=Phase.EXPLOIT,
                    tool="exploit.run",
                    arguments={"max_attempts": 1, "min_severity": "high"},
                    priority=0.8,
                    tags=["exploit", hypothesis.category, f"hypothesis:{hypothesis.id}"],
                    origin="adaptive",
                )
            )
        return intents

    def decide(self, state: Any, *, fallback: Any = None) -> Decision:
        self.state.turn += 1
        exploit_enabled = bool(getattr(state, "exploit_enabled", False))
        novel = self.note_endpoints(getattr(state, "endpoints", []) or [])
        if novel:
            self.reward("recon.crawl", novelty=novel)
        self.engine.seed_from_findings(getattr(state, "findings", []) or [], exploit_enabled=exploit_enabled)
        mode = self.mode_for(state, exploit_enabled=exploit_enabled)
        limit = max(1, self.config.max_tests)
        builders = {
            "verify": lambda: self._verify_intents(state, limit=limit),
            "exploit": lambda: self._exploit_intents(state, limit=limit),
            "test": lambda: self.engine.next_tests(limit=limit, exploit_enabled=exploit_enabled),
            "explore": lambda: self._explore_intents(state, limit=limit),
        }
        cascade = {
            "verify": ("verify", "test", "exploit", "explore"),
            "exploit": ("exploit", "test", "verify", "explore"),
            "test": ("test", "verify", "explore"),
            "explore": ("explore", "test", "verify"),
        }[mode]
        intents: list[Intent] = []
        for candidate in cascade:
            intents = self._dedupe(builders[candidate](), state)
            if intents:
                mode = candidate
                break
        self.state.mode = mode
        if not intents:
            if fallback is not None:
                decision = fallback.decide(state)
                decision.reasoning = f"adaptive found nothing to add; {decision.reasoning}"
                return decision
            return Decision("finish", "adaptive has no test worth its cost", confidence=0.6, source="adaptive")

        hypothesis = self.engine.best()
        reasoning = f"mode={mode}"
        if hypothesis is not None:
            reasoning += f" · best belief: {hypothesis.category} p={hypothesis.posterior:.2f}"
        if self.state.stalls:
            reasoning += f" · stalled for {self.state.stalls} turn(s)"
        return Decision("plan", reasoning, intents, confidence=0.7, source="adaptive")

    def observe(self, intent: Intent, *, ok: bool, findings: int = 0, novelty: int = 0) -> None:
        arm = intent.tool or "detect.run"
        self.reward(arm, findings=findings, novelty=novelty, ok=ok)
        targets = [self.engine.get(tag.split(":", 1)[1]) for tag in intent.tags if tag.startswith("hypothesis:")]
        chosen = [item for item in targets if item is not None]
        if not chosen and any(tag == "hypothesis" for tag in intent.tags):
            best = self.engine.best()
            chosen = [best] if best is not None else []
        for target in chosen:
            self.engine.record(
                target,
                observed=bool(findings),
                strength=0.6 if intent.tool != "exploit.run" else 0.8,
                note=f"{intent.tool} {'hit' if findings else 'missed'}",
            )

    def report(self) -> dict[str, Any]:
        return {
            "state": self.state.to_dict(),
            "bandit": self.bandit.snapshot(),
            "hypotheses": self.engine.to_dict(),
            "anomalies": self.detector.to_dict(),
            "summary": self.summary(),
        }

    def summary(self) -> str:
        best_arm = self.bandit.best()
        arm_text = f", best arm {best_arm.name} ({best_arm.mean:.2f})" if best_arm and best_arm.pulls else ""
        return f"turn {self.state.turn}, mode {self.state.mode}{arm_text}; {self.engine.summary()}"

    def markdown(self) -> str:
        lines = ["## Adaptive state", "", self.summary(), "", "| arm | pulls | mean reward |", "| --- | --- | --- |"]
        for arm in self.bandit.snapshot()["arms"][:8]:
            lines.append(f"| {arm['name']} | {arm['pulls']} | {arm['mean_reward']} |")
        lines.append("")
        lines.append(self.engine.markdown())
        lines.append(explain_anomalies(self.detector))
        lines.append("")
        return "\n".join(lines)


class AdaptivePlanner:
    """Planner protocol on top of the controller, with a fallback behind it."""

    name = "adaptive"

    def __init__(self, fallback: Any = None, *, config: AdaptiveConfig | None = None, controller: AdaptiveController | None = None, strategy: str = "") -> None:
        if strategy:
            config = config or AdaptiveConfig()
            config.strategy = strategy
        self.fallback = fallback
        self.controller = controller or AdaptiveController(config)

    def decide(self, state: Any) -> Decision:
        return self.controller.decide(state, fallback=self.fallback)

    def ingest(self, observations: Iterable[Any]) -> list[Anomaly]:
        return self.controller.ingest(observations)

    def observe(self, intent: Intent, *, ok: bool, findings: int = 0, novelty: int = 0) -> None:
        self.controller.observe(intent, ok=ok, findings=findings, novelty=novelty)

    def reject(self, intent: Intent, reason: str = "") -> None:
        self.controller.reject(intent, reason)

    def report(self) -> dict[str, Any]:
        return self.controller.report()

    def markdown(self) -> str:
        return self.controller.markdown()


def from_state(engine: HypothesisEngine, *, limit: int = 5) -> list[str]:
    return [explain_hypothesis(item) for item in engine.ranked(limit=limit)]
