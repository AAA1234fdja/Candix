"""Beliefs with numbers: what might be true, what would prove it, what to test first.

The planner asks "what is the next step"; the engine asks "what do I currently
believe, how strong is that belief, and which single request would change it the
most".
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable

from candix.agent.knowledge import lookup, normalise, severity_hint
from candix.agent.models import Intent, Phase, new_id

SEVERITY_WEIGHT = {"critical": 1.6, "high": 1.3, "medium": 1.0, "low": 0.7, "info": 0.4}
STATUS_BANDS = ((0.85, "supported"), (0.55, "likely"), (0.3, "open"), (0.1, "unlikely"), (0.0, "refuted"))

TOOL_BY_CATEGORY: dict[str, tuple[str, Phase]] = {
    "xss": ("detect.run", Phase.DETECT),
    "sqli": ("detect.run", Phase.DETECT),
    "ssti": ("detect.run", Phase.DETECT),
    "lfi": ("detect.run", Phase.DETECT),
    "rce": ("detect.run", Phase.DETECT),
    "xxe": ("detect.run", Phase.DETECT),
    "ssrf": ("detect.run", Phase.DETECT),
    "idor": ("detect.run", Phase.DETECT),
    "cors": ("detect.run", Phase.DETECT),
    "open_redirect": ("detect.run", Phase.DETECT),
    "exposed_secret": ("web.probe", Phase.RECON),
    "graphql_introspection": ("graphql.query", Phase.RECON),
    "jwt": ("jwt.inspect", Phase.DETECT),
    "auth": ("auth.flow", Phase.DETECT),
    "reflection": ("detect.run", Phase.DETECT),
    "sqli": ("detect.run", Phase.DETECT),
    "error": ("detect.run", Phase.DETECT),
    "behaviour": ("http.batch", Phase.DETECT),
    "config": ("detect.run", Phase.DETECT),
    "availability": ("http.replay", Phase.VERIFY),
}

PARAM_HINTS: tuple[tuple[tuple[str, ...], str, float], ...] = (
    (("id", "uid", "user", "account", "tenant", "invoice", "order", "profile"), "idor", 0.45),
    (("file", "path", "filename", "doc", "page", "template", "include", "dir"), "lfi", 0.4),
    (("url", "next", "redirect", "return", "target", "dest", "continue", "callback"), "ssrf", 0.35),
    (("q", "s", "search", "query", "term", "filter", "name"), "xss", 0.4),
    (("cmd", "exec", "command", "run", "shell"), "rce", 0.35),
    (("sort", "order", "orderby", "column"), "sqli", 0.3),
    (("token", "jwt", "auth", "session"), "jwt", 0.3),
)


def sigmoid(value: float) -> float:
    if value >= 0:
        return 1 / (1 + math.exp(-value))
    exp = math.exp(value)
    return exp / (1 + exp)


def logit(probability: float, *, floor: float = 0.001, ceiling: float = 0.999) -> float:
    probability = min(ceiling, max(floor, probability))
    return math.log(probability / (1 - probability))


def entropy(probability: float) -> float:
    p = min(1 - 1e-9, max(1e-9, probability))
    return -(p * math.log2(p) + (1 - p) * math.log2(1 - p))


def band_of(probability: float) -> str:
    for threshold, name in STATUS_BANDS:
        if probability >= threshold:
            return name
    return "refuted"


def likelihood_ratio(*, strength: float) -> tuple[float, float]:
    """Detection and false-alarm rates for a test of the given strength."""

    strength = min(1.0, max(0.05, strength))
    detection = 0.55 + 0.4 * strength
    false_alarm = max(0.04, 0.35 - 0.3 * strength)
    return detection, false_alarm


@dataclass
class Hypothesis:
    claim: str
    category: str = ""
    url: str = ""
    parameter: str = ""
    prior: float = 0.35
    evidence: list[str] = field(default_factory=list)
    tests: int = 0
    cost: float = 1.0
    source: str = ""
    id: str = field(default_factory=lambda: new_id("hyp"))
    log_odds: float = field(init=False, default=0.0)
    created_at: float = 0.0

    def __post_init__(self) -> None:
        if not self.category:
            self.category = normalise(self.claim) or "behaviour"
        self.log_odds = logit(self.prior)

    @property
    def posterior(self) -> float:
        return sigmoid(self.log_odds)

    @property
    def status(self) -> str:
        return band_of(self.posterior)

    @property
    def severity(self) -> str:
        return severity_hint(self.category)

    @property
    def signature(self) -> str:
        return f"{self.category}|{self.url}|{self.parameter}".lower()

    @property
    def settled(self) -> bool:
        return self.posterior >= 0.9 or self.posterior <= 0.08

    def update(self, *, observed: bool, strength: float = 0.7, note: str = "") -> float:
        detection, false_alarm = likelihood_ratio(strength=strength)
        if observed:
            self.log_odds += math.log(detection / false_alarm)
        else:
            self.log_odds += math.log((1 - detection) / (1 - false_alarm))
        self.tests += 1
        if note:
            self.evidence.append(("+" if observed else "-") + note[:160])
        return self.posterior

    def expected_entropy_after(self, *, strength: float = 0.7) -> float:
        detection, false_alarm = likelihood_ratio(strength=strength)
        p = self.posterior
        p_if_true = sigmoid(self.log_odds + math.log(detection / false_alarm))
        p_if_false = sigmoid(self.log_odds + math.log((1 - detection) / (1 - false_alarm)))
        return (p * entropy(p_if_true) + (1 - p) * entropy(p_if_false))

    def information_gain(self, *, strength: float = 0.7) -> float:
        return max(0.0, entropy(self.posterior) - self.expected_entropy_after(strength=strength))

    def value(self, *, strength: float = 0.7) -> float:
        weight = SEVERITY_WEIGHT.get(self.severity, 1.0)
        return weight * self.information_gain(strength=strength) / (1.0 + max(0.0, self.cost))

    def payoff(self, *, strength: float = 0.7) -> float:
        """Expected severity of acting now: posterior weighted by impact."""

        return SEVERITY_WEIGHT.get(self.severity, 1.0) * self.posterior

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "claim": self.claim,
            "category": self.category,
            "url": self.url,
            "parameter": self.parameter,
            "prior": round(self.prior, 3),
            "posterior": round(self.posterior, 3),
            "status": self.status,
            "tests": self.tests,
            "cost": self.cost,
            "evidence": list(self.evidence[-6:]),
            "source": self.source,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "Hypothesis":
        item = cls(
            claim=str(payload.get("claim", "")),
            category=str(payload.get("category", "")),
            url=str(payload.get("url", "")),
            parameter=str(payload.get("parameter", "")),
            prior=float(payload.get("prior", 0.35)),
            evidence=list(payload.get("evidence") or []),
            tests=int(payload.get("tests", 0)),
            cost=float(payload.get("cost", 1.0)),
            source=str(payload.get("source", "")),
            id=str(payload.get("id") or new_id("hyp")),
        )
        if "posterior" in payload:
            item.log_odds = logit(float(payload["posterior"]))
        return item


def test_for(hypothesis: Hypothesis, *, exploit_enabled: bool = False) -> tuple[str, Phase, dict[str, Any]]:
    """Which tool would test this belief, and with what arguments."""

    category = hypothesis.category
    if hypothesis.status == "supported" and exploit_enabled and category not in {"exposed_secret", "graphql_introspection"}:
        return ("exploit.run", Phase.EXPLOIT, {"max_attempts": 1, "min_severity": "high"})
    tool, phase = TOOL_BY_CATEGORY.get(category, ("http.batch", Phase.DETECT))
    if tool == "detect.run":
        arguments: dict[str, Any] = {"max_findings": 6}
        if category:
            arguments["categories"] = [category]
        return (tool, phase, arguments)
    if tool == "web.probe":
        return (tool, phase, {"url": hypothesis.url})
    if tool in {"jwt.inspect", "auth.flow", "graphql.query"}:
        return (tool, phase, {"url": hypothesis.url} if hypothesis.url else {})
    if tool == "http.replay":
        return ("http.request", Phase.VERIFY, {"url": hypothesis.url} if hypothesis.url else {})
    return (tool, phase, {"urls": [hypothesis.url]} if hypothesis.url else {})


class HypothesisEngine:
    """Holds the beliefs of one run and turns them into ranked tests."""

    def __init__(self, *, threshold: float = 0.05, max_hypotheses: int = 300) -> None:
        self.threshold = threshold
        self.max_hypotheses = max_hypotheses
        self.items: dict[str, Hypothesis] = {}
        self.history: list[dict[str, Any]] = []
        self.seen_tests: set[str] = set()

    # ------------------------------------------------------------ lifecycle
    def add(self, hypothesis: Hypothesis) -> Hypothesis:
        existing = self.items.get(hypothesis.signature)
        if existing is not None:
            existing.log_odds += (hypothesis.log_odds - logit(hypothesis.prior))
            existing.evidence.extend(hypothesis.evidence)
            return existing
        if len(self.items) >= self.max_hypotheses:
            weakest = min(self.items.values(), key=lambda item: item.value())
            if hypothesis.value() <= weakest.value():
                return hypothesis
            self.items.pop(weakest.signature, None)
        self.items[hypothesis.signature] = hypothesis
        return hypothesis

    def propose(self, claim: str, *, category: str = "", url: str = "", parameter: str = "", prior: float = 0.35, source: str = "") -> Hypothesis:
        return self.add(Hypothesis(claim=claim, category=category, url=url, parameter=parameter, prior=prior, source=source))

    def record(self, hypothesis: Hypothesis, *, observed: bool, strength: float = 0.7, note: str = "") -> float:
        posterior = hypothesis.update(observed=observed, strength=strength, note=note)
        self.history.append({"claim": hypothesis.claim, "observed": observed, "posterior": round(posterior, 3), "note": note[:120]})
        return posterior

    def forget(self, status: str) -> int:
        doomed = [key for key, item in self.items.items() if item.status == status]
        for key in doomed:
            self.items.pop(key, None)
        return len(doomed)

    def prune(self) -> int:
        removed = 0
        for status in ("refuted",):
            removed += self.forget(status)
        return removed

    # ------------------------------------------------------------ queries
    def ranked(self, *, limit: int = 10, include_settled: bool = False) -> list[Hypothesis]:
        items = list(self.items.values())
        if not include_settled:
            items = [item for item in items if not item.settled]
        return sorted(items, key=lambda item: -item.value())[:limit]

    def supported(self) -> list[Hypothesis]:
        return [item for item in self.items.values() if item.status in {"supported", "likely"}]

    def open(self) -> list[Hypothesis]:
        return [item for item in self.items.values() if item.status == "open"]

    def unverified(self) -> list[Hypothesis]:
        return [item for item in self.items.values() if item.tests == 0]

    def get(self, hypothesis_id: str) -> Hypothesis | None:
        for item in self.items.values():
            if item.id == hypothesis_id:
                return item
        return None

    def by_url(self, url: str) -> list[Hypothesis]:
        return [item for item in self.items.values() if item.url == url]

    def best(self) -> Hypothesis | None:
        ranked = self.ranked(limit=1)
        return ranked[0] if ranked else None

    def expected_value(self) -> float:
        return round(sum(item.value() for item in self.ranked(limit=50)), 3)

    # ------------------------------------------------------------ seeding
    def seed_from_findings(self, findings: Iterable[dict[str, Any]], *, exploit_enabled: bool = False) -> int:
        added = 0
        for finding in findings:
            category = normalise(str(finding.get("category", "") or finding.get("title", "")))
            url = str(finding.get("url", ""))
            parameter = str(finding.get("parameter", ""))
            if finding.get("exploited"):
                continue
            if not finding.get("verified"):
                claim = f"{category or 'finding'} at {url} reproduces on a second request"
                prior = 0.6
                source = "unverified-finding"
            elif exploit_enabled:
                claim = f"{category or 'finding'} at {url} can be exploited"
                prior = 0.5
                source = "verified-finding"
            else:
                continue
            before = len(self.items)
            self.propose(claim, category=category, url=url, parameter=parameter, prior=prior, source=source)
            added += int(len(self.items) > before)
        return added

    def seed_from_anomalies(self, anomalies: Iterable[Any]) -> int:
        added = 0
        for anomaly in anomalies:
            hint = str(getattr(anomaly, "hint", "") or "behaviour")
            url = str(getattr(anomaly, "url", ""))
            strength = float(getattr(anomaly, "strength", 0.5))
            before = len(self.items)
            self.propose(
                f"{hint} on {url} caused by the input",
                category=hint,
                url=url,
                prior=round(min(0.7, 0.25 + strength * 0.5), 3),
                source="anomaly",
            )
            added += int(len(self.items) > before)
        return added

    def seed_from_endpoints(self, endpoints: Iterable[dict[str, Any]]) -> int:
        added = 0
        for endpoint in endpoints:
            url = str(endpoint.get("url", ""))
            if not url:
                continue
            path = url.split("?", 1)[0]
            lowered = url.lower()
            if "graphql" in lowered:
                before = len(self.items)
                self.propose(f"introspection is enabled on {path}", category="graphql_introspection", url=url, prior=0.5, source="endpoint-shape")
                added += int(len(self.items) > before)
            if any(token in lowered for token in ("/login", "/signin", "/auth", "/session")):
                before = len(self.items)
                self.propose(f"the login flow on {path} can be bypassed or replayed", category="auth", url=url, prior=0.4, source="endpoint-shape")
                added += int(len(self.items) > before)
            query = url.split("?", 1)[1] if "?" in url else ""
            names = [pair.split("=", 1)[0] for pair in query.split("&") if pair]
            for name in names[:6]:
                for needles, category, prior in PARAM_HINTS:
                    if any(needle == name.lower() or needle in name.lower() for needle in needles):
                        before = len(self.items)
                        self.propose(
                            f"parameter {name} on {path} is injectable",
                            category=category,
                            url=url,
                            parameter=name,
                            prior=prior,
                            source="parameter-name",
                        )
                        added += int(len(self.items) > before)
                        break
        return added

    def seed(self, *, findings: Iterable[dict[str, Any]] = (), endpoints: Iterable[dict[str, Any]] = (), anomalies: Iterable[Any] = (), exploit_enabled: bool = False) -> int:
        return (
            self.seed_from_anomalies(anomalies)
            + self.seed_from_endpoints(endpoints)
            + self.seed_from_findings(findings, exploit_enabled=exploit_enabled)
        )

    # ------------------------------------------------------------ planning
    def next_tests(self, *, limit: int = 3, exploit_enabled: bool = False) -> list[Intent]:
        """One intent per (tool, category): a detector run already covers every endpoint."""

        intents: list[Intent] = []
        covered: dict[tuple[str, str], Intent] = {}
        for hypothesis in self.ranked(limit=limit * 6):
            if hypothesis.value() < self.threshold:
                continue
            tool, phase, arguments = test_for(hypothesis, exploit_enabled=exploit_enabled)
            signature = f"{tool}:{hypothesis.signature}"
            if signature in self.seen_tests:
                continue
            self.seen_tests.add(signature)
            hypothesis.cost += 0.25
            key = (tool, hypothesis.category)
            existing = covered.get(key)
            if existing is not None:
                existing.tags.append(f"hypothesis:{hypothesis.id}")
                if len(existing.tags) > 8:
                    existing.tags = existing.tags[:1] + existing.tags[-1:]
                continue
            intent = Intent(
                title=f"Test: {hypothesis.claim[:70]}",
                description=f"posterior {hypothesis.posterior:.2f} · value {hypothesis.value():.2f} · source {hypothesis.source}",
                phase=phase,
                tool=tool,
                arguments=arguments,
                priority=round(min(0.95, 0.4 + hypothesis.value()), 3),
                tags=["hypothesis", hypothesis.category, f"hypothesis:{hypothesis.id}"],
                origin="hypotheses",
            )
            covered[key] = intent
            intents.append(intent)
            if len(intents) >= limit:
                break
        return intents

    def settle(self, intents: Iterable[Intent]) -> int:
        """Close beliefs whose test already ran, so the same test is not reissued."""

        closed = 0
        for item in self.items.values():
            tool, _, _ = test_for(item)
            if tool and any(intent.tool == tool and item.url and item.url in str(intent.arguments) for intent in intents):
                closed += 1
        return closed

    # ------------------------------------------------------------ reporting
    def summary(self) -> str:
        if not self.items:
            return "no hypotheses"
        supported = len(self.supported())
        open_count = len(self.open())
        return f"{len(self.items)} hypothesis(es): {supported} supported, {open_count} open, best value {self.expected_value():.2f}"

    def markdown(self, *, limit: int = 12) -> str:
        lines = ["## Hypotheses", "", self.summary(), "", "| posterior | status | category | claim | tests |", "| --- | --- | --- | --- | --- |"]
        for item in self.ranked(limit=limit, include_settled=True):
            lines.append(f"| {item.posterior:.2f} | {item.status} | {item.category} | {item.claim[:70]} | {item.tests} |")
        return "\n".join(lines) + "\n"

    def to_dict(self) -> dict[str, Any]:
        return {
            "summary": self.summary(),
            "expected_value": self.expected_value(),
            "hypotheses": [item.to_dict() for item in self.ranked(limit=50, include_settled=True)],
            "history": self.history[-40:],
        }

    def save(self, path: str | Path) -> str:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(self.to_dict(), indent=2, sort_keys=True), encoding="utf-8")
        return str(target)


def prioritise(engine: HypothesisEngine, *, limit: int = 5) -> list[Hypothesis]:
    return engine.ranked(limit=limit)


def explain(hypothesis: Hypothesis) -> str:
    item = lookup(hypothesis.category)
    label = item.name if item else hypothesis.category
    return (
        f"{label} at {hypothesis.url or 'unknown'} ({hypothesis.parameter or 'no parameter'}): "
        f"posterior {hypothesis.posterior:.2f} from prior {hypothesis.prior:.2f} after {hypothesis.tests} test(s), "
        f"value {hypothesis.value():.2f}"
    )


def to_todo(engine: HypothesisEngine, *, limit: int = 3) -> list[str]:
    return [f"test {item.claim} (p={item.posterior:.2f})" for item in engine.ranked(limit=limit)]
