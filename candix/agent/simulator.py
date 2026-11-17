"""Predict what a plan costs before spending a single request.

Planning is cheap until it hits the network. The simulator walks a list of
intents, applies the risk policy and the per-tool limits, and estimates how many
requests, seconds and tokens the plan needs. ``candix agent --dry-run`` prints
this, and the loop uses it to refuse plans that cannot fit the remaining budget.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

# Requests a tool typically issues for one call, and typical latency in seconds.
PROFILES: dict[str, tuple[int, float]] = {
    "http.request": (1, 0.35),
    "http.batch": (20, 3.0),
    "http.replay": (1, 0.35),
    "recon.crawl": (12, 4.0),
    "recon.fingerprint": (1, 0.4),
    "recon.robots": (2, 0.5),
    "scope.map": (4, 3.0),
    "detect.run": (80, 45.0),
    "exploit.run": (12, 20.0),
    "fuzz.run": (120, 30.0),
    "auth.test": (6, 3.0),
    "facts.add": (0, 0.02),
    "facts.list": (0, 0.01),
    "goal.prove": (0, 0.02),
    "endpoints.list": (0, 0.01),
    "findings.list": (0, 0.01),
    "report.write": (0, 0.05),
    "finish": (0, 0.0),
}

DEFAULT_PROFILE = (4, 1.0)


@dataclass
class Estimate:
    intent: str
    tool: str
    requests: int
    seconds: float
    tokens: int = 0
    risk: float = 0.0
    allowed: bool = True
    requires_approval: bool = False
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "intent": self.intent,
            "tool": self.tool,
            "requests": self.requests,
            "seconds": round(self.seconds, 2),
            "risk": round(self.risk, 2),
            "allowed": self.allowed,
            "approval": self.requires_approval,
            "reasons": self.reasons,
        }


@dataclass
class Simulation:
    estimates: list[Estimate] = field(default_factory=list)
    turns: int = 0
    notes: list[str] = field(default_factory=list)

    @property
    def requests(self) -> int:
        return sum(item.requests for item in self.estimates if item.allowed)

    @property
    def seconds(self) -> float:
        return sum(item.seconds for item in self.estimates if item.allowed)

    @property
    def tokens(self) -> int:
        return sum(item.tokens for item in self.estimates if item.allowed)

    def blocked(self) -> list[Estimate]:
        return [item for item in self.estimates if not item.allowed]

    def to_dict(self) -> dict[str, Any]:
        return {
            "requests": self.requests,
            "seconds": round(self.seconds, 2),
            "tokens": self.tokens,
            "turns": self.turns,
            "blocked": [item.to_dict() for item in self.blocked()],
            "estimates": [item.to_dict() for item in self.estimates],
            "notes": list(self.notes),
        }

    def summary(self) -> str:
        blocked = len(self.blocked())
        suffix = f", {blocked} blocked" if blocked else ""
        return f"{len(self.estimates)} intent(s), ~{self.requests} request(s), ~{self.seconds:.0f}s{suffix}"


def estimate_intent(intent: Any, policy: Any = None, registry: Any = None) -> Estimate:
    tool = str(getattr(intent, "tool", "") or "")
    requests, seconds = PROFILES.get(tool, DEFAULT_PROFILE)
    arguments = getattr(intent, "arguments", {}) or {}
    if tool == "http.batch":
        urls = arguments.get("urls") or []
        requests = max(1, len(urls)) if isinstance(urls, (list, tuple)) else requests
    elif tool == "recon.crawl":
        pages = int(arguments.get("max_pages", 15) or 15)
        requests = max(1, pages)
        seconds = 0.35 * pages + 1.0
    elif tool == "detect.run":
        limit = int(arguments.get("max_findings", 40) or 40)
        requests = 40 + limit
        seconds = 25.0 + 0.4 * limit
    elif tool == "exploit.run":
        attempts = int(arguments.get("max_attempts", 3) or 3)
        requests = 4 * attempts
        seconds = 6.0 * attempts
    estimate = Estimate(intent=str(getattr(intent, "title", "")), tool=tool, requests=requests, seconds=seconds)

    if registry is not None:
        tool_obj = registry.get(tool) if hasattr(registry, "get") else None
        if tool_obj is None:
            estimate.allowed = False
            estimate.reasons.append(f"unknown tool {tool!r}")
            return estimate
        if getattr(tool_obj, "max_calls", 0):
            estimate.reasons.append(f"tool cap {tool_obj.max_calls}/run")
        estimate.seconds = min(estimate.seconds, float(getattr(tool_obj, "timeout", estimate.seconds) or estimate.seconds))

    if policy is not None and hasattr(policy, "gate"):
        try:
            decision = policy.gate(intent)
            estimate.risk = float(getattr(decision, "risk", 0.0))
            estimate.allowed = estimate.allowed and bool(getattr(decision, "allowed", True))
            estimate.requires_approval = bool(getattr(decision, "requires_approval", False))
            reason = getattr(decision, "reason", "")
            if reason and not estimate.allowed:
                estimate.reasons.append(str(reason))
        except Exception as error:
            estimate.reasons.append(f"policy error: {error}")
    return estimate


def simulate(intents: Iterable[Any], *, policy: Any = None, registry: Any = None, budget: Any = None) -> Simulation:
    items = list(intents)
    simulation = Simulation(turns=1 if items else 0)
    for intent in items:
        simulation.estimates.append(estimate_intent(intent, policy=policy, registry=registry))
    if budget is not None:
        remaining = getattr(budget, "remaining_tool_calls", lambda: None)
        left = remaining() if callable(remaining) else None
        if left is not None and simulation.requests > left * 3:
            simulation.notes.append(f"plan needs ~{simulation.requests} requests, {left} tool calls remain")
        seconds_left = getattr(budget, "remaining_seconds", lambda: None)
        left_seconds = seconds_left() if callable(seconds_left) else None
        if left_seconds is not None and simulation.seconds > left_seconds:
            simulation.notes.append(f"plan needs ~{simulation.seconds:.0f}s, {left_seconds:.0f}s remain")
    return simulation


def fits(simulation: Simulation, *, max_requests: int = 0, max_seconds: float = 0.0) -> bool:
    if max_requests and simulation.requests > max_requests:
        return False
    if max_seconds and simulation.seconds > max_seconds:
        return False
    return True


def cheapest(intents: Iterable[Any], *, limit: int = 3, policy: Any = None) -> list[Any]:
    """Order intents by estimated cost; useful when a plan must be trimmed."""

    scored = []
    for intent in intents:
        estimate = estimate_intent(intent, policy=policy)
        scored.append((estimate.seconds + estimate.requests * 0.05, intent))
    scored.sort(key=lambda pair: pair[0])
    return [intent for _cost, intent in scored[:limit]]
