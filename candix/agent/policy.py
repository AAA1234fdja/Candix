"""Autonomy levels and risk-based gating of planned work."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterable

from candix.agent.guard import SafetyDecision
from candix.agent.models import Intent, Phase


class AutonomyLevel(str, Enum):
    """How much the agent may do without a human in the loop."""

    OBSERVE = "observe"
    ASSIST = "assist"
    BOUNDED = "bounded"
    AUTO = "auto"

    @classmethod
    def parse(cls, value: Any) -> "AutonomyLevel":
        if isinstance(value, cls):
            return value
        text = str(value or "assist").strip().lower()
        aliases = {"read-only": "observe", "readonly": "observe", "manual": "assist", "guided": "assist", "full": "auto"}
        try:
            return cls(aliases.get(text, text))
        except ValueError:
            return cls.ASSIST

    @property
    def allows_active(self) -> bool:
        return self is not AutonomyLevel.OBSERVE

    @property
    def allows_exploit(self) -> bool:
        return self in {AutonomyLevel.BOUNDED, AutonomyLevel.AUTO}

    def describe(self) -> str:
        return {
            AutonomyLevel.OBSERVE: "reconnaissance and passive checks only; no active request is sent",
            AutonomyLevel.ASSIST: "every active intent waits for operator approval",
            AutonomyLevel.BOUNDED: "active checks run automatically; exploitation needs approval",
            AutonomyLevel.AUTO: "the agent plans, verifies and exploits within the run budget",
        }[self]


# The exploit phase is gated on its own; these hints only add risk to intents that
# name a technique beyond the phase itself.
_ACTIVE_HINTS = re.compile(
    r"inject|brute|fuzz|upload|smuggl|poison|race|payload|auth-?bypass|takeover",
    re.IGNORECASE,
)
_DESTRUCTIVE_HINTS = re.compile(r"delete|destroy|wipe|reset|drop|overwrite", re.IGNORECASE)


@dataclass
class RiskPolicy:
    """Maps an intent onto a risk score and a gate decision."""

    autonomy: AutonomyLevel = AutonomyLevel.ASSIST
    max_risk_auto: float = 0.55
    max_risk_approved: float = 0.9
    exploit_enabled: bool = False
    max_requests_per_intent: int = 120
    allow_phases: tuple[Phase, ...] = (Phase.RECON, Phase.DETECT, Phase.VERIFY, Phase.REPORT, Phase.EXPLOIT)
    approvals_seen: int = 0

    # ------------------------------------------------------------------
    def score(self, intent: Intent) -> float:
        risk = 0.1
        if intent.phase is Phase.DETECT:
            risk = 0.35
        elif intent.phase is Phase.EXPLOIT:
            risk = 0.8
        elif intent.phase is Phase.VERIFY:
            risk = 0.45
        haystack = f"{intent.title} {intent.description} {intent.tool}"
        if _ACTIVE_HINTS.search(haystack):
            # An exploit-phase intent is already scored high and gated on --exploit;
            # keyword inflation there would push ordinary exploitation past the ceiling.
            risk += 0.05 if intent.phase is Phase.EXPLOIT else 0.15
        if _DESTRUCTIVE_HINTS.search(f"{haystack} {intent.arguments}"):
            risk = max(risk, 0.95)
        if str(intent.arguments.get("method", "")).upper() in {"PUT", "PATCH", "DELETE"}:
            risk += 0.1
        concurrency = intent.arguments.get("concurrency")
        if isinstance(concurrency, int) and concurrency > 20:
            risk += 0.15
        return min(1.0, round(max(risk, intent.risk), 3))

    def gate(self, intent: Intent) -> SafetyDecision:
        risk = self.score(intent)
        intent.risk = risk

        if intent.phase not in self.allow_phases:
            return SafetyDecision.deny(f"phase {intent.phase.value} is disabled for this run", rule="phase")
        if intent.phase is Phase.EXPLOIT and not self.exploit_enabled:
            return SafetyDecision.deny("exploitation is disabled; pass --exploit to enable it", rule="exploit")
        if risk > self.max_risk_approved:
            return SafetyDecision.deny(f"risk {risk:.2f} above the maximum approvable {self.max_risk_approved:.2f}", rule="risk")
        if not self.autonomy.allows_active and intent.phase in {Phase.DETECT, Phase.EXPLOIT}:
            return SafetyDecision.deny(
                f"autonomy {self.autonomy.value} does not permit {intent.phase.value} work", rule="autonomy"
            )
        if self.autonomy is AutonomyLevel.ASSIST or risk > self.max_risk_auto:
            return SafetyDecision(
                True,
                reason=f"risk {risk:.2f} needs approval under {self.autonomy.value}",
                requires_approval=True,
                rule="approval",
                risk=risk,
            )
        return SafetyDecision.allow(reason=f"risk {risk:.2f} within {self.autonomy.value}", risk=risk)

    # ------------------------------------------------------------------
    def filter(self, intents: Iterable[Intent]) -> tuple[list[Intent], list[tuple[Intent, SafetyDecision]]]:
        allowed: list[Intent] = []
        blocked: list[tuple[Intent, SafetyDecision]] = []
        for intent in intents:
            decision = self.gate(intent)
            if decision.allowed:
                allowed.append(intent)
            else:
                intent.mark(intent.status.BLOCKED, result=decision.reason)
                blocked.append((intent, decision))
        return allowed, blocked

    def describe(self) -> dict[str, Any]:
        return {
            "autonomy": self.autonomy.value,
            "autonomy_meaning": self.autonomy.describe(),
            "exploit_enabled": self.exploit_enabled,
            "max_risk_auto": self.max_risk_auto,
            "max_risk_approved": self.max_risk_approved,
            "phases": [phase.value for phase in self.allow_phases],
        }
