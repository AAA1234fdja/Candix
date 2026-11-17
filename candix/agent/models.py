"""Core data model for an autonomous run.

The vocabulary is deliberately small:

``Goal``       what the operator asked for, in one sentence, with success criteria
``Intent``     one bounded unit of work the planner believes moves the goal forward
``Step``       a single tool call inside an intent
``Observation``what a tool returned, wrapped so the model treats it as data
``Decision``   the planner's next move, recorded with the reasoning that produced it
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterable


def new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}"


class IntentStatus(str, Enum):
    PENDING = "pending"
    READY = "ready"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"
    BLOCKED = "blocked"
    CANCELLED = "cancelled"
    AWAITING_APPROVAL = "awaiting_approval"

    @property
    def terminal(self) -> bool:
        return self in {IntentStatus.DONE, IntentStatus.FAILED, IntentStatus.CANCELLED, IntentStatus.BLOCKED}


class Phase(str, Enum):
    RECON = "recon"
    DETECT = "detect"
    EXPLOIT = "exploit"
    VERIFY = "verify"
    REPORT = "report"


class Outcome(str, Enum):
    PROGRESS = "progress"
    NO_PROGRESS = "no_progress"
    BLOCKED = "blocked"
    ERROR = "error"


@dataclass
class Goal:
    statement: str
    success_criteria: list[str] = field(default_factory=list)
    targets: list[str] = field(default_factory=list)
    constraints: list[str] = field(default_factory=list)
    max_phases: int = 4
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "statement": self.statement,
            "success_criteria": list(self.success_criteria),
            "targets": list(self.targets),
            "constraints": list(self.constraints),
            "max_phases": self.max_phases,
        }


@dataclass
class Intent:
    """One unit of planned work."""

    title: str
    description: str = ""
    phase: Phase = Phase.RECON
    tool: str = ""
    arguments: dict[str, Any] = field(default_factory=dict)
    priority: float = 0.5
    risk: float = 0.0
    id: str = field(default_factory=lambda: new_id("intent"))
    status: IntentStatus = IntentStatus.PENDING
    depends_on: list[str] = field(default_factory=list)
    attempts: int = 0
    max_attempts: int = 2
    created_at: float = field(default_factory=time.time)
    started_at: float = 0.0
    finished_at: float = 0.0
    result: str = ""
    steps: list["Step"] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    origin: str = "planner"

    def __post_init__(self) -> None:
        if not isinstance(self.phase, Phase):
            self.phase = Phase(str(self.phase))
        if not isinstance(self.status, IntentStatus):
            self.status = IntentStatus(str(self.status))

    @property
    def duration(self) -> float:
        if not self.started_at:
            return 0.0
        return (self.finished_at or time.monotonic()) - self.started_at

    def mark(self, status: IntentStatus, *, result: str = "") -> "Intent":
        self.status = status
        if result:
            self.result = result
        if status is IntentStatus.RUNNING and not self.started_at:
            self.started_at = time.monotonic()
        if status.terminal:
            self.finished_at = time.monotonic()
        return self

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "phase": self.phase.value,
            "tool": self.tool,
            "arguments": dict(self.arguments),
            "priority": round(self.priority, 3),
            "risk": round(self.risk, 3),
            "status": self.status.value,
            "depends_on": list(self.depends_on),
            "attempts": self.attempts,
            "result": self.result,
            "tags": list(self.tags),
            "duration": round(self.duration, 3),
            "origin": self.origin,
            "steps": [step.to_dict() for step in self.steps],
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "Intent":
        intent = cls(
            title=str(payload.get("title", "")),
            description=str(payload.get("description", "")),
            phase=Phase(payload.get("phase", "recon")),
            tool=str(payload.get("tool", "")),
            arguments=dict(payload.get("arguments") or {}),
            priority=float(payload.get("priority", 0.5) or 0.5),
            risk=float(payload.get("risk", 0.0) or 0.0),
            id=str(payload.get("id") or new_id("intent")),
            status=IntentStatus(payload.get("status", "pending")),
            depends_on=[str(item) for item in payload.get("depends_on") or []],
            attempts=int(payload.get("attempts", 0) or 0),
            result=str(payload.get("result", "")),
            tags=[str(item) for item in payload.get("tags") or []],
            origin=str(payload.get("origin", "planner")),
        )
        intent.steps = [Step.from_dict(item) for item in payload.get("steps") or []]
        return intent


@dataclass
class Step:
    """One tool execution."""

    tool: str
    arguments: dict[str, Any] = field(default_factory=dict)
    ok: bool = True
    output: str = ""
    error: str = ""
    started: float = field(default_factory=time.monotonic)
    finished: float = 0.0
    tokens: int = 0

    @property
    def duration(self) -> float:
        return (self.finished or time.monotonic()) - self.started

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "arguments": dict(self.arguments),
            "ok": self.ok,
            "output": self.output[:2000],
            "error": self.error,
            "duration": round(self.duration, 3),
            "tokens": self.tokens,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "Step":
        return cls(
            tool=str(payload.get("tool", "")),
            arguments=dict(payload.get("arguments") or {}),
            ok=bool(payload.get("ok", True)),
            output=str(payload.get("output", "")),
            error=str(payload.get("error", "")),
            tokens=int(payload.get("tokens", 0) or 0),
        )


@dataclass
class Observation:
    """A tool result as the agent sees it: data, never instructions."""

    tool: str
    summary: str
    payload: dict[str, Any] = field(default_factory=dict)
    digest: str = ""
    untrusted: bool = True
    truncated: bool = False
    at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "summary": self.summary,
            "payload": dict(self.payload),
            "digest": self.digest,
            "untrusted": self.untrusted,
            "truncated": self.truncated,
        }


@dataclass
class Decision:
    """A planner decision with the reasoning that justifies it."""

    action: str
    reasoning: str = ""
    intents: list[Intent] = field(default_factory=list)
    confidence: float = 0.5
    source: str = "heuristic"
    at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "reasoning": self.reasoning,
            "confidence": round(self.confidence, 3),
            "source": self.source,
            "intents": [intent.to_dict() for intent in self.intents],
        }


@dataclass
class ProofObligation:
    """What the agent still has to demonstrate before it may close the goal."""

    claim: str
    required_sources: tuple[str, ...] = ("tool_output", "operator_input", "third_party_intel", "inference")
    satisfied_by: list[str] = field(default_factory=list)
    blocked_reason: str = ""

    @property
    def satisfied(self) -> bool:
        return bool(self.satisfied_by)

    def to_dict(self) -> dict[str, Any]:
        return {
            "claim": self.claim,
            "required_sources": list(self.required_sources),
            "satisfied_by": list(self.satisfied_by),
            "satisfied": self.satisfied,
            "blocked_reason": self.blocked_reason,
        }


@dataclass
class TaskResult:
    """Everything one run produced."""

    goal: Goal
    intents: list[Intent] = field(default_factory=list)
    observations: list[Observation] = field(default_factory=list)
    decisions: list[Decision] = field(default_factory=list)
    proofs: list[dict[str, Any]] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    lessons: list[dict[str, Any]] = field(default_factory=list)
    stop_reason: str = "unknown"
    started_at: float = field(default_factory=time.time)
    finished_at: float = 0.0

    @property
    def duration(self) -> float:
        return (self.finished_at or time.time()) - self.started_at

    def counts(self) -> dict[str, int]:
        grouped: dict[str, int] = {}
        for intent in self.intents:
            grouped[intent.status.value] = grouped.get(intent.status.value, 0) + 1
        return grouped

    def to_dict(self) -> dict[str, Any]:
        return {
            "goal": self.goal.to_dict(),
            "stop_reason": self.stop_reason,
            "duration": round(self.duration, 2),
            "intents": [intent.to_dict() for intent in self.intents],
            "observations": [item.to_dict() for item in self.observations],
            "decisions": [item.to_dict() for item in self.decisions],
            "proofs": list(self.proofs),
            "findings": list(self.findings),
            "lessons": list(self.lessons),
            "counts": self.counts(),
        }


def phase_order() -> list[Phase]:
    return [Phase.RECON, Phase.DETECT, Phase.EXPLOIT, Phase.VERIFY, Phase.REPORT]


def summarize_intents(intents: Iterable[Intent]) -> str:
    materialized = list(intents)
    if not materialized:
        return "no intents"
    done = sum(1 for intent in materialized if intent.status is IntentStatus.DONE)
    failed = sum(1 for intent in materialized if intent.status is IntentStatus.FAILED)
    return f"{done}/{len(materialized)} done, {failed} failed"
