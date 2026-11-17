"""Persist a session so a run can be resumed without repeating itself.

A run that stops for an approval, a budget or an operator pause should continue
where it left off: same graphs, same facts, same budget counters, same pending
intents. This module writes that state to JSON and reads it back.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from candix.agent.budget import AgentBudget, BudgetLimits
from candix.agent.facts import Confidence, Fact, FactSource, FactStore
from candix.agent.graph import AssetGraph, ExplorationGraph
from candix.agent.models import Intent, IntentStatus, Phase
from candix.agent.policy import AutonomyLevel

STATE_VERSION = 2


class StateError(RuntimeError):
    """Raised when a saved state cannot be read safely."""


@dataclass
class SessionState:
    run_id: str = ""
    goal: str = ""
    targets: list[str] = field(default_factory=list)
    autonomy: str = "assist"
    exploit: bool = False
    assets: dict[str, Any] = field(default_factory=dict)
    exploration: dict[str, Any] = field(default_factory=dict)
    facts: list[dict[str, Any]] = field(default_factory=list)
    intents: list[dict[str, Any]] = field(default_factory=list)
    attempts: dict[str, int] = field(default_factory=dict)
    budget: dict[str, Any] = field(default_factory=dict)
    telemetry: dict[str, Any] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)
    version: int = STATE_VERSION

    # ------------------------------------------------------------------
    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "run_id": self.run_id,
            "goal": self.goal,
            "targets": list(self.targets),
            "autonomy": self.autonomy,
            "exploit": self.exploit,
            "assets": self.assets,
            "exploration": self.exploration,
            "facts": self.facts,
            "intents": self.intents,
            "attempts": self.attempts,
            "budget": self.budget,
            "telemetry": self.telemetry,
            "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "SessionState":
        version = int(payload.get("version", 1))
        if version > STATE_VERSION:
            raise StateError(f"state version {version} is newer than this build ({STATE_VERSION})")
        return cls(
            run_id=str(payload.get("run_id", "")),
            goal=str(payload.get("goal", "")),
            targets=[str(item) for item in payload.get("targets") or []],
            autonomy=str(payload.get("autonomy", "assist")),
            exploit=bool(payload.get("exploit", False)),
            assets=dict(payload.get("assets") or {}),
            exploration=dict(payload.get("exploration") or {}),
            facts=list(payload.get("facts") or []),
            intents=list(payload.get("intents") or []),
            attempts=dict(payload.get("attempts") or {}),
            budget=dict(payload.get("budget") or {}),
            telemetry=dict(payload.get("telemetry") or {}),
            notes=[str(item) for item in payload.get("notes") or []],
            version=version,
        )

    def save(self, path: str | Path) -> str:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        tmp = target.with_suffix(target.suffix + ".tmp")
        tmp.write_text(json.dumps(self.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")
        tmp.replace(target)
        return str(target)

    @classmethod
    def load(cls, path: str | Path) -> "SessionState":
        try:
            payload = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, ValueError) as error:
            raise StateError(f"cannot read state: {error}") from error
        if not isinstance(payload, dict):
            raise StateError("state file is not an object")
        return cls.from_dict(payload)


# ----------------------------------------------------------------------
def capture(session: Any, *, intents: list[Intent] | None = None, notes: list[str] | None = None) -> SessionState:
    """Snapshot a live session into a serialisable state."""

    state = SessionState(
        run_id=str(getattr(session, "id", "")),
        goal=session.settings.goal,
        targets=list(session.targets),
        autonomy=session.settings.autonomy.value,
        exploit=bool(session.settings.exploit),
        assets=session.assets.to_dict(),
        exploration=session.exploration.to_dict(),
        facts=[fact.to_dict() for fact in session.blackboard.facts.facts.values()],
        intents=[intent.to_dict() for intent in (intents or [])],
        budget=session.budget.snapshot(),
        telemetry=session.telemetry.snapshot(),
        notes=list(notes or []),
    )
    for intent in intents or []:
        state.attempts[intent.tool] = state.attempts.get(intent.tool, 0) + intent.attempts
    return state


def restore(session: Any, state: SessionState) -> dict[str, Any]:
    """Apply a state to an existing session and return what was restored."""

    restored = {"assets": 0, "facts": 0, "intents": 0, "budget": False}
    try:
        session.assets = AssetGraph.from_dict(state.assets)
        session.exploration = ExplorationGraph.from_dict(state.exploration)
        restored["assets"] = len(session.assets)
    except Exception as error:
        raise StateError(f"asset graph is corrupt: {error}") from error

    store = FactStore()
    for item in state.facts:
        try:
            store.add(
                Fact(
                    claim=str(item.get("claim", "")),
                    source=FactSource(str(item.get("source", "inference"))),
                    confidence=Confidence(str(item.get("confidence", "inferred"))),
                    subject=str(item.get("subject", "")),
                    evidence=list(item.get("evidence") or []),
                )
            )
            restored["facts"] += 1
        except Exception:
            continue
    session.blackboard.facts = store

    limits = state.budget.get("limits") or {}
    if limits:
        session.budget = AgentBudget(
            limits=BudgetLimits(
                turns=int(limits.get("turns", 12)),
                tool_calls=int(limits.get("tool_calls", 60)),
                tokens=int(limits.get("tokens", 200000)),
                seconds=float(limits.get("seconds", 900)),
                cost_usd=float(limits.get("cost_usd", 0.0)),
                intents=int(limits.get("intents", 40)),
                consecutive_failures=int(limits.get("consecutive_failures", 4)),
            ),
            turns=int(state.budget.get("turns", 0)),
            tool_calls=int(state.budget.get("tool_calls", 0)),
            tokens=int(state.budget.get("tokens", 0)),
            intents=int(state.budget.get("intents", 0)),
        )
        restored["budget"] = True

    session.tool_context.state["assets"] = session.assets
    session.tool_context.state["facts"] = session.blackboard.facts
    restored["intents"] = len(state.intents)
    return restored


def pending_intents(state: SessionState) -> list[Intent]:
    """Intents that were queued or interrupted and should be retried."""

    output: list[Intent] = []
    for payload in state.intents:
        status = str(payload.get("status", "pending"))
        if status in {IntentStatus.DONE.value, IntentStatus.CANCELLED.value, IntentStatus.BLOCKED.value}:
            continue
        try:
            intent = Intent.from_dict(payload)
        except Exception:
            continue
        intent.status = IntentStatus.PENDING
        output.append(intent)
    return output


def merge_states(first: SessionState, second: SessionState) -> SessionState:
    """Combine two snapshots, preferring the newer graph and the larger budget."""

    merged = SessionState.from_dict(first.to_dict())
    merged.assets = _merge_graph(first.assets, second.assets)
    merged.exploration = _merge_graph(first.exploration, second.exploration)
    seen: set[str] = {str(item.get("claim", "")) for item in merged.facts}
    for item in second.facts:
        if str(item.get("claim", "")) not in seen:
            merged.facts.append(item)
            seen.add(str(item.get("claim", "")))
    for name, count in second.attempts.items():
        merged.attempts[name] = max(merged.attempts.get(name, 0), int(count))
    used = max(int(first.budget.get("tool_calls", 0)), int(second.budget.get("tool_calls", 0)))
    merged.budget = dict(second.budget or first.budget)
    merged.budget["tool_calls"] = used
    merged.notes = list(dict.fromkeys(first.notes + second.notes))
    return merged


def _merge_graph(left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any]:
    if not left:
        return dict(right)
    if not right:
        return dict(left)
    merged = json.loads(json.dumps(left))
    nodes = {node.get("id"): node for node in merged.get("nodes", [])}
    for node in right.get("nodes", []):
        nodes.setdefault(node.get("id"), node)
    merged["nodes"] = list(nodes.values())
    edges = {edge.get("id"): edge for edge in merged.get("edges", [])}
    for edge in right.get("edges", []):
        edges.setdefault(edge.get("id"), edge)
    merged["edges"] = list(edges.values())
    return merged


def summary(state: SessionState) -> str:
    assets = state.assets or {}
    endpoints = sum(1 for node in assets.get("nodes", []) if str(node.get("kind")) in {"endpoint", "NodeKind.ENDPOINT"})
    return (
        f"run {state.run_id or '?'}: {len(state.targets)} target(s), {endpoints} endpoint(s), "
        f"{len(state.facts)} fact(s), {len(state.intents)} intent(s), "
        f"{state.budget.get('tool_calls', 0)} tool call(s) spent"
    )


def autonomy_of(state: SessionState) -> AutonomyLevel:
    try:
        return AutonomyLevel(str(state.autonomy))
    except ValueError:
        return AutonomyLevel.ASSIST


def phase_of(intent: Intent) -> Phase:
    return intent.phase
