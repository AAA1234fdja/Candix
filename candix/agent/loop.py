"""The agent loop: plan, gate, act, observe, write back."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable

from candix.agent.approvals import ApprovalQueue, ApprovalStatus
from candix.agent.blackboard import Blackboard
from candix.agent.budget import AgentBudget
from candix.agent.facts import FactStore
from candix.agent.graph import AssetGraph, ExplorationGraph
from candix.agent.guard import SafetyDecision
from candix.agent.journal import Journal, NullJournal
from candix.agent.models import Decision, Goal, Intent, IntentStatus, Observation, Phase, TaskResult, IntentStatus as _IS
from candix.agent.planner import PlannerState
from candix.agent.policy import RiskPolicy
from candix.agent.scheduler import IntentScheduler
from candix.agent.telemetry import Telemetry
from candix.agent.tools import ToolContext
from candix.llm.errors import BudgetExhausted


@dataclass
class LoopConfig:
    max_intents_per_turn: int = 3
    max_turns: int = 10
    stop_after_stalls: int = 2
    stop_on_approval: bool = True
    verify_before_finish: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "max_intents_per_turn": self.max_intents_per_turn,
            "max_turns": self.max_turns,
            "stop_after_stalls": self.stop_after_stalls,
            "stop_on_approval": self.stop_on_approval,
            "verify_before_finish": self.verify_before_finish,
        }


@dataclass
class LoopEvent:
    kind: str
    payload: dict[str, Any]
    at: float = field(default_factory=time.time)


class AgentLoop:
    """Coordinates the planner, the policy and the workers for one goal."""

    def __init__(
        self,
        *,
        goal: Goal,
        planner: Any,
        worker: Any,
        context: ToolContext,
        policy: RiskPolicy,
        approvals: ApprovalQueue,
        budget: AgentBudget,
        telemetry: Telemetry,
        journal: Journal | NullJournal | None = None,
        assets: AssetGraph | None = None,
        exploration: ExplorationGraph | None = None,
        blackboard: Blackboard | None = None,
        scheduler: IntentScheduler | None = None,
        verifier: Any = None,
        memory: Any = None,
        config: LoopConfig | None = None,
        on_event: Callable[[str, dict[str, Any]], None] | None = None,
    ) -> None:
        self.goal = goal
        self.planner = planner
        self.worker = worker
        self.context = context
        self.policy = policy
        self.approvals = approvals
        self.budget = budget
        self.telemetry = telemetry
        self.journal = journal or NullJournal()
        # Graphs are falsy when empty, so they must not be selected with ``or``.
        self.assets = assets if assets is not None else AssetGraph()
        self.exploration = exploration if exploration is not None else ExplorationGraph()
        self.blackboard = blackboard if blackboard is not None else Blackboard()
        self.scheduler = scheduler or IntentScheduler()
        self.verifier = verifier
        self.memory = memory
        self.config = config or LoopConfig()
        self.on_event = on_event
        self.events: list[LoopEvent] = []

    # ------------------------------------------------------------------
    def run(self) -> TaskResult:
        result = TaskResult(goal=self.goal)
        self.context.state.setdefault("assets", self.assets)
        self.context.state.setdefault("facts", self.blackboard.facts)
        self.context.state.setdefault("blackboard", self.blackboard)
        self.context.state.setdefault("goal", self.goal.statement)
        self.journal.append(
            "run.start",
            {
                "goal": self.goal.statement,
                "targets": list(self.goal.targets),
                "policy": self.policy.describe(),
                "budget": self.budget.limits.to_dict(),
            },
        )
        self._emit("run.start", {"goal": self.goal.statement})
        stalls = 0
        stop_reason = ""

        while True:
            try:
                self.budget.start_turn()
            except BudgetExhausted as exhausted:
                stop_reason = str(exhausted)
                break
            if self.config.max_turns and self.budget.turns > self.config.max_turns:
                stop_reason = f"turn cap reached ({self.config.max_turns})"
                break

            state = self._planner_state()
            decision = self.planner.decide(state)
            result.decisions.append(decision)
            self.journal.append(
                "plan",
                {"action": decision.action, "reasoning": decision.reasoning[:400], "intents": [i.to_dict() for i in decision.intents]},
            )
            self._emit("plan", {"action": decision.action, "reasoning": decision.reasoning, "count": len(decision.intents)})

            if decision.action == "finish":
                stop_reason = decision.reasoning or "planner finished"
                break

            approved, asked = self._gate(decision.intents, result)
            if not approved:
                if asked and self.config.stop_on_approval:
                    stop_reason = f"waiting for {asked} approval(s)"
                    break
                stalls += 1
                if stalls >= self.config.stop_after_stalls:
                    stop_reason = "no runnable intents"
                    break
                continue

            progressed = False
            for intent in approved[: self.config.max_intents_per_turn]:
                try:
                    self.budget.spend_intent()
                except BudgetExhausted as exhausted:
                    stop_reason = str(exhausted)
                    break
                outcome = self._execute(intent, result)
                progressed = progressed or outcome
                if stop_reason:
                    break
            if stop_reason:
                break

            if self._goal_proven(result):
                stop_reason = "goal proven"
                break
            if not progressed:
                stalls += 1
                self.telemetry.increment("loop.stalls")
                if stalls >= self.config.stop_after_stalls:
                    stop_reason = "no progress after repeated attempts"
                    break

        result.stop_reason = stop_reason or "loop ended"
        result.finished_at = time.time()
        self.journal.append(
            "run.finish",
            {
                "stop_reason": result.stop_reason,
                "counts": result.counts(),
                "budget": self.budget.snapshot(),
                "proofs": len(result.proofs),
            },
        )
        self._emit("run.finish", {"stop_reason": result.stop_reason, "counts": result.counts()})
        self.telemetry.gauge("loop.turns", self.budget.turns)
        self.telemetry.gauge("findings", len(result.findings))
        return result

    # ------------------------------------------------------------------
    def _planner_state(self) -> PlannerState:
        coverage = self.assets.coverage()
        attempted = [
            f"{node.attributes.get('tool', '')}:{node.label}"
            for node in self.exploration.of_kind("intent")
            if node.attributes.get("status") in {"done", "failed"}
        ]
        blocked = [
            f"{node.label} ({node.attributes.get('status')})"
            for node in self.exploration.of_kind("intent")
            if node.attributes.get("status") in {"blocked", "failed"}
        ]
        return PlannerState(
            goal=self.goal.statement,
            targets=list(self.goal.targets),
            phase=self._phase(),
            findings=self._findings(),
            coverage=coverage,
            blackboard=self.blackboard.render(limit=15),
            attempted=attempted,
            blocked=blocked,
            remaining_turns=self.budget.remaining_turns,
            exploit_enabled=self.policy.exploit_enabled,
            facts=len(self.blackboard.facts),
            provable_facts=len(self.blackboard.facts.provable()),
            proofs=len(self.context.state.get("proofs") or []),
        )

    def _findings(self) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for node in self.assets.of_kind("finding"):
            rows.append(
                {
                    "id": node.id,
                    "title": node.label,
                    "severity": node.attributes.get("severity"),
                    "url": node.attributes.get("url"),
                    "verified": node.attributes.get("verified"),
                    "category": node.attributes.get("category"),
                }
            )
        return rows

    def _phase(self) -> Phase:
        coverage = self.assets.coverage()
        if not coverage.get("endpoints"):
            return Phase.RECON
        if not coverage.get("findings"):
            return Phase.DETECT
        if self.policy.exploit_enabled and any(
            node.attributes.get("severity") in {"critical", "high"} for node in self.assets.of_kind("finding")
        ):
            return Phase.EXPLOIT
        return Phase.VERIFY

    def _gate(self, intents: list[Intent], result: TaskResult) -> tuple[list[Intent], int]:
        approved: list[Intent] = []
        asked = 0
        for intent in intents:
            decision = self.policy.gate(intent)
            if intent not in result.intents:
                result.intents.append(intent)
            self.exploration.add_intent(intent)
            if not decision.allowed:
                intent.mark(IntentStatus.BLOCKED, result=decision.reason)
                self.journal.append("intent.blocked", {"intent": intent.id, "reason": decision.reason, "rule": decision.rule})
                self._emit("intent.blocked", {"title": intent.title, "reason": decision.reason})
                continue
            if decision.requires_approval:
                request = self.approvals.request(intent, decision.reason, risk=decision.risk)
                if request.status is ApprovalStatus.APPROVED:
                    approved.append(intent)
                else:
                    asked += 1
                    intent.mark(IntentStatus.AWAITING_APPROVAL, result=request.reason)
                    self._emit("intent.awaiting_approval", {"title": intent.title, "id": request.id, "risk": decision.risk})
                    self.journal.append("intent.awaiting_approval", {"intent": intent.id, "request": request.id})
                continue
            approved.append(intent)
        return approved, asked

    def _execute(self, intent: Intent, result: TaskResult) -> bool:
        intent.mark(IntentStatus.RUNNING)
        self.journal.append("intent.start", {"intent": intent.id, "title": intent.title, "tool": intent.tool})
        self._emit("intent.start", {"title": intent.title, "tool": intent.tool})
        started = time.monotonic()
        try:
            worker_result = self.worker.run(intent, self.context)
        except BudgetExhausted as exhausted:
            intent.mark(IntentStatus.BLOCKED, result=str(exhausted))
            self.journal.append("intent.blocked", {"intent": intent.id, "reason": str(exhausted)})
            raise
        except Exception as error:  # a worker crash must not lose the run
            intent.mark(IntentStatus.FAILED, result=f"{type(error).__name__}: {error}")
            self.budget.record_outcome(False)
            self.telemetry.increment("worker.crashed")
            self.journal.append("intent.crash", {"intent": intent.id, "error": repr(error)})
            self._emit("intent.failed", {"title": intent.title, "error": str(error)})
            return False

        duration = time.monotonic() - started
        self.telemetry.observe("intent.duration", duration)
        self.telemetry.increment("intents.ok" if worker_result.ok else "intents.failed")
        self.budget.record_outcome(worker_result.ok)
        intent.attempts += 1
        intent.mark(IntentStatus.DONE if worker_result.ok else IntentStatus.FAILED, result=worker_result.summary[:400])

        self.exploration.add_intent(intent)
        for observation in worker_result.observations:
            result.observations.append(observation)
            node = self.exploration.add_observation(observation)
            self.exploration.link_intent_observation(intent.id, node.id, step=intent.tool)
            self.journal.append(
                "observation",
                {"intent": intent.id, "tool": observation.tool, "digest": observation.digest, "summary": observation.summary[:300]},
            )
        if worker_result.ok and "verify" in intent.tags:
            self._mark_verified(str(intent.arguments.get("url", "")), result)
        self._absorb(worker_result, result)
        self.journal.append(
            "intent.finish",
            {
                "intent": intent.id,
                "ok": worker_result.ok,
                "duration": round(duration, 3),
                "summary": worker_result.summary[:300],
            },
        )
        self._emit(
            "intent.finish",
            {"title": intent.title, "ok": worker_result.ok, "summary": worker_result.summary[:200], "duration": round(duration, 2)},
        )
        return worker_result.ok and bool(worker_result.observations)

    def _absorb(self, worker_result: Any, result: TaskResult) -> None:
        steps = getattr(worker_result, "steps", []) or []
        for step in steps:
            if step.get("tool") == "detect.run":
                for finding in step.get("findings") or []:
                    self._register_finding(finding, result)
        for observation in getattr(worker_result, "observations", []) or []:
            payload = observation.payload or {}
            if payload:
                from candix.agent.contracts import validate as validate_contract

                check = validate_contract(getattr(observation, "tool", ""), payload)
                if not check.ok:
                    self.telemetry.increment("contract.violations")
                    self.journal.append(
                        "contract.violation",
                        {"tool": check.tool, "problems": check.problems[:3]},
                    )
                else:
                    payload = check.payload
            for finding in payload.get("findings") or []:
                self._register_finding(finding, result)
            for proof in payload.get("proofs") or []:
                record = dict(proof) if isinstance(proof, dict) else {"summary": str(proof)}
                record.setdefault("claim", self.goal.statement)
                if record not in result.proofs:
                    result.proofs.append(record)
                    self.journal.append("proof", {"intent": worker_result.intent.id, "summary": record.get("summary", "")})
                    self.telemetry.increment("proofs")
                    self._emit("proof", record)
            if payload.get("proven"):
                result.proofs.append(
                    {"claim": payload.get("summary", ""), "facts": payload.get("facts") or [], "intent": worker_result.intent.id}
                )
                self.journal.append("proof", {"intent": worker_result.intent.id, "summary": payload.get("summary", "")})
        proofs = self.context.state.get("proofs") or []
        for proof in proofs:
            if proof not in result.proofs:
                result.proofs.append(proof)

    def _mark_verified(self, url: str, result: TaskResult) -> None:
        if not url:
            return
        changed = False
        for finding in result.findings:
            if str(finding.get("url", "")) == url and not finding.get("verified"):
                finding["verified"] = True
                changed = True
        for node in self.assets.of_kind("finding"):
            if str(node.attributes.get("url", "")) == url:
                node.attributes["verified"] = True
                changed = True
        if changed:
            self.telemetry.increment("findings.verified")
            self.journal.append("finding.verified", {"url": url})

    def _already_known(self, finding: dict[str, Any], result: TaskResult) -> bool:
        key = (
            str(finding.get("title", "")).strip().lower(),
            str(finding.get("url", "")).strip().lower(),
            str(finding.get("parameter", "")).strip().lower(),
        )
        for existing in result.findings:
            other = (
                str(existing.get("title", "")).strip().lower(),
                str(existing.get("url", "")).strip().lower(),
                str(existing.get("parameter", "")).strip().lower(),
            )
            if key == other:
                existing["verified"] = bool(existing.get("verified")) or bool(finding.get("verified"))
                existing["exploited"] = bool(existing.get("exploited")) or bool(finding.get("exploited"))
                return True
        return False

    def _register_finding(self, finding: dict[str, Any], result: TaskResult) -> None:
        if self._already_known(finding, result):
            self.telemetry.increment("findings.duplicate")
            return
        key = finding.get("id") or finding.get("title")
        if any(item.get("id") == key for item in result.findings):
            return
        result.findings.append(finding)
        node = self.assets.add_finding(finding)
        self.exploration.upsert(node.id, node.kind, node.label, **node.attributes)
        self.telemetry.increment("findings.registered")
        self.journal.append(
            "finding",
            {"id": key, "title": finding.get("title"), "severity": finding.get("severity"), "url": finding.get("url")},
        )
        self._emit("finding", {"title": finding.get("title"), "severity": finding.get("severity")})

    def _goal_proven(self, result: TaskResult) -> bool:
        """A goal is closed by an accepted proof, never by enthusiasm.

        Findings alone do not close a goal: the agent must have called
        ``goal.prove`` and had at least one fact accepted.
        """

        return bool(result.proofs)

    # ------------------------------------------------------------------
    def _emit(self, kind: str, payload: dict[str, Any]) -> None:
        self.events.append(LoopEvent(kind, payload))
        if self.on_event is not None:
            try:
                self.on_event(kind, payload)
            except Exception:
                pass
