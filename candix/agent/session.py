"""Session: one engagement, one goal, one run.

The session owns everything that outlives a single loop turn - the scan context,
the graphs, the fact store, the journal, the budget - and builds the planner and
worker the loop needs. Callers (CLI, API, tests) only see ``run()`` and the
snapshot it returns.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable

from candix.agent.approvals import ApprovalQueue
from candix.agent.blackboard import Blackboard
from candix.agent.budget import AgentBudget, BudgetLimits
from candix.agent.facts import FactStore
from candix.agent.graph import AssetGraph, ExplorationGraph, LinkedGraphs
from candix.agent.guard import DenyList, OutputGuard, RedLines, SafetyDecision, ScopeGuard
from candix.agent.harness import Harness, HarnessSettings
from candix.agent.journal import Journal, NullJournal
from candix.agent.loop import AgentLoop, LoopConfig
from candix.agent.memory import MemoryStore
from candix.agent.models import Goal, TaskResult, new_id
from candix.agent.planner import HeuristicPlanner, LLMPlanner
from candix.agent.policy import AutonomyLevel, RiskPolicy
from candix.agent.reflection import reflect
from candix.agent.scheduler import IntentScheduler
from candix.agent.skills import SkillRegistry
from candix.agent.telemetry import Telemetry
from candix.agent.toolset import default_registry
from candix.agent.tools import ToolContext, ToolRegistry
from candix.agent.verifier import Verifier
from candix.agent.worker import DeterministicWorker, LLMWorker
from candix.core.scope import Engagement
from candix.llm.client import LLMClient
from candix.llm.errors import BudgetExhausted


@dataclass
class AgentSettings:
    """Everything the operator can change about a run."""

    engine: dict[str, object] = field(default_factory=dict)
    goal: str = "assess the target and prove what you can"
    autonomy: AutonomyLevel = AutonomyLevel.ASSIST
    exploit: bool = False
    limits: BudgetLimits = field(default_factory=BudgetLimits)
    artifacts_dir: str = ""
    journal_path: str = ""
    memory_path: str = ""
    skills_dir: str = ""
    max_intents_per_turn: int = 3
    max_turns: int = 10
    use_llm: bool = True
    worker_max_steps: int = 4
    approve_mode: str = "ask"
    success_criteria: list[str] = field(default_factory=list)
    verify: bool = True
    dry_run: bool = False
    playbook: str = ""
    playbook_limit: int = 0
    adaptive: bool = False
    adaptive_strategy: str = "ucb"
    explore_ratio: float = 0.3
    priors_path: str = ""
    use_priors: bool = True
    gate: bool = True
    gate_max_risk: int = 70
    allow_commands: tuple[str, ...] = ()
    allow_private: bool = False
    notify_config: dict[str, Any] = field(default_factory=dict)
    notify_min_severity: str = "high"
    poc: bool = True
    review: bool = True
    todos: bool = True
    targeting: bool = True

    def loop_config(self) -> LoopConfig:
        return LoopConfig(max_intents_per_turn=self.max_intents_per_turn, max_turns=self.max_turns, verify_before_finish=self.verify)

    def to_dict(self) -> dict[str, Any]:
        return {
            "goal": self.goal,
            "autonomy": self.autonomy.value,
            "exploit": self.exploit,
            "approve_mode": self.approve_mode,
            "use_llm": self.use_llm,
            "max_turns": self.max_turns,
            "adaptive": self.adaptive,
            "adaptive_strategy": self.adaptive_strategy,
            "success_criteria": list(self.success_criteria),
            "limits": self.limits.to_dict(),
            "gate": self.gate,
            "gate_max_risk": self.gate_max_risk,
            "allow_commands": list(self.allow_commands),
            "allow_private": self.allow_private,
            "notify": sorted(self.notify_config.keys()),
            "notify_min_severity": self.notify_min_severity,
            "poc": self.poc,
            "review": self.review,
            "todos": self.todos,
            "targeting": self.targeting,
        }


class AgentSession:
    """Builds and runs the agent against a live scan context."""

    def __init__(
        self,
        *,
        settings: AgentSettings,
        targets: list[str],
        context: Any,
        guard: ScopeGuard,
        registry: ToolRegistry,
        client: LLMClient | None = None,
        skills: SkillRegistry | None = None,
        memory: MemoryStore | None = None,
        on_event: Callable[[str, dict[str, Any]], None] | None = None,
    ) -> None:
        self.settings = settings
        self.targets = list(targets)
        self.id = new_id("run")
        self.context = context
        self.guard = guard
        self.registry = registry
        self.client = client
        self.skills = skills or SkillRegistry()
        self.memory = memory or MemoryStore()
        self.on_event = on_event
        self.planner_factory: Callable[["AgentSession"], Any] | None = None
        self.worker_factory: Callable[["AgentSession"], Any] | None = None

        self.budget = AgentBudget(limits=settings.limits)
        self.telemetry = Telemetry()
        self.blackboard = Blackboard()
        self.assets = AssetGraph()
        self.exploration = ExplorationGraph()
        self.graphs = LinkedGraphs(self.assets, self.exploration)
        self.approvals = ApprovalQueue(
            auto_approve=self._auto_approve if settings.approve_mode == "auto" else None,
            path=Path(settings.artifacts_dir) / "approvals.json" if settings.artifacts_dir else None,
        )
        self.journal: Journal | NullJournal
        if settings.journal_path:
            self.journal = Journal(settings.journal_path)
        else:
            self.journal = NullJournal()
        self.policy = RiskPolicy(autonomy=settings.autonomy, exploit_enabled=settings.exploit)
        engine_cfg = dict(getattr(settings, "engine", {}) or {})
        try:
            if hasattr(self.context, "config") and getattr(self.context, "config", None) is not None:
                from candix.engine_bridge.config import BridgeConfig
                bc = BridgeConfig.from_config(self.context.config)
                engine_cfg = {"enabled": bc.enabled, "parallel": bc.parallel, "url": bc.url, "timeout": bc.timeout, "use_subprocess": bc.use_subprocess, "bridge_bin": bc.bridge_bin, "auto_start": bc.auto_start, **engine_cfg}
        except Exception:
            pass
        self.harness = Harness(
            targets=self.targets,
            settings=HarnessSettings(
                gate=settings.gate,
                allowed_prefixes=tuple(settings.allow_commands),
                max_risk=settings.gate_max_risk,
                allow_private=settings.allow_private,
                notify=dict(settings.notify_config),
                notify_min_severity=settings.notify_min_severity,
                poc=settings.poc,
                review=settings.review,
                todos=settings.todos,
                targeting=settings.targeting,
                artifacts=settings.artifacts_dir,
                engine=engine_cfg,
            ),
        )
        self.harness_summary: dict[str, Any] = {}
        self.tool_context = ToolContext(
            guard=guard,
            interceptor=self.harness,
            output_guard=OutputGuard(),
            budget=self.budget,
            telemetry=self.telemetry,
            journal=self.journal,
            artifacts=Path(settings.artifacts_dir) if settings.artifacts_dir else None,
        )
        self.tool_context.state.update(
            {
                "scan_context": context,
                "assets": self.assets,
                "facts": self.blackboard.facts,
                "blackboard": self.blackboard,
                "goal": settings.goal,
            }
        )
        self.verifier = Verifier(registry, self.tool_context)

    # ------------------------------------------------------------------
    @classmethod
    def create(
        cls,
        targets: Iterable[str],
        *,
        config: Any,
        engagement: Engagement | None = None,
        settings: AgentSettings | None = None,
        client: LLMClient | None = None,
        skills_dir: str = "",
        on_event: Callable[[str, dict[str, Any]], None] | None = None,
    ) -> "AgentSession":
        from candix.core.context import ScanContext

        settings = settings or AgentSettings()
        target_list = [str(target) for target in targets]
        context = ScanContext.create(target_list, config=config, engagement=engagement)
        guard = ScopeGuard(engagement=engagement, deny=DenyList(), red_lines=RedLines())
        registry = default_registry()
        session = cls(
            settings=settings,
            targets=target_list,
            context=context,
            guard=guard,
            registry=registry,
            client=client,
            skills=SkillRegistry.load(skills_dir or settings.skills_dir) if (skills_dir or settings.skills_dir) else SkillRegistry(),
            memory=MemoryStore(settings.memory_path) if settings.memory_path else MemoryStore(),
            on_event=on_event,
        )
        if context is not None and hasattr(context, "http"):
            session.tool_context.state["session"] = context.http
        session.tool_context.state["scan"] = context
        session.tool_context.state["engagement"] = engagement
        from candix.agent.scope_map import build_scope

        session.tool_context.state["scope_map"] = build_scope(target_list, resolve=False)
        return session

    # ------------------------------------------------------------------
    def _auto_approve(self, request: Any) -> bool:
        return request.risk <= self.policy.max_risk_approved

    def build_planner(self) -> Any:
        if getattr(self, "planner_factory", None) is not None:
            return self.planner_factory(self)
        base: Any = HeuristicPlanner()
        source = "heuristic"
        if self.settings.use_llm and self.client is not None:
            schemas = {tool.name: tool.parameters for tool in self.registry.tools.values()}
            base = LLMPlanner(self.client, tool_names=self.registry.names(), schemas=schemas, fallback=HeuristicPlanner())
            source = "llm"
        if self.settings.adaptive:
            base = self._with_adaptive(base)
            source = f"adaptive/{source}"
        if self.settings.playbook:
            source = f"playbook+{source}"
        self.tool_context.state["planner_source"] = source
        return self._with_playbook(base)

    def _with_adaptive(self, planner: Any) -> Any:
        from candix.agent.adaptive import AdaptiveConfig, AdaptiveController, AdaptivePlanner
        from candix.agent.learning import Learner

        existing = getattr(self, "_adaptive", None)
        if existing is not None:
            existing.fallback = planner
            return existing
        if getattr(self, "learner", None) is None:
            self.learner = Learner(
                path=self.settings.priors_path or None,
                targets=self.targets,
                enabled=bool(self.settings.use_priors),
            )
        controller = AdaptiveController(
            AdaptiveConfig(explore_ratio=float(self.settings.explore_ratio), strategy=self.settings.adaptive_strategy),
        )
        try:
            self.learner.seed_bandit(controller.bandit)
        except Exception:
            self.telemetry.increment("adaptive.prior_seed_failed")
        adaptive = AdaptivePlanner(planner, controller=controller)
        self._adaptive = adaptive
        self.tool_context.state["adaptive"] = controller
        return adaptive

    def _with_playbook(self, planner: Any) -> Any:
        if not self.settings.playbook:
            return planner
        from candix.agent.playbooks import PlaybookPlanner, default_registry, values_for

        registry = default_registry()
        try:
            playbook = registry.get(self.settings.playbook)
        except Exception as error:
            raise ValueError(f"{error}; available: {', '.join(registry.names())}") from error
        return PlaybookPlanner(
            playbook,
            planner,
            values=values_for(self.targets, goal=self.settings.goal),
            limit=self.settings.playbook_limit,
        )

    def _learn_from_run(self, result: TaskResult) -> None:
        learner = getattr(self, "learner", None)
        if learner is None or not getattr(learner, "enabled", False):
            return
        try:
            from candix.agent.insights import collect

            report = collect(result, self.telemetry, budget=self.budget)
            stats = [
                {"tool": stat.tool, "calls": stat.calls, "findings": stat.findings, "errors": stat.errors}
                for stat in getattr(report, "tools", [])
            ]
            outcomes = learner.outcomes(stats)
            if outcomes:
                learner.record_run(outcomes)
                learner.decay()
                learner.save()
        except Exception:
            self.telemetry.increment("adaptive.learn_failed")

    def _legacy_build_planner(self) -> Any:
        fallback = HeuristicPlanner()
        if not self.settings.use_llm or self.client is None:
            self.tool_context.state["planner_source"] = "heuristic"
            return fallback
        schemas = {tool.name: tool.parameters for tool in self.registry.tools.values()}
        self.tool_context.state["planner_source"] = "llm"
        return LLMPlanner(self.client, tool_names=self.registry.names(), schemas=schemas, fallback=fallback)

    def build_worker(self) -> Any:
        if getattr(self, "worker_factory", None) is not None:
            return self.worker_factory(self)
        if not self.settings.use_llm or self.client is None:
            return DeterministicWorker(self.registry)
        return LLMWorker(self.client, self.registry, max_steps=self.settings.worker_max_steps)

    # ------------------------------------------------------------------
    def goal(self) -> Goal:
        return Goal(
            statement=self.settings.goal,
            success_criteria=list(self.settings.success_criteria),
            targets=self.targets,
            constraints=[f"autonomy: {self.settings.autonomy.value}", f"exploit: {self.settings.exploit}"],
        )

    def run(self) -> TaskResult:
        goal = self.goal()
        if self.skills.skills:
            selected = self.skills.select(self.settings.goal, limit=2)
            if selected:
                self.blackboard.note(
                    "skills selected: " + ", ".join(skill.name for skill in selected), kind="skills"
                )
                self.tool_context.state["skills"] = [skill.to_dict() for skill in selected]
        loop = AgentLoop(
            goal=goal,
            planner=self.build_planner(),
            worker=self.build_worker(),
            context=self.tool_context,
            policy=self.policy,
            approvals=self.approvals,
            budget=self.budget,
            telemetry=self.telemetry,
            journal=self.journal,
            assets=self.assets,
            exploration=self.exploration,
            blackboard=self.blackboard,
            scheduler=IntentScheduler(),
            verifier=self.verifier,
            memory=self.memory,
            config=self.settings.loop_config(),
            on_event=self.on_event,
            run_id=self.id,
            harness=self.harness,
        )
        started = time.time()
        result = loop.run()
        result.finished_at = time.time()
        try:
            self.harness_summary = self.harness.finish(result, self)
        except Exception as error:  # the run's evidence matters more than its packaging
            self.harness_summary = {"error": f"{type(error).__name__}: {error}"}
            self.telemetry.increment("harness.finish_failed")
        self._learn_from_run(result)
        try:
            lessons = reflect(result, telemetry=self.telemetry, memory=self.memory, journal=self.journal)
            result.lessons = lessons
        except Exception:  # reflection is advisory; never fail the run on it
            result.lessons = []
        try:
            from candix.agent.scope_map import build_scope, directives_for, seed_assets, ScopeMap
            scope = self.tool_context.state.get("scope_map")
            if isinstance(scope, ScopeMap):
                seed_assets(scope, self.assets)
                self.tool_context.state["scope_directives"] = directives_for(scope)
        except Exception:
            pass
        self.budget.gauge = getattr(self.budget, "gauge", None)
        self.telemetry.gauge("run.seconds", time.time() - started)
        return result

    # ------------------------------------------------------------------
    def verify_findings(self, findings: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
        materialized = findings if findings is not None else [
            {"id": node.id, "title": node.label, "url": node.attributes.get("url"), "method": "GET"}
            for node in self.assets.of_kind("finding")
        ]
        return self.verifier.verify_all(materialized)

    def _scope_directives(self) -> list[str]:
        scope = self.tool_context.state.get("scope_map")
        if scope is None:
            return []
        try:
            from candix.agent.scope_map import directives_for

            return directives_for(scope)
        except Exception:
            return []

    def snapshot(self, result: TaskResult | None = None) -> dict[str, Any]:
        from candix.agent.triage import triage

        findings = list(result.findings) if result is not None else []
        payload: dict[str, Any] = {
            "id": self.id,
            "settings": self.settings.to_dict(),
            "targets": self.targets,
            "graphs": self.graphs.summary(),
            "assets": self.assets.to_dict(),
            "exploration": self.exploration.to_dict(),
            "anchors": list(self.graphs.anchors),
            "blackboard": self.blackboard.snapshot(),
            "policy": self.policy.describe(),
            "budget": self.budget.snapshot(),
            "telemetry": self.telemetry.snapshot(),
            "approvals": self.approvals.stats(),
            "journal": self.journal.summary(),
            "skills": self.skills.snapshot(),
            "memory": self.memory.snapshot(),
            "limiter": self.guard.snapshot(),
            "coverage": self.assets.coverage(),
            "technologies": [
                {"name": node.label, **(node.attributes or {})} for node in self.assets.of_kind("technology")
            ],
            "scope_directives": self._scope_directives(),
            "harness": self.harness_summary or self.harness.summary(),
            "engagement": dict(self.tool_context.state.get("engagement_summary") or {}),
        }
        adaptive = getattr(self, "_adaptive", None)
        if adaptive is not None:
            try:
                payload["adaptive"] = adaptive.report()
                payload["priors"] = self.learner.to_dict() if getattr(self, "learner", None) is not None else {}
            except Exception:
                payload["adaptive"] = {}
                payload["priors"] = {}
        if result is not None:
            payload["triage"] = triage(findings, assets=self.assets).to_dict()
            try:
                from candix.agent.compliance import evaluate
                from candix.agent.scorecard import from_result

                chain_count = 0
                from candix.agent.evidence_chain import build_chain

                chain_count = len(build_chain(result, self.assets).records)
                payload["scorecard"] = from_result(result, self.assets, evidence=chain_count).to_dict()
                payload["compliance"] = evaluate(findings).to_dict()
                from candix.agent.audit import from_session
                from candix.agent.insights import collect

                insight_report = collect(result, self.telemetry, budget=self.budget)
                from candix.agent.techniques import report as technique_report

                tools_used = [intent.tool for intent in result.intents if getattr(intent, "tool", "")]
                payload["insights"] = insight_report.to_dict()
                payload["audit"] = from_session(self).to_dict()
                payload["techniques"] = technique_report(tools_used, allow_exploit=bool(getattr(self.settings, "exploit", False))).to_dict()
            except Exception:
                payload["scorecard"] = {}
                payload["compliance"] = {}
                payload["insights"] = {}
                payload["audit"] = {}
                payload["techniques"] = {}
            try:
                from candix.agent.evidence_chain import build_chain

                payload["evidence_chain"] = build_chain(result, self.assets).bundle()
            except Exception:
                payload["evidence_chain"] = {}
            payload["errors"] = [error for error in (result.stop_reason,) if error.startswith("error")]
        return payload

    def save(self, path: str | Path, result: TaskResult | None = None) -> str:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(self.snapshot(result), indent=2, sort_keys=True), encoding="utf-8")
        return str(target)
