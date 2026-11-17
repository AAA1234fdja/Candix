"""Autonomous layer: goals, plans, workers, tools and the run journal.

The package is deliberately model-optional. Everything that decides what may
happen - scope, deny-lists, red lines, budgets, approvals - works with no model
at all; the model layer adds better planning, not permission.
"""

from candix.agent.approvals import ApprovalQueue, ApprovalRequest, ApprovalStatus
from candix.agent.blackboard import Blackboard, Todo
from candix.agent.budget import AgentBudget, BudgetLimits
from candix.agent.facts import Confidence, Fact, FactSource, FactStore
from candix.agent.graph import AssetGraph, EdgeKind, ExplorationGraph, LinkedGraphs, NodeKind
from candix.agent.guard import DenyList, OutputGuard, RedLines, SafetyDecision, ScopeBlocked, ScopeGuard
from candix.agent.journal import Journal, JournalEntry, NullJournal
from candix.agent.loop import AgentLoop, LoopConfig, LoopEvent
from candix.agent.memory import Lesson, MemoryStore
from candix.agent.models import Decision, Goal, Intent, IntentStatus, Observation, Phase, Step, TaskResult
from candix.agent.planner import HeuristicPlanner, LLMPlanner, PlannerState
from candix.agent.policy import AutonomyLevel, RiskPolicy
from candix.agent.reflection import derive_lessons, reflect
from candix.agent.reporting import render_json, render_markdown, summary_line
from candix.agent.scheduler import IntentScheduler
from candix.agent.session import AgentSession, AgentSettings
from candix.agent.skills import Skill, SkillError, SkillRegistry, load_skill
from candix.agent.telemetry import Telemetry
from candix.agent.toolset import default_registry
from candix.agent.tools import Tool, ToolContext, ToolError, ToolRegistry, ToolResult
from candix.agent.verifier import VerificationResult, Verifier
from candix.agent.worker import DeterministicWorker, LLMWorker, WorkerResult

__all__ = [
    "AgentBudget",
    "AgentLoop",
    "AgentSession",
    "AgentSettings",
    "ApprovalQueue",
    "ApprovalRequest",
    "ApprovalStatus",
    "AssetGraph",
    "AutonomyLevel",
    "Blackboard",
    "BudgetLimits",
    "Confidence",
    "Decision",
    "DenyList",
    "DeterministicWorker",
    "EdgeKind",
    "ExplorationGraph",
    "Fact",
    "FactSource",
    "FactStore",
    "Goal",
    "HeuristicPlanner",
    "Intent",
    "IntentScheduler",
    "IntentStatus",
    "Journal",
    "JournalEntry",
    "LLMPlanner",
    "LLMWorker",
    "Lesson",
    "LinkedGraphs",
    "LoopConfig",
    "LoopEvent",
    "MemoryStore",
    "NodeKind",
    "NullJournal",
    "Observation",
    "OutputGuard",
    "Phase",
    "PlannerState",
    "RedLines",
    "RiskPolicy",
    "SafetyDecision",
    "ScopeBlocked",
    "ScopeGuard",
    "Skill",
    "SkillError",
    "SkillRegistry",
    "Step",
    "TaskResult",
    "Telemetry",
    "Todo",
    "Tool",
    "ToolContext",
    "ToolError",
    "ToolRegistry",
    "ToolResult",
    "VerificationResult",
    "Verifier",
    "WorkerResult",
    "default_registry",
    "derive_lessons",
    "load_skill",
    "reflect",
    "render_json",
    "render_markdown",
    "summary_line",
]
