"""Hierarchical run budgets ported from engine/agent/budget.go.

Levels: task -> intent (one worker run) -> planner round.
Faithful to Go semantics, stdlib only, a la par with Go bridge.
"""

from __future__ import annotations

import contextvars
import math
import os
import threading
from dataclasses import dataclass, field


UNLIMITED: int = 2**63 - 1
BUDGET_MARGIN_PERCENT = 5
BUDGET_MARGIN_MIN_TOKENS = 20_000
BUDGET_MARGIN_MIN_TURNS = 2
DEFAULT_WORKER_ESTIMATE_TOKENS = 50_000
DEFAULT_WORKER_ESTIMATE_TURNS = 10

WORKER_BUDGET_WRAPUP = (
    "[Budget reached] This intent's token/turn budget is used up; the tool call was not executed. "
    "Do not run any more commands or probes. Write back what you identified but have not persisted yet "
    "(insert_assets, record_fact, report_finding), then, in a single standalone sentence of plain text, "
    "summarize what you did and your key conclusions."
)
PLANNER_BUDGET_WRAPUP = (
    "**The task's token/turn budget is exhausted and the task is about to end** (a normal end, not an error). "
    "Based on the current facts and findings, make the final goal judgment: call prove_goal for goals proven met "
    "by evidence. **Do not generate any new intents** (they will not be executed). Then, in a single standalone "
    "sentence of plain text, summarize where the task stands."
)

WRAPUP_ALLOWED_TOOLS = frozenset({"record_fact", "insert_assets", "report_finding", "update_finding_report", "record_coverage"})


def _cap(n: int) -> int:
    return UNLIMITED if n <= 0 else int(n)


@dataclass(frozen=True)
class Budget:
    tokens: int = UNLIMITED
    turns: int = UNLIMITED

    def remaining(self, spent: Spend) -> Budget:  # type: ignore[name-defined]
        return Budget(left(self.tokens, spent.tokens), left(self.turns, spent.turns))

    def to_dict(self) -> dict:
        return {"tokens": None if self.tokens == UNLIMITED else self.tokens,
                "turns": None if self.turns == UNLIMITED else self.turns}


@dataclass(frozen=True)
class Spend:
    tokens: int = 0
    turns: int = 0


def new_budget(tokens: int, turns: int) -> Budget:
    return Budget(_cap(tokens), _cap(turns))


def effective_budget(own: Budget, parent_remaining: Budget) -> Budget:
    return Budget(min(own.tokens, parent_remaining.tokens), min(own.turns, parent_remaining.turns))


def left(capacity: int, spent: int) -> int:
    if capacity == UNLIMITED:
        return UNLIMITED
    return max(capacity - spent, 0)


def wrapup_margin(task: Budget) -> Budget:
    def m(capacity: int, floor: int) -> int:
        if capacity == UNLIMITED:
            return 0
        return max(capacity * BUDGET_MARGIN_PERCENT // 100, floor)
    return Budget(m(task.tokens, BUDGET_MARGIN_MIN_TOKENS), m(task.turns, BUDGET_MARGIN_MIN_TURNS))


def budgets_from_env() -> tuple[Budget, Budget]:
    def env(k: str) -> int:
        try:
            return int(os.getenv(k, "").strip() or "0")
        except Exception:
            return 0
    return (
        new_budget(env("CANDIX_ENGINE_TASK_BUDGET_TOKENS"), env("CANDIX_ENGINE_TASK_BUDGET_TURNS")),
        new_budget(env("CANDIX_ENGINE_INTENT_BUDGET_TOKENS"), env("CANDIX_ENGINE_INTENT_BUDGET_TURNS")),
    )


@dataclass
class BudgetState:
    task: Budget
    remaining: Budget
    margin: Budget
    spent: Spend
    estimate: Spend
    at_margin: bool
    dispatch: bool

    def line(self) -> str:
        def of(rem: int, cap: int) -> str:
            if cap == UNLIMITED:
                return "unlimited"
            return f"{rem} of {cap}"
        return (
            f"[Task budget] remaining: tokens {of(self.remaining.tokens, self.task.tokens)}, "
            f"turns {of(self.remaining.turns, self.task.turns)} "
            f"(wrap-up reserve: {self.margin.tokens} tokens, {self.margin.turns} turns)"
        )

    def to_dict(self) -> dict:
        return {
            "task": self.task.to_dict(),
            "remaining": self.remaining.to_dict(),
            "margin": self.margin.to_dict(),
            "spent": {"tokens": self.spent.tokens, "turns": self.spent.turns},
            "estimate": {"tokens": self.estimate.tokens, "turns": self.estimate.turns},
            "at_margin": self.at_margin,
            "dispatch": self.dispatch,
            "line": self.line(),
        }


class BudgetLedger:
    """Meters one task, in memory (process restart starts afresh)."""

    def __init__(self, task: Budget, intent: Budget) -> None:
        self.task = task
        self.intent = intent
        self._mu = threading.Lock()
        self.spent = Spend()
        self.worker_runs = 0
        self.worker_spent = Spend()
        self.wrapup = False

    @classmethod
    def new(cls, task: Budget, intent: Budget) -> BudgetLedger | None:
        if task == new_budget(0, 0) and intent == new_budget(0, 0):
            return None
        return cls(task, intent)

    @classmethod
    def from_env(cls) -> BudgetLedger | None:
        task, intent = budgets_from_env()
        return cls.new(task, intent)

    def record(self, *, tokens: int = 0, turns: int = 1) -> None:
        with self._mu:
            self.spent = Spend(self.spent.tokens + tokens, self.spent.turns + turns)

    def record_usage(self, input_tokens: int = 0, output_tokens: int = 0) -> None:
        self.record(tokens=input_tokens + output_tokens, turns=1)

    def state(self) -> BudgetState:
        with self._mu:
            rem = self.task.remaining(self.spent)
            m = wrapup_margin(self.task)
            est = Spend(DEFAULT_WORKER_ESTIMATE_TOKENS, DEFAULT_WORKER_ESTIMATE_TURNS)
            if self.worker_runs > 0:
                est = Spend(self.worker_spent.tokens // self.worker_runs, self.worker_spent.turns // self.worker_runs)
            est = Spend(min(est.tokens, self.intent.tokens), min(est.turns, self.intent.turns))
            at = (rem.tokens != UNLIMITED and rem.tokens <= m.tokens) or (rem.turns != UNLIMITED and rem.turns <= m.turns)
            dispatch = not self.wrapup and not at and rem.tokens >= est.tokens and rem.turns >= est.turns
            return BudgetState(task=self.task, remaining=rem, margin=m, spent=Spend(self.spent.tokens, self.spent.turns),
                               estimate=est, at_margin=at, dispatch=dispatch)

    def begin_wrapup(self) -> bool:
        with self._mu:
            first = not self.wrapup
            self.wrapup = True
            return first

    def start_intent(self) -> IntentMeter:  # type: ignore[name-defined]
        return IntentMeter(ledger=self)


class IntentMeter:
    """Meters one worker run against min(intent budget, task remaining above reserve)."""

    def __init__(self, ledger: BudgetLedger) -> None:
        self._ledger = ledger
        self.spent = Spend()

    def record(self, *, tokens: int = 0, turns: int = 1) -> None:
        with self._ledger._mu:
            self.spent = Spend(self.spent.tokens + tokens, self.spent.turns + turns)
            self._ledger.spent = Spend(self._ledger.spent.tokens + tokens, self._ledger.spent.turns + turns)

    def record_usage(self, input_tokens: int = 0, output_tokens: int = 0) -> None:
        self.record(tokens=input_tokens + output_tokens, turns=1)

    def remaining(self) -> Budget:
        l = self._ledger
        with l._mu:
            parent = Budget(0, 0)
            if not l.wrapup:
                rem = l.task.remaining(l.spent)
                res = wrapup_margin(l.task)
                parent = Budget(left(rem.tokens, res.tokens), left(rem.turns, res.turns))
            return effective_budget(l.intent.remaining(self.spent), parent)

    def exhausted(self) -> bool:
        r = self.remaining()
        return r.tokens == 0 or r.turns == 0

    def finish(self) -> None:
        with self._ledger._mu:
            self._ledger.worker_runs += 1
            self._ledger.worker_spent = Spend(
                self._ledger.worker_spent.tokens + self.spent.tokens,
                self._ledger.worker_spent.turns + self.spent.turns,
            )


def budget_wrapup_blocks(tool: str) -> bool:
    return tool not in WRAPUP_ALLOWED_TOOLS


# Context propagation (mirrors Go BudgetRound / IntentMeter on context)
_budget_round_var: contextvars.ContextVar = contextvars.ContextVar("candix_budget_round", default=None)
_intent_meter_var: contextvars.ContextVar = contextvars.ContextVar("candix_intent_meter", default=None)


@dataclass(frozen=True)
class BudgetRound:
    line: str = ""
    wrap_up: bool = False


def with_budget_round(round: BudgetRound) -> contextvars.Token:
    return _budget_round_var.set(round)


def current_budget_round() -> BudgetRound | None:
    return _budget_round_var.get()


def with_intent_meter(meter: IntentMeter) -> contextvars.Token:
    return _intent_meter_var.set(meter)


def current_intent_meter() -> IntentMeter | None:
    return _intent_meter_var.get()


def planner_budget_block() -> str:
    r = _budget_round_var.get()
    if r is None:
        return ""
    s = ""
    if r.line:
        s += "\n\n" + r.line
    if r.wrap_up:
        s += "\n\n[Task budget wrap-up (special instruction for this round, overriding the normal planning flow above)]: " + PLANNER_BUDGET_WRAPUP
    return s


def turn_cap(default_max_turns: int) -> int:
    m = _intent_meter_var.get()
    if m is None:
        return default_max_turns
    rem = m.remaining().turns
    if rem == UNLIMITED:
        return default_max_turns
    c = int(max(rem, 1))
    if default_max_turns <= 0 or c < default_max_turns:
        return c
    return default_max_turns
