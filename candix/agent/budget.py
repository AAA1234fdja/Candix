"""Run budgets: turns, tool calls, tokens, wall clock, money and intents."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from candix.llm.errors import BudgetExhausted


@dataclass
class BudgetLimits:
    turns: int = 12
    tool_calls: int = 60
    tokens: int = 200_000
    seconds: float = 900.0
    cost_usd: float = 0.0
    intents: int = 40
    consecutive_failures: int = 4

    def to_dict(self) -> dict[str, Any]:
        return {
            "turns": self.turns,
            "tool_calls": self.tool_calls,
            "tokens": self.tokens,
            "seconds": self.seconds,
            "cost_usd": self.cost_usd,
            "intents": self.intents,
            "consecutive_failures": self.consecutive_failures,
        }


@dataclass
class AgentBudget:
    """Tracks spend and refuses the next unit of work when a limit is reached."""

    limits: BudgetLimits = field(default_factory=BudgetLimits)
    turns: int = 0
    tool_calls: int = 0
    tokens: int = 0
    intents: int = 0
    cost_usd: float = 0.0
    consecutive_failures: int = 0
    started: float = field(default_factory=time.monotonic)
    stopped_reason: str = ""

    # ------------------------------------------------------------------
    @property
    def elapsed(self) -> float:
        return time.monotonic() - self.started

    @property
    def remaining_seconds(self) -> float:
        if not self.limits.seconds:
            return float("inf")
        return max(0.0, self.limits.seconds - self.elapsed)

    @property
    def remaining_tokens(self) -> int:
        if not self.limits.tokens:
            return 2**31
        return max(0, self.limits.tokens - self.tokens)

    @property
    def remaining_turns(self) -> int:
        if not self.limits.turns:
            return 2**31
        return max(0, self.limits.turns - self.turns)

    # ------------------------------------------------------------------
    def _fail(self, reason: str) -> None:
        self.stopped_reason = reason
        raise BudgetExhausted(reason)

    def start_turn(self) -> None:
        if self.limits.turns and self.turns >= self.limits.turns:
            self._fail(f"turn budget exhausted ({self.limits.turns})")
        if self.limits.seconds and self.elapsed >= self.limits.seconds:
            self._fail(f"time budget exhausted ({self.limits.seconds:.0f}s)")
        if self.limits.cost_usd and self.cost_usd >= self.limits.cost_usd:
            self._fail(f"cost budget exhausted (${self.cost_usd:.4f})")
        if self.limits.tokens and self.tokens >= self.limits.tokens:
            self._fail(f"token budget exhausted ({self.tokens})")
        if self.limits.consecutive_failures and self.consecutive_failures >= self.limits.consecutive_failures:
            self._fail(f"{self.consecutive_failures} consecutive intent failures")
        self.turns += 1

    def spend_tool_call(self, *, tokens: int = 0, cost: float = 0.0) -> None:
        if self.limits.tool_calls and self.tool_calls >= self.limits.tool_calls:
            self._fail(f"tool-call budget exhausted ({self.limits.tool_calls})")
        self.tool_calls += 1
        self.tokens += max(0, tokens)
        self.cost_usd += max(0.0, cost)
        if self.limits.tokens and self.tokens > self.limits.tokens:
            self._fail(f"token budget exhausted ({self.tokens})")
        if self.limits.cost_usd and self.cost_usd > self.limits.cost_usd:
            self._fail(f"cost budget exhausted (${self.cost_usd:.4f})")

    def spend_intent(self) -> None:
        if self.limits.intents and self.intents >= self.limits.intents:
            self._fail(f"intent budget exhausted ({self.limits.intents})")
        self.intents += 1

    def record_outcome(self, ok: bool) -> None:
        self.consecutive_failures = 0 if ok else self.consecutive_failures + 1

    # ------------------------------------------------------------------
    def exhausted(self) -> str:
        """Return the reason the budget is spent, or an empty string."""

        if self.limits.turns and self.turns >= self.limits.turns:
            return "turns"
        if self.limits.tool_calls and self.tool_calls >= self.limits.tool_calls:
            return "tool_calls"
        if self.limits.tokens and self.tokens >= self.limits.tokens:
            return "tokens"
        if self.limits.seconds and self.elapsed >= self.limits.seconds:
            return "seconds"
        if self.limits.cost_usd and self.cost_usd >= self.limits.cost_usd:
            return "cost"
        if self.limits.intents and self.intents >= self.limits.intents:
            return "intents"
        if self.limits.consecutive_failures and self.consecutive_failures >= self.limits.consecutive_failures:
            return "failures"
        return ""

    def snapshot(self) -> dict[str, Any]:
        return {
            "turns": self.turns,
            "tool_calls": self.tool_calls,
            "tokens": self.tokens,
            "intents": self.intents,
            "cost_usd": round(self.cost_usd, 6),
            "elapsed": round(self.elapsed, 2),
            "limits": self.limits.to_dict(),
            "remaining": {
                "turns": self.remaining_turns,
                "tokens": self.remaining_tokens,
                "seconds": None if self.remaining_seconds == float("inf") else round(self.remaining_seconds, 1),
            },
            "exhausted": self.exhausted(),
            "stopped_reason": self.stopped_reason,
        }

    def rows(self) -> list[tuple[str, str]]:
        snapshot = self.snapshot()
        return [
            ("turns", f"{snapshot['turns']}/{self.limits.turns}"),
            ("tool calls", f"{snapshot['tool_calls']}/{self.limits.tool_calls}"),
            ("tokens", f"{snapshot['tokens']}/{self.limits.tokens}"),
            ("elapsed", f"{snapshot['elapsed']:.1f}s"),
            ("cost", f"${snapshot['cost_usd']:.4f}"),
        ]
