"""Token, request and cost accounting for every model call."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Iterable

from candix.llm.errors import BudgetExhausted
from candix.llm.types import ModelInfo, Usage


@dataclass
class UsageRecord:
    task: str
    provider: str
    model: str
    usage: Usage
    cost: float
    at: float = field(default_factory=time.time)
    cached: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "task": self.task,
            "provider": self.provider,
            "model": self.model,
            "usage": self.usage.to_dict(),
            "cost_usd": round(self.cost, 6),
            "cached": self.cached,
            "at": round(self.at, 3),
        }


@dataclass
class LedgerLimits:
    max_total_tokens: int = 0
    max_prompt_tokens: int = 0
    max_requests: int = 0
    max_cost_usd: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "max_total_tokens": self.max_total_tokens,
            "max_prompt_tokens": self.max_prompt_tokens,
            "max_requests": self.max_requests,
            "max_cost_usd": self.max_cost_usd,
        }


class UsageLedger:
    """Aggregates usage and enforces spend limits before each call is made."""

    def __init__(self, limits: LedgerLimits | None = None, *, prices: dict[str, ModelInfo] | None = None) -> None:
        self.limits = limits or LedgerLimits()
        self.prices = dict(prices or {})
        self.records: list[UsageRecord] = []
        self.started = time.time()

    # ------------------------------------------------------------------
    def price_for(self, model: str) -> ModelInfo | None:
        if model in self.prices:
            return self.prices[model]
        for name, info in self.prices.items():
            if model.startswith(name):
                return info
        return None

    def cost_for(self, model: str, usage: Usage) -> float:
        info = self.price_for(model)
        return info.cost(usage) if info else 0.0

    def record(self, *, task: str, provider: str, model: str, usage: Usage, cached: bool = False) -> UsageRecord:
        record = UsageRecord(task=task, provider=provider, model=model, usage=usage, cost=self.cost_for(model, usage), cached=cached)
        self.records.append(record)
        return record

    # ------------------------------------------------------------------
    @property
    def totals(self) -> Usage:
        total = Usage()
        for record in self.records:
            total = total.add(record.usage)
        return total

    @property
    def cost(self) -> float:
        return sum(record.cost for record in self.records)

    @property
    def requests(self) -> int:
        return sum(1 for record in self.records if not record.cached)

    def guard(self, *, prompt_tokens: int = 0) -> None:
        """Raise before a call that would exceed a configured limit."""

        totals = self.totals
        limits = self.limits
        if limits.max_requests and self.requests + 1 > limits.max_requests:
            raise BudgetExhausted(f"request budget exhausted ({limits.max_requests})")
        if limits.max_prompt_tokens and prompt_tokens > limits.max_prompt_tokens:
            raise BudgetExhausted(
                f"prompt of {prompt_tokens} tokens exceeds the per-request limit of {limits.max_prompt_tokens}"
            )
        if limits.max_total_tokens and totals.total_tokens >= limits.max_total_tokens:
            raise BudgetExhausted(f"token budget exhausted ({totals.total_tokens}/{limits.max_total_tokens})")
        if limits.max_cost_usd and self.cost >= limits.max_cost_usd:
            raise BudgetExhausted(f"cost budget exhausted (${self.cost:.4f}/${limits.max_cost_usd:.2f})")

    def would_exceed(self, *, prompt_tokens: int = 0) -> bool:
        try:
            self.guard(prompt_tokens=prompt_tokens)
        except BudgetExhausted:
            return True
        return False

    # ------------------------------------------------------------------
    def by_model(self) -> dict[str, dict[str, Any]]:
        grouped: dict[str, dict[str, Any]] = {}
        for record in self.records:
            entry = grouped.setdefault(
                record.model or record.provider,
                {"requests": 0, "prompt_tokens": 0, "completion_tokens": 0, "cost_usd": 0.0},
            )
            entry["requests"] += 1
            entry["prompt_tokens"] += record.usage.prompt_tokens
            entry["completion_tokens"] += record.usage.completion_tokens
            entry["cost_usd"] = round(entry["cost_usd"] + record.cost, 6)
        return grouped

    def by_task(self) -> dict[str, int]:
        grouped: dict[str, int] = {}
        for record in self.records:
            grouped[record.task] = grouped.get(record.task, 0) + record.usage.total_tokens
        return grouped

    def snapshot(self) -> dict[str, Any]:
        totals = self.totals
        return {
            "requests": self.requests,
            "cached": sum(1 for record in self.records if record.cached),
            "prompt_tokens": totals.prompt_tokens,
            "completion_tokens": totals.completion_tokens,
            "total_tokens": totals.total_tokens,
            "cost_usd": round(self.cost, 6),
            "elapsed": round(time.time() - self.started, 2),
            "limits": self.limits.to_dict(),
            "by_model": self.by_model(),
            "by_task": self.by_task(),
        }

    def rows(self) -> list[tuple[str, str]]:
        snapshot = self.snapshot()
        return [
            ("requests", str(snapshot["requests"])),
            ("cached", str(snapshot["cached"])),
            ("prompt tokens", str(snapshot["prompt_tokens"])),
            ("completion tokens", str(snapshot["completion_tokens"])),
            ("total tokens", str(snapshot["total_tokens"])),
            ("cost (usd)", f"${snapshot['cost_usd']:.4f}"),
        ]

    def extend(self, records: Iterable[UsageRecord]) -> None:
        self.records.extend(records)

    def reset(self) -> None:
        self.records.clear()
        self.started = time.time()
