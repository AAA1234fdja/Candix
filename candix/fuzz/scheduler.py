"""Adaptive scheduling of mutation families.

The scheduler is a small epsilon-greedy bandit: every family keeps a running
average reward, and families that keep producing anomalies are chosen more
often. It keeps the fuzzer useful on long runs without any ML dependency.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Iterable

from candix.fuzz.mutators import FAMILIES, STRATEGY_WEIGHTS


@dataclass
class Arm:
    family: str
    weight: float
    pulls: int = 0
    reward: float = 0.0
    best: float = 0.0

    @property
    def average(self) -> float:
        return self.reward / self.pulls if self.pulls else 0.0

    @property
    def priority(self) -> float:
        exploration = 0.35 / (1.0 + self.pulls) ** 0.5
        return self.average + exploration + self.weight * 0.2

    def to_dict(self) -> dict[str, float | int | str]:
        return {
            "family": self.family,
            "weight": round(self.weight, 3),
            "pulls": self.pulls,
            "average_reward": round(self.average, 3),
            "best": round(self.best, 3),
            "priority": round(self.priority, 3),
        }


@dataclass
class Scheduler:
    strategy: str = "balanced"
    epsilon: float = 0.15
    rng: random.Random = field(default_factory=lambda: random.Random(0))
    arms: dict[str, Arm] = field(default_factory=dict)
    history: list[dict[str, float | str]] = field(default_factory=list)

    def __post_init__(self) -> None:
        weights = STRATEGY_WEIGHTS.get(self.strategy, STRATEGY_WEIGHTS["balanced"])
        self.arms = {
            family: Arm(family=family, weight=float(weights.get(family, 0.05))) for family in FAMILIES
        }

    def pick(self) -> str:
        if self.rng.random() < self.epsilon:
            families = list(self.arms)
            return self.rng.choice(families)
        return max(self.arms.values(), key=lambda arm: arm.priority).family

    def reward(self, family: str, value: float) -> None:
        arm = self.arms.get(family)
        if arm is None:
            return
        arm.pulls += 1
        arm.reward += max(0.0, min(1.0, value))
        arm.best = max(arm.best, value)
        if value >= 0.5:
            self.history.append({"family": family, "reward": round(value, 3), "pull": arm.pulls})

    def penalise(self, family: str) -> None:
        arm = self.arms.get(family)
        if arm is not None:
            arm.pulls += 1

    def snapshot(self) -> list[dict[str, float | int | str]]:
        return [arm.to_dict() for arm in sorted(self.arms.values(), key=lambda item: -item.priority)]

    def best_families(self, count: int = 3) -> list[str]:
        ordered = sorted(self.arms.values(), key=lambda arm: -arm.average)
        return [arm.family for arm in ordered[:count] if arm.pulls]

    def stats(self) -> dict[str, object]:
        return {
            "strategy": self.strategy,
            "arms": self.snapshot(),
            "notable": list(self.history[-20:]),
        }


class DeterministicSampler:
    """Ordering helper that keeps runs reproducible for a given seed."""

    def __init__(self, items: Iterable[str], *, seed: int = 0) -> None:
        self._items = list(items)
        self._rng = random.Random(seed)
        self._cursor = 0

    def next(self) -> str:
        if not self._items:
            raise StopIteration("sampler is empty")
        if self._cursor >= len(self._items):
            self._rng.shuffle(self._items)
            self._cursor = 0
        item = self._items[self._cursor]
        self._cursor += 1
        return item

    def peek(self) -> str | None:
        return self._items[self._cursor] if self._items else None
