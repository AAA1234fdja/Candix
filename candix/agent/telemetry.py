"""Counters, gauges and timers for one agent run."""

from __future__ import annotations

import time
from collections import defaultdict
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Iterator


@dataclass
class Timer:
    name: str
    started: float = field(default_factory=time.monotonic)
    finished: float = 0.0

    @property
    def duration(self) -> float:
        return (self.finished or time.monotonic()) - self.started

    def stop(self) -> float:
        self.finished = time.monotonic()
        return self.duration


class Telemetry:
    """Additive metrics with a fixed, printable surface.

    The run report and the TUI read the same snapshot, so a number shown live is
    the number that ends up in the artefact.
    """

    def __init__(self) -> None:
        self.counters: dict[str, int] = defaultdict(int)
        self.gauges: dict[str, float] = {}
        self.durations: dict[str, list[float]] = defaultdict(list)
        self.errors: dict[str, int] = defaultdict(int)

    # ------------------------------------------------------------------
    def increment(self, name: str, value: int = 1) -> None:
        self.counters[name] += value

    def gauge(self, name: str, value: float) -> None:
        self.gauges[name] = value

    def observe(self, name: str, value: float) -> None:
        self.durations[name].append(value)

    def error(self, name: str, detail: str = "") -> None:
        key = f"{name}: {detail[:60]}" if detail else name
        self.errors[key] += 1

    @contextmanager
    def timer(self, name: str) -> Iterator[Timer]:
        timer = Timer(name)
        try:
            yield timer
        finally:
            self.observe(name, timer.stop())

    # ------------------------------------------------------------------
    def summary(self, name: str) -> dict[str, float]:
        values = self.durations.get(name) or []
        if not values:
            return {"count": 0, "total": 0.0, "avg": 0.0, "max": 0.0, "p95": 0.0}
        ordered = sorted(values)
        index = min(len(ordered) - 1, int(round(0.95 * (len(ordered) - 1))))
        return {
            "count": float(len(ordered)),
            "total": round(sum(ordered), 3),
            "avg": round(sum(ordered) / len(ordered), 3),
            "max": round(ordered[-1], 3),
            "p95": round(ordered[index], 3),
        }

    def snapshot(self) -> dict[str, Any]:
        return {
            "counters": dict(sorted(self.counters.items())),
            "gauges": {name: round(value, 3) for name, value in sorted(self.gauges.items())},
            "durations": {name: self.summary(name) for name in sorted(self.durations)},
            "errors": dict(sorted(self.errors.items())),
        }

    def rows(self, limit: int = 10) -> list[tuple[str, str]]:
        rows = [(name, str(value)) for name, value in sorted(self.counters.items())][:limit]
        rows.extend((f"{name}.p95", f"{self.summary(name)['p95']:.2f}s") for name in sorted(self.durations)[:limit])
        return rows

    def merge(self, other: "Telemetry") -> None:
        for name, value in other.counters.items():
            self.counters[name] += value
        for name, values in other.durations.items():
            self.durations[name].extend(values)
        for name, detail in other.errors.items():
            self.errors[name] += detail
        self.gauges.update(other.gauges)
