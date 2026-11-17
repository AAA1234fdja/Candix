"""Baseline collection and stability analysis.

Every active detector compares an attack response against a baseline. A single
baseline is noisy on dynamic pages, so Candix samples the endpoint a few times,
learns which parts of the response are stable, and only reports a difference
that exceeds the observed natural variation.
"""

from __future__ import annotations

import statistics
import time
from dataclasses import dataclass, field
from typing import Any, Iterable

from candix.analysis.diff import normalize, similarity, stable_hash
from candix.net.http import Response


@dataclass
class Baseline:
    """Observed normal behaviour for a request."""

    responses: list[Response] = field(default_factory=list)
    requested: int = 1
    stable_hash: str = ""
    lengths: list[int] = field(default_factory=list)
    timings: list[float] = field(default_factory=list)
    statuses: list[int] = field(default_factory=list)
    body: str = ""
    unstable: bool = False
    variability: float = 0.0

    @classmethod
    def build(cls, responses: Iterable[Response]) -> "Baseline":
        items = [response for response in responses if response is not None]
        baseline = cls(responses=items, requested=len(items))
        if not items:
            return baseline
        baseline.lengths = [response.size for response in items]
        baseline.timings = [response.elapsed for response in items]
        baseline.statuses = [response.status for response in items]
        baseline.body = items[-1].text
        baseline.stable_hash = stable_hash(items[-1])
        if len(items) > 1:
            reference = items[0]
            similarities = [similarity(reference.text, item.text) for item in items[1:]]
            baseline.variability = 1.0 - (sum(similarities) / len(similarities)) if similarities else 0.0
            baseline.unstable = baseline.variability > 0.08 or len(set(baseline.statuses)) > 1
        return baseline

    @property
    def status(self) -> int:
        return self.statuses[-1] if self.statuses else 0

    @property
    def length(self) -> int:
        return self.lengths[-1] if self.lengths else 0

    @property
    def elapsed(self) -> float:
        return statistics.median(self.timings) if self.timings else 0.0

    @property
    def length_range(self) -> tuple[int, int]:
        if not self.lengths:
            return (0, 0)
        return (min(self.lengths), max(self.lengths))

    def length_tolerance(self, *, floor: int = 24, ratio: float = 0.03) -> int:
        if len(self.lengths) < 2:
            return floor
        spread = statistics.pstdev(self.lengths) * 3
        return int(max(floor, ratio * (sum(self.lengths) / len(self.lengths)), spread))

    def time_tolerance(self, *, floor: float = 0.6, sigma: float = 3.0) -> float:
        if len(self.timings) < 2:
            return floor
        return max(floor, statistics.pstdev(self.timings) * sigma, statistics.mean(self.timings) * 0.35)

    def matches_length(self, response: Response) -> bool:
        low, high = self.length_range
        tolerance = self.length_tolerance()
        return (low - tolerance) <= response.size <= (high + tolerance)

    def is_timing_outlier(self, response: Response) -> bool:
        return response.elapsed > self.elapsed + self.time_tolerance()

    def changed(self, response: Response) -> bool:
        if response.status != self.status:
            return True
        if not self.matches_length(response):
            return True
        return stable_hash(response) != self.stable_hash and similarity(self.body, response.text) < 0.9

    def summary(self) -> dict[str, Any]:
        return {
            "samples": len(self.responses),
            "status": self.status,
            "length": self.length,
            "length_range": self.length_range,
            "median_time": round(self.elapsed, 3),
            "variability": round(self.variability, 4),
            "unstable": self.unstable,
        }


class BaselineCollector:
    """Collects and caches baselines per URL/method/parameter combination."""

    def __init__(self, http: Any, *, samples: int = 2, max_cache: int = 500) -> None:
        self.http = http
        self.samples = max(1, samples)
        self.max_cache = max_cache
        self._cache: dict[str, Baseline] = {}

    def _key(self, url: str, method: str, param: str | None, data: str | None) -> str:
        return f"{method.upper()}|{url}|{param or ''}|{(data or '')[:200]}"

    def collect(
        self,
        url: str,
        *,
        method: str = "GET",
        param: str | None = None,
        data: str | None = None,
        headers: dict[str, str] | None = None,
        samples: int | None = None,
    ) -> Baseline:
        key = self._key(url, method, param, data)
        cached = self._cache.get(key)
        if cached is not None:
            return cached
        count = samples or self.samples
        responses: list[Response] = []
        for index in range(count):
            response = self.http.probe(
                url,
                method=method,
                param=param,
                value=None,
                data=data,
                headers=headers,
                tag=f"baseline-{index}",
            )
            responses.append(response)
        baseline = Baseline.build(responses)
        if len(self._cache) >= self.max_cache:
            self._cache.pop(next(iter(self._cache)), None)
        self._cache[key] = baseline
        return baseline

    def invalidate(self, url: str | None = None) -> None:
        if url is None:
            self._cache.clear()
            return
        for key in [key for key in self._cache if url in key]:
            self._cache.pop(key, None)

    @property
    def size(self) -> int:
        return len(self._cache)


def stable_portion(responses: Iterable[Response]) -> str:
    """Return lines that appear in every response (a crude stable template)."""

    bodies = [normalize(response.text).splitlines() for response in responses]
    if not bodies:
        return ""
    common = set(bodies[0])
    for lines in bodies[1:]:
        common &= set(lines)
    return "\n".join(line for line in bodies[0] if line in common)


def measure_latency(http: Any, url: str, samples: int = 3) -> float:
    values: list[float] = []
    for _ in range(samples):
        started = time.monotonic()
        http.get(url)
        values.append(time.monotonic() - started)
    return statistics.median(values) if values else 0.0
