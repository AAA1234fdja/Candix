"""Statistical helpers for timing, length and token anomalies.

Blind injection detection needs a defensible threshold: comparing a 2.1s
response against a 0.2s baseline is only meaningful if the baseline is stable.
These helpers implement median absolute deviation and robust z-scores so a
single slow sample does not create a finding.
"""

from __future__ import annotations

import math
import statistics
from dataclasses import dataclass, field
from typing import Iterable, Sequence


def mean(values: Sequence[float]) -> float:
    return statistics.fmean(values) if values else 0.0


def median(values: Sequence[float]) -> float:
    return statistics.median(values) if values else 0.0


def stdev(values: Sequence[float]) -> float:
    return statistics.pstdev(values) if len(values) > 1 else 0.0


def mad(values: Sequence[float]) -> float:
    if not values:
        return 0.0
    centre = statistics.median(values)
    return statistics.median([abs(value - centre) for value in values])


def robust_z(value: float, sample: Sequence[float]) -> float:
    centre = median(sample)
    deviation = mad(sample)
    if deviation == 0:
        spread = stdev(sample)
        if spread == 0:
            return 0.0 if value == centre else float("inf")
        return (value - centre) / spread
    return 0.6745 * (value - centre) / deviation


def percentile(values: Sequence[float], fraction: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, int(round(fraction * (len(ordered) - 1)))))
    return ordered[index]


@dataclass
class TimingProfile:
    samples: list[float] = field(default_factory=list)
    threshold_sigma: float = 5.0
    minimum_delay: float = 0.8

    def add(self, elapsed: float) -> None:
        self.samples.append(max(0.0, elapsed))

    @property
    def base(self) -> float:
        return median(self.samples)

    @property
    def spread(self) -> float:
        return max(mad(self.samples), stdev(self.samples))

    def is_delayed(self, elapsed: float, *, expected_delay: float = 0.0) -> bool:
        floor = max(self.minimum_delay, expected_delay * 0.6)
        excess = elapsed - self.base
        if excess < floor:
            return False
        if len(self.samples) < 3:
            return True
        z = robust_z(elapsed, self.samples)
        return z >= self.threshold_sigma or excess >= max(floor, self.base * 0.8)

    def summary(self) -> dict[str, float]:
        return {
            "samples": float(len(self.samples)),
            "median": round(self.base, 4),
            "mad": round(mad(self.samples), 4),
            "p95": round(percentile(self.samples, 0.95), 4),
        }


@dataclass
class LengthProfile:
    samples: list[int] = field(default_factory=list)

    def add(self, length: int) -> None:
        self.samples.append(int(length))

    @property
    def base(self) -> float:
        return median([float(item) for item in self.samples])

    def deviation(self, length: int) -> float:
        base = self.base
        if base == 0:
            return 1.0 if length else 0.0
        return abs(length - base) / base

    def is_anomalous(self, length: int, *, threshold: float = 0.06) -> bool:
        spread = max(16.0, stdev([float(item) for item in self.samples]) * 3)
        if abs(length - self.base) <= spread:
            return False
        return self.deviation(length) >= threshold


def is_outlier(value: float, sample: Iterable[float], *, threshold: float = 4.0) -> bool:
    values = list(sample)
    if len(values) < 3:
        return False
    return robust_z(value, values) >= threshold


def ratio(value: float, reference: float) -> float:
    if reference <= 0:
        return 0.0 if value <= 0 else float("inf")
    return value / reference


def detect_step_change(series: Sequence[float], *, window: int = 3, factor: float = 2.0) -> int:
    """Return the index where a persistent latency step occurs, or -1."""

    if len(series) < window * 2:
        return -1
    for index in range(window, len(series) - window):
        before = median(series[index - window : index])
        after = median(series[index : index + window])
        if before > 0 and after >= before * factor:
            return index
    return -1


def coefficient_of_variation(values: Sequence[float]) -> float:
    average = mean(values)
    if average == 0:
        return 0.0
    return stdev(values) / average


def bayesian_rate(successes: int, trials: int, *, prior: float = 0.5, strength: float = 2.0) -> float:
    """Posterior mean of a Beta prior - used for probabilistic confidence."""

    alpha = prior * strength + successes
    beta = (1.0 - prior) * strength + (trials - successes)
    return alpha / (alpha + beta)


def entropy(values: Iterable[float]) -> float:
    total = sum(values)
    if total <= 0:
        return 0.0
    result = 0.0
    for value in values:
        if value <= 0:
            continue
        probability = value / total
        result -= probability * math.log2(probability)
    return result
