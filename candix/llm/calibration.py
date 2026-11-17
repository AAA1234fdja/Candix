"""Do the model's confidences mean anything? Measure, then correct."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable


@dataclass
class Label:
    confidence: float
    correct: bool
    source: str = ""

    def clamped(self) -> float:
        return min(1.0, max(0.0, float(self.confidence)))


@dataclass
class Bin:
    lower: float
    upper: float
    count: int = 0
    positives: int = 0
    confidence_sum: float = 0.0

    @property
    def mean_confidence(self) -> float:
        return self.confidence_sum / self.count if self.count else 0.0

    @property
    def accuracy(self) -> float:
        return self.positives / self.count if self.count else 0.0

    @property
    def gap(self) -> float:
        return self.accuracy - self.mean_confidence

    def to_dict(self) -> dict[str, Any]:
        return {"lower": self.lower, "upper": self.upper, "count": self.count, "accuracy": round(self.accuracy, 3), "mean_confidence": round(self.mean_confidence, 3)}


def brier(labels: Iterable[Label]) -> float:
    items = list(labels)
    if not items:
        return 0.0
    return sum((item.clamped() - (1.0 if item.correct else 0.0)) ** 2 for item in items) / len(items)


def log_loss(labels: Iterable[Label], *, epsilon: float = 1e-6) -> float:
    import math

    items = list(labels)
    if not items:
        return 0.0
    total = 0.0
    for item in items:
        p = min(1 - epsilon, max(epsilon, item.clamped()))
        total += -math.log(p) if item.correct else -math.log(1 - p)
    return total / len(items)


def bins(labels: Iterable[Label], *, count: int = 10) -> list[Bin]:
    edges = [index / count for index in range(count + 1)]
    buckets = [Bin(lower=edges[index], upper=edges[index + 1]) for index in range(count)]
    for item in labels:
        value = item.clamped()
        index = min(count - 1, int(value * count))
        bucket = buckets[index]
        bucket.count += 1
        bucket.confidence_sum += value
        bucket.positives += 1 if item.correct else 0
    return buckets


def reliability(labels: Iterable[Label], *, count: int = 10) -> dict[str, Any]:
    items = list(labels)
    buckets = bins(items, count=count)
    ece = sum(bucket.count * abs(bucket.gap) for bucket in buckets) / len(items) if items else 0.0
    return {
        "labels": len(items),
        "accuracy": round(sum(1 for item in items if item.correct) / len(items), 3) if items else 0.0,
        "mean_confidence": round(sum(item.clamped() for item in items) / len(items), 3) if items else 0.0,
        "brier": round(brier(items), 4),
        "ece": round(ece, 4),
        "bins": [bucket.to_dict() for bucket in buckets if bucket.count],
    }


def precision_recall(labels: Iterable[Label], *, threshold: float = 0.5) -> dict[str, float]:
    items = [item for item in labels if item.clamped() >= threshold]
    tp = sum(1 for item in items if item.correct)
    fp = len(items) - tp
    total_positives = sum(1 for item in labels if item.correct)
    precision = tp / len(items) if items else 0.0
    recall = tp / total_positives if total_positives else 0.0
    return {"threshold": threshold, "selected": float(len(items)), "precision": round(precision, 3), "recall": round(recall, 3)}


def pick_threshold(labels: Iterable[Label], *, target_precision: float = 0.9, step: float = 0.05) -> float:
    items = list(labels)
    if not items:
        return 0.5
    best = 0.5
    for index in range(1, int(1 / step)):
        threshold = index * step
        stats = precision_recall(items, threshold=threshold)
        if stats["precision"] >= target_precision:
            best = threshold
    return round(best, 3)


@dataclass
class Calibrator:
    """Isotonic-style piecewise mapping from raw confidence to observed accuracy."""

    points: list[tuple[float, float]] = field(default_factory=list)
    samples: int = 0

    def fit(self, labels: Iterable[Label]) -> "Calibrator":
        items = sorted(labels, key=lambda item: item.clamped())
        self.samples = len(items)
        if not items:
            self.points = []
            return self
        # Pool adjacent violators over quantiles of the raw confidence.
        width = max(1, len(items) // 8)
        groups = [items[index : index + width] for index in range(0, len(items), width)]
        merged: list[list[Label]] = []
        for group in groups:
            merged.append(group)
            while len(merged) > 1:
                last, previous = merged[-1], merged[-2]
                last_acc = sum(1 for item in last if item.correct) / len(last)
                prev_acc = sum(1 for item in previous if item.correct) / len(previous)
                if last_acc >= prev_acc:
                    break
                merged[-2:] = [previous + last]
        self.points = []
        for group in merged:
            raw = sum(item.clamped() for item in group) / len(group)
            observed = sum(1 for item in group if item.correct) / len(group)
            self.points.append((round(raw, 4), round(observed, 4)))
        return self

    def apply(self, confidence: float) -> float:
        if not self.points:
            return min(1.0, max(0.0, confidence))
        value = min(1.0, max(0.0, confidence))
        if value <= self.points[0][0]:
            return self.points[0][1]
        if value >= self.points[-1][0]:
            return self.points[-1][1]
        for (low_raw, low_obs), (high_raw, high_obs) in zip(self.points, self.points[1:]):
            if low_raw <= value <= high_raw:
                span = high_raw - low_raw or 1e-9
                ratio = (value - low_raw) / span
                return round(low_obs + ratio * (high_obs - low_obs), 4)
        return self.points[-1][1]

    def to_dict(self) -> dict[str, Any]:
        return {"points": self.points, "samples": self.samples}

    def save(self, path: str | Path) -> str:
        target = Path(path)
        target.write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")
        return str(target)

    @classmethod
    def load(cls, path: str | Path) -> "Calibrator":
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls(points=[tuple(item) for item in payload.get("points", [])], samples=int(payload.get("samples", 0)))


def inflate(confidence: float, *, factor: float = 1.15, ceiling: float = 0.99) -> float:
    """Confidence raised for repeated independent confirmations."""

    return min(ceiling, confidence * factor)


def deflate(confidence: float, *, factor: float = 0.8) -> float:
    return max(0.0, confidence * factor)


def adjust(confidence: float, *, verified: bool = False, contradicted: bool = False, source: str = "") -> float:
    value = confidence
    if verified:
        value = inflate(value)
    if contradicted:
        value = deflate(value, factor=0.5)
    if source in {"inference", "guess"}:
        value = deflate(value, factor=0.7)
    return round(min(0.99, max(0.01, value)), 3)


def from_findings(findings: Iterable[dict[str, Any]], *, ground_truth: dict[str, bool] | None = None) -> list[Label]:
    truth = ground_truth or {}
    labels: list[Label] = []
    for finding in findings:
        key = str(finding.get("id") or finding.get("title", ""))
        if key not in truth:
            continue
        confidence = float(finding.get("confidence", 0.5) or 0.5)
        if confidence > 1:
            confidence = confidence / 100.0
        labels.append(Label(confidence=confidence, correct=bool(truth[key]), source=key))
    return labels


def report(labels: Iterable[Label]) -> str:
    stats = reliability(labels)
    lines = [
        f"labels: {stats['labels']}",
        f"accuracy: {stats['accuracy']} · mean confidence: {stats['mean_confidence']}",
        f"brier: {stats['brier']} · ece: {stats['ece']}",
        "",
        "| bin | n | accuracy | confidence |",
        "| --- | --- | --- | --- |",
    ]
    for bucket in stats["bins"]:
        lines.append(f"| {bucket['lower']:.1f}-{bucket['upper']:.1f} | {bucket['count']} | {bucket['accuracy']:.2f} | {bucket['mean_confidence']:.2f} |")
    return "\n".join(lines) + "\n"
