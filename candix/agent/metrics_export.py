"""Export run telemetry in the shapes monitoring systems already read."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

_PREFIX = "candix_agent"


def _escape(value: str) -> str:
    return str(value).replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def _labels(labels: dict[str, str]) -> str:
    if not labels:
        return ""
    body = ",".join(f'{key}="{_escape(value)}"' for key, value in sorted(labels.items()))
    return "{" + body + "}"


@dataclass
class Sample:
    name: str
    value: float
    labels: dict[str, str] = field(default_factory=dict)
    kind: str = "gauge"
    help: str = ""

    def render(self) -> str:
        return f"{_PREFIX}_{self.name}{_labels(self.labels)} {self.value}"


@dataclass
class Metrics:
    samples: list[Sample] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)

    def add(self, name: str, value: float, *, labels: dict[str, str] | None = None, kind: str = "gauge") -> Sample:
        sample = Sample(name=name, value=float(value), labels=dict(labels or {}), kind=kind)
        self.samples.append(sample)
        return sample

    def extend(self, samples: Iterable[Sample]) -> None:
        self.samples.extend(samples)

    def prometheus(self, *, include_help: bool = True) -> str:
        lines: list[str] = []
        seen: set[tuple[str, str]] = set()
        for sample in self.samples:
            key = (sample.name, sample.kind)
            if include_help and key not in seen:
                seen.add(key)
                lines.append(f"# HELP {_PREFIX}_{sample.name} {sample.help or sample.name}")
                lines.append(f"# TYPE {_PREFIX}_{sample.name} {sample.kind}")
            lines.append(sample.render())
        return "\n".join(lines) + "\n"

    def json_lines(self) -> str:
        return "\n".join(
            json.dumps({"name": f"{_PREFIX}_{sample.name}", "value": sample.value, "labels": sample.labels, "type": sample.kind})
            for sample in self.samples
        ) + "\n"

    def openmetrics(self) -> str:
        return self.prometheus() + "# EOF\n"

    def save(self, path: str | Path, *, fmt: str = "prometheus") -> str:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        body = {"prometheus": self.prometheus, "openmetrics": self.openmetrics, "jsonl": self.json_lines}[fmt]()
        target.write_text(body, encoding="utf-8")
        return str(target)

    def to_dict(self) -> dict[str, Any]:
        return {"timestamp": self.timestamp, "samples": [{"name": item.name, "value": item.value, "labels": item.labels} for item in self.samples]}


def from_result(result: Any, *, telemetry: Any = None, budget: Any = None, extra_labels: dict[str, str] | None = None) -> Metrics:
    labels = dict(extra_labels or {})
    metrics = Metrics()
    metrics.add("run_seconds", getattr(result, "duration", 0.0), labels=labels)
    metrics.add("findings", len(getattr(result, "findings", [])), labels=labels)
    metrics.add("proofs", len(getattr(result, "proofs", [])), labels=labels)
    for status, count in (result.counts() if hasattr(result, "counts") else {}).items():
        metrics.add("intents", count, labels={**labels, "status": status}, kind="counter")
    for intent in getattr(result, "intents", []) or []:
        metrics.add(
            "intent_seconds",
            float(getattr(intent, "duration", 0.0) or 0.0),
            labels={**labels, "tool": str(getattr(intent, "tool", "") or "none")},
            kind="histogram",
        )
    if budget is not None and hasattr(budget, "snapshot"):
        snapshot = budget.snapshot()
        for name in ("turns", "tool_calls", "tokens", "intents", "cost_usd"):
            value = snapshot.get(name, 0)
            metrics.add(f"budget_{name}", float(value or 0), labels=labels, kind="counter")
        limits = snapshot.get("limits", {}) or {}
        for name, value in limits.items():
            metrics.add(f"limit_{name}", float(value or 0), labels=labels)
    if telemetry is not None and hasattr(telemetry, "snapshot"):
        payload = telemetry.snapshot()
        for name, value in (payload.get("counters") or {}).items():
            metrics.add("counter", float(value), labels={**labels, "name": name}, kind="counter")
        for name, stats in (payload.get("timers") or payload.get("observations") or {}).items():
            if isinstance(stats, dict):
                metrics.add("step_seconds", float(stats.get("total", 0.0) or 0.0), labels={**labels, "step": name}, kind="histogram")
    return metrics


def write_textfile(metrics: Metrics, path: str | Path) -> str:
    """Prometheus node-exporter textfile convention: write then rename."""

    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_suffix(target.suffix + ".tmp")
    tmp.write_text(metrics.prometheus(), encoding="utf-8")
    tmp.replace(target)
    return str(target)


def merge(*collections: Metrics) -> Metrics:
    merged = Metrics()
    for collection in collections:
        merged.extend(collection.samples)
    return merged


def filter_by(samples: Iterable[Sample], *, kind: str = "") -> list[Sample]:
    return [sample for sample in samples if not kind or sample.kind == kind]


def summary(metrics: Metrics) -> str:
    gauges = [sample for sample in metrics.samples if sample.kind == "gauge"]
    return f"{len(metrics.samples)} sample(s), {len(gauges)} gauge(s), {len({sample.name for sample in metrics.samples})} series"


def zero_fill(metrics: Metrics, names: Iterable[str]) -> Metrics:
    present = {sample.name for sample in metrics.samples}
    for name in names:
        if name not in present:
            metrics.add(name, 0.0)
    return metrics


def cost_per_finding(metrics: Metrics) -> float:
    cost = next((sample.value for sample in metrics.samples if sample.name == "budget_cost_usd"), 0.0)
    findings = next((sample.value for sample in metrics.samples if sample.name == "findings"), 0.0)
    return cost / findings if findings else 0.0


def snapshot_file(path: str | Path) -> str:
    """Write a JSON snapshot that dashboards can poll without a parser."""

    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps({"generated_at": time.time(), "note": "candix agent run metrics"}, indent=2),
        encoding="utf-8",
    )
    return str(target)
