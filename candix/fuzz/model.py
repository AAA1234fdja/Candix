"""Data structures produced by the fuzzer."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

from candix.core.clock import humanize_duration, isoformat
from candix.core.severity import Severity


@dataclass
class FuzzCase:
    """One mutated request the fuzzer intends to send."""

    index: int
    method: str
    url: str
    parameter: str
    location: str
    original: str
    value: str
    family: str
    label: str
    strategy: str = "balanced"
    headers: dict[str, str] = field(default_factory=dict)

    @property
    def request_key(self) -> str:
        return f"{self.method} {self.url} {self.location}:{self.parameter}:{self.family}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "method": self.method,
            "url": self.url,
            "parameter": self.parameter,
            "location": self.location,
            "original": self.original,
            "value": self.value,
            "family": self.family,
            "label": self.label,
            "strategy": self.strategy,
        }


@dataclass
class FuzzSignal:
    """An anomaly detected while comparing a fuzzed response with its baseline."""

    family: str
    kind: str
    score: float
    severity: Severity
    reasons: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)

    @property
    def confident(self) -> bool:
        return self.score >= 0.75

    def to_dict(self) -> dict[str, Any]:
        return {
            "family": self.family,
            "kind": self.kind,
            "score": round(self.score, 3),
            "severity": self.severity.value,
            "reasons": list(self.reasons),
            "evidence": dict(self.evidence),
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "FuzzSignal":
        return cls(
            family=payload.get("family", ""),
            kind=payload.get("kind", ""),
            score=float(payload.get("score", 0.0)),
            severity=Severity.parse(payload.get("severity", "low")),
            reasons=list(payload.get("reasons") or []),
            evidence=dict(payload.get("evidence") or {}),
        )


@dataclass
class FuzzObservation:
    case: FuzzCase
    status: int
    length: int
    elapsed: float
    signal: FuzzSignal | None = None
    baseline_status: int = 0
    baseline_length: int = 0
    response_hash: str = ""

    @property
    def interesting(self) -> bool:
        return self.signal is not None and self.signal.score >= 0.5

    def to_dict(self) -> dict[str, Any]:
        return {
            "case": self.case.to_dict(),
            "status": self.status,
            "length": self.length,
            "elapsed": round(self.elapsed, 4),
            "baseline_status": self.baseline_status,
            "baseline_length": self.baseline_length,
            "response_hash": self.response_hash,
            "signal": self.signal.to_dict() if self.signal else None,
        }


@dataclass
class FuzzResult:
    scan_id: str
    started_at: str
    finished_at: str
    duration: float
    strategy: str
    seed: int
    iterations: int
    requests: int = 0
    errors: int = 0
    cases: list[FuzzCase] = field(default_factory=list)
    observations: list[FuzzObservation] = field(default_factory=list)
    findings: list[Any] = field(default_factory=list)
    corpus_dir: str = ""
    stats: dict[str, Any] = field(default_factory=dict)

    @property
    def signals(self) -> list[FuzzSignal]:
        return [observation.signal for observation in self.observations if observation.signal is not None]

    def counts(self) -> dict[str, int]:
        counts = {severity.value: 0 for severity in Severity}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        counts["total"] = len(self.findings)
        return counts

    def summary(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_seconds": round(self.duration, 3),
            "duration_human": humanize_duration(self.duration),
            "strategy": self.strategy,
            "seed": self.seed,
            "iterations": self.iterations,
            "requests": self.requests,
            "errors": self.errors,
            "cases": len(self.cases),
            "observations": len(self.observations),
            "signals": len(self.signals),
            "counts": self.counts(),
            "corpus_dir": self.corpus_dir,
            "stats": dict(self.stats),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "summary": self.summary(),
            "findings": [finding.to_dict(include_evidence=False) for finding in self.findings],
            "signals": [signal.to_dict() for signal in self.signals],
            "observations": [observation.to_dict() for observation in self.observations[:500]],
            "cases": [case.to_dict() for case in self.cases[:500]],
        }

    def to_json(self, *, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True, default=str)

    def digest(self) -> str:
        payload = json.dumps([case.to_dict() for case in self.cases], sort_keys=True)
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:32]
