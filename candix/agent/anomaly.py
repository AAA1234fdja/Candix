"""Detect the responses that differ from what the target normally does.

A scanner compares against a payload list. An adaptive agent compares against
the target itself: the same endpoint answering differently is the signal worth
spending the next request on.
"""

from __future__ import annotations

import statistics
from dataclasses import dataclass, field
from typing import Any, Iterable

STATUS_KINDS = {
    401: "authz",
    403: "authz",
    405: "method",
    429: "rate_limit",
    500: "error",
    502: "error",
    503: "rate_limit",
}

ERROR_SIGNATURES = (
    ("sql", "sqli"),
    ("syntax error", "sqli"),
    ("unterminated", "sqli"),
    ("stack trace", "error"),
    ("traceback", "error"),
    ("exception", "error"),
    ("template", "ssti"),
    ("root:x:0:0", "lfi"),
    ("no such file", "lfi"),
    ("permission denied", "lfi"),
)

MARKER_HINTS = (
    ("<script", "xss"),
    ("onerror", "xss"),
    ("alert(", "xss"),
    ("javascript:", "xss"),
    ("{{", "ssti"),
    ("${", "ssti"),
)

HEADER_HINTS = (
    ("access-control-allow-origin", "cors"),
    ("x-powered-by", "fingerprint"),
    ("location", "open_redirect"),
    ("www-authenticate", "auth"),
)


def _sig(value: float) -> str:
    return f"{value:.3f}"


@dataclass
class Sample:
    url: str = ""
    method: str = "GET"
    status: int = 0
    length: int = 0
    elapsed: float = 0.0
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    marker: str = ""
    error: str = ""
    family: str = ""

    def key(self, *, base: str = "") -> str:
        """Baseline key: the URL without its query, so parameters share a baseline."""

        target = self.url or base
        return target.split("?", 1)[0].rstrip("/") or base or "unknown"

    def header_signature(self) -> str:
        names = sorted(name.lower() for name in self.headers)
        return "|".join(names)

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "method": self.method,
            "status": self.status,
            "length": self.length,
            "elapsed": round(self.elapsed, 3),
            "family": self.family,
        }


@dataclass
class Baseline:
    key: str
    samples: int = 0
    statuses: dict[int, int] = field(default_factory=dict)
    lengths: list[float] = field(default_factory=list)
    durations: list[float] = field(default_factory=list)
    headers: set[str] = field(default_factory=set)

    def add(self, sample: Sample) -> None:
        self.samples += 1
        self.statuses[sample.status] = self.statuses.get(sample.status, 0) + 1
        self.lengths.append(float(sample.length))
        if sample.elapsed:
            self.durations.append(float(sample.elapsed))
        if sample.headers:
            self.headers.update(name.lower() for name in sample.headers)
        if len(self.lengths) > 200:
            self.lengths = self.lengths[-200:]
        if len(self.durations) > 200:
            self.durations = self.durations[-200:]

    @property
    def typical_status(self) -> int:
        if not self.statuses:
            return 0
        return max(self.statuses.items(), key=lambda pair: pair[1])[0]

    def length_stats(self) -> tuple[float, float]:
        if len(self.lengths) < 3:
            return (statistics.fmean(self.lengths) if self.lengths else 0.0, 0.0)
        median = statistics.median(self.lengths)
        deviation = statistics.median([abs(value - median) for value in self.lengths]) or 1.0
        return (median, deviation)

    def duration_stats(self) -> tuple[float, float]:
        usable = [value for value in self.durations if value > 0]
        if len(usable) < 3:
            return (statistics.fmean(usable) if usable else 0.0, 0.0)
        median = statistics.median(usable)
        deviation = statistics.median([abs(value - median) for value in usable]) or 0.01
        return (median, deviation)

    def to_dict(self) -> dict[str, Any]:
        median, mad = self.length_stats()
        return {"key": self.key, "samples": self.samples, "status": self.typical_status, "median_length": round(median, 2), "length_mad": round(mad, 2)}


@dataclass
class Anomaly:
    kind: str
    url: str
    strength: float
    detail: str
    hint: str = ""
    sample: dict[str, Any] = field(default_factory=dict)

    @property
    def weight(self) -> str:
        if self.strength >= 0.75:
            return "strong"
        if self.strength >= 0.45:
            return "medium"
        return "weak"

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "url": self.url,
            "strength": round(self.strength, 3),
            "weight": self.weight,
            "detail": self.detail,
            "hint": self.hint,
        }

    def describe(self) -> str:
        return f"{self.weight} {self.kind} on {self.url}: {self.detail}"


def family_of(url: str) -> str:
    lowered = url.lower()
    if "graphql" in lowered:
        return "graphql"
    if any(word in lowered for word in ("login", "signin", "auth", "session", "token")):
        return "auth"
    if "/api/" in lowered or lowered.endswith("/api"):
        return "api"
    return "web"


class AnomalyDetector:
    """Keeps per-endpoint baselines and reports deviations worth a test."""

    def __init__(self, *, length_z: float = 3.0, time_z: float = 3.5, min_samples: int = 2) -> None:
        self.length_z = length_z
        self.time_z = time_z
        self.min_samples = min_samples
        self.baselines: dict[str, Baseline] = {}
        self.anomalies: list[Anomaly] = []
        self.samples: int = 0

    def baseline(self, key: str) -> Baseline:
        return self.baselines.setdefault(key, Baseline(key=key))

    def observe(self, sample: Sample, *, learn: bool = True) -> list[Anomaly]:
        self.samples += 1
        key = sample.key()
        base = self.baseline(key)
        found: list[Anomaly] = []
        if base.samples >= self.min_samples:
            found.extend(self._status(sample, base))
            found.extend(self._length(sample, base))
            found.extend(self._timing(sample, base))
            found.extend(self._headers(sample, base))
        found.extend(self._content(sample))
        if learn:
            base.add(sample)
        for anomaly in found:
            self.anomalies.append(anomaly)
        if len(self.anomalies) > 500:
            self.anomalies = self.anomalies[-500:]
        return found

    def _status(self, sample: Sample, base: Baseline) -> list[Anomaly]:
        if not sample.status or sample.status == base.typical_status:
            return []
        hint = STATUS_KINDS.get(sample.status, "")
        strength = 0.6 if sample.status >= 500 else 0.5
        if base.typical_status and base.typical_status < 400 <= sample.status:
            strength = 0.7
        return [Anomaly("status", sample.url, strength, f"{sample.status} where the endpoint usually answers {base.typical_status}", hint or "behaviour", sample.to_dict())]

    def _length(self, sample: Sample, base: Baseline) -> list[Anomaly]:
        median, mad = base.length_stats()
        if not median:
            return []
        z = abs(sample.length - median) / max(mad, 1.0)
        if z < self.length_z:
            return []
        direction = "longer" if sample.length > median else "shorter"
        strength = min(0.9, 0.4 + z / 20)
        return [Anomaly("length", sample.url, strength, f"response {direction} than usual ({sample.length} vs {median:.0f} bytes, z={_sig(z)})", "reflection", sample.to_dict())]

    def _timing(self, sample: Sample, base: Baseline) -> list[Anomaly]:
        median, mad = base.duration_stats()
        if not median or not sample.elapsed:
            return []
        z = (sample.elapsed - median) / max(mad, 0.01)
        if z < self.time_z:
            return []
        strength = min(0.95, 0.35 + z / 12)
        return [Anomaly("timing", sample.url, strength, f"{sample.elapsed:.2f}s against a {median:.2f}s baseline (z={_sig(z)})", "sqli", sample.to_dict())]

    def _headers(self, sample: Sample, base: Baseline) -> list[Anomaly]:
        if not base.headers or not sample.headers:
            return []
        current = {name.lower() for name in sample.headers}
        added = current - base.headers
        if not added:
            return []
        hints = {hint for name, hint in HEADER_HINTS if name in added}
        detail = ", ".join(sorted(added)[:4])
        return [Anomaly("header", sample.url, 0.45, f"unusual headers: {detail}", next(iter(hints), "config"), sample.to_dict())]

    def _content(self, sample: Sample) -> list[Anomaly]:
        found: list[Anomaly] = []
        body = (sample.body or "").lower()
        marker = (sample.marker or "").lower()
        if marker and marker in body:
            hint = next((hint for token, hint in MARKER_HINTS if token in body or token in marker), "xss")
            found.append(Anomaly("reflection", sample.url, 0.85, f"marker {sample.marker} came back in the body", hint, sample.to_dict()))
        for token, hint in ERROR_SIGNATURES:
            if token in body:
                found.append(Anomaly("error", sample.url, 0.7, f"error signature '{token}' in the response", hint, sample.to_dict()))
                break
        if sample.error:
            found.append(Anomaly("transport", sample.url, 0.4, sample.error[:120], "availability", sample.to_dict()))
        return found

    def ranked(self, *, limit: int = 20) -> list[Anomaly]:
        return sorted(self.anomalies, key=lambda item: -item.strength)[:limit]

    def hints(self) -> dict[str, float]:
        totals: dict[str, float] = {}
        for anomaly in self.anomalies:
            if not anomaly.hint:
                continue
            totals[anomaly.hint] = round(totals.get(anomaly.hint, 0.0) + anomaly.strength, 3)
        return dict(sorted(totals.items(), key=lambda pair: -pair[1]))

    def by_url(self, url: str) -> list[Anomaly]:
        return [anomaly for anomaly in self.anomalies if anomaly.url == url]

    def summary(self) -> str:
        if not self.anomalies:
            return f"{self.samples} sample(s), no deviation from baseline"
        strongest = self.ranked(limit=1)[0]
        return f"{self.samples} sample(s), {len(self.anomalies)} anomaly(ies); strongest: {strongest.kind} on {strongest.url}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "samples": self.samples,
            "baselines": [baseline.to_dict() for baseline in self.baselines.values()][:40],
            "anomalies": [anomaly.to_dict() for anomaly in self.ranked()],
            "hints": self.hints(),
        }


def from_observation(observation: Any) -> list[Sample]:
    """Best-effort conversion of a tool observation into response samples."""

    payload = getattr(observation, "payload", None) or {}
    rows: list[Sample] = []
    if payload.get("url") and payload.get("status"):
        rows.append(
            Sample(
                url=str(payload.get("url")),
                method=str(payload.get("method", "GET")),
                status=int(payload.get("status", 0) or 0),
                length=int(payload.get("length", 0) or len(str(payload.get("body", ""))) or 0),
                elapsed=float(payload.get("elapsed", 0.0) or 0.0),
                headers={str(k): str(v) for k, v in (payload.get("headers") or {}).items()},
                body=str(payload.get("body", "") or payload.get("snippet", "") or ""),
                marker=str(payload.get("marker", "") or ""),
                error=str(payload.get("error", "") or ""),
                family=family_of(str(payload.get("url"))),
            )
        )
    for key in ("paths", "requests", "responses", "results"):
        for entry in payload.get(key) or []:
            if not isinstance(entry, dict):
                continue
            url = str(entry.get("url") or entry.get("path") or "")
            if not url:
                continue
            rows.append(
                Sample(
                    url=url,
                    method=str(entry.get("method", "GET")),
                    status=int(entry.get("status", 0) or 0),
                    length=int(entry.get("length", 0) or entry.get("size", 0) or 0),
                    elapsed=float(entry.get("elapsed", 0.0) or entry.get("duration", 0.0) or 0.0),
                    headers={str(k): str(v) for k, v in (entry.get("headers") or {}).items()},
                    body=str(entry.get("body", "") or entry.get("snippet", "") or ""),
                    marker=str(entry.get("marker", "") or ""),
                    error=str(entry.get("error", "") or ""),
                    family=family_of(url),
                )
            )
    for item in payload.get("signals") or []:
        text = str(item)
        rows.append(Sample(url=str(payload.get("url", "")), body=text, marker=text, family="signal"))
    return rows


def absorb(detector: AnomalyDetector, observations: Iterable[Any]) -> list[Anomaly]:
    found: list[Anomaly] = []
    for observation in observations:
        for sample in from_observation(observation):
            found.extend(detector.observe(sample))
    return found


def interesting(detector: AnomalyDetector, *, threshold: float = 0.6) -> list[Anomaly]:
    return [anomaly for anomaly in detector.ranked() if anomaly.strength >= threshold]


def explain(detector: AnomalyDetector) -> str:
    lines = [detector.summary(), ""]
    for anomaly in detector.ranked(limit=10):
        lines.append(f"- {anomaly.describe()}" + (f" → {anomaly.hint}" if anomaly.hint else ""))
    if detector.hints():
        lines.append("")
        lines.append("hints: " + ", ".join(f"{name} {score:.2f}" for name, score in detector.hints().items()))
    return "\n".join(lines)
