"""SIEM-oriented exports: CEF, LEEF, syslog and NDJSON."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Iterable, Mapping

CEF_VERSION = 0
DEVICE_VENDOR = "Candix"
DEVICE_PRODUCT = "SecurityAssessment"
DEVICE_VERSION = "0.1.0"

_CEF_ESCAPES = (("\\", "\\\\"), ("|", "\\|"), ("=", "\\="), ("\n", "\\n"), ("\r", "\\r"))


def _escape(value: Any) -> str:
    text = str(value)
    for source, target in _CEF_ESCAPES:
        text = text.replace(source, target)
    return text


def _severity_number(severity: str) -> int:
    return {"info": 2, "low": 4, "medium": 6, "high": 8, "critical": 10}.get(severity.lower(), 3)


@dataclass
class SiemEvent:
    finding_id: str
    name: str
    severity: str
    endpoint: str
    method: str
    parameter: str
    cwe: tuple[str, ...]
    description: str
    scan_id: str
    detected_at: str = ""
    extra: dict[str, Any] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        self.extra = dict(self.extra or {})

    @classmethod
    def from_finding(cls, finding: Mapping[str, Any], *, scan_id: str = "") -> "SiemEvent":
        severity = finding.get("severity", "info")
        if isinstance(severity, Mapping):
            severity = severity.get("name", "info")
        return cls(
            finding_id=str(finding.get("id", "")),
            name=str(finding.get("title", "finding")),
            severity=str(severity).lower(),
            endpoint=str(finding.get("url", "")),
            method=str(finding.get("method", "GET")),
            parameter=str(finding.get("parameter", "")),
            cwe=tuple(finding.get("cwe") or ()),
            description=str(finding.get("description", ""))[:512],
            scan_id=scan_id or str((finding.get("target") or "")),
            detected_at=str(finding.get("discovered_at", "")),
            extra={
                "confidence": finding.get("confidence", ""),
                "verified": finding.get("verified", False),
                "exploited": finding.get("exploited", False),
            },
        )

    def to_cef(self) -> str:
        header = "|".join(
            _escape(part)
            for part in (
                f"CEF:{CEF_VERSION}",
                DEVICE_VENDOR,
                DEVICE_PRODUCT,
                DEVICE_VERSION,
                self.finding_id or self.name,
                self.name,
                _severity_number(self.severity),
            )
        )
        extension = {
            "src": self.endpoint,
            "requestMethod": self.method,
            "cs1Label": "candix.parameter",
            "cs1": self.parameter,
            "cs2Label": "candix.scan",
            "cs2": self.scan_id,
            "cs3Label": "candix.cwe",
            "cs3": ",".join(self.cwe),
            "msg": self.description,
            "cat": "security-finding",
            "rt": self.detected_at,
            "outcome": "verified" if self.extra.get("verified") else "reported",
        }
        pairs = " ".join(f"{key}={_escape(value)}" for key, value in extension.items() if value not in ("", None))
        return f"{header}|{pairs}"

    def to_leef(self) -> str:
        attributes = {
            "ident": self.finding_id,
            "name": self.name,
            "sev": _severity_number(self.severity),
            "url": self.endpoint,
            "method": self.method,
            "param": self.parameter,
            "cwe": ",".join(self.cwe),
            "scan": self.scan_id,
            "msg": self.description,
        }
        body = "\t".join(f"{key}={value}" for key, value in attributes.items())
        return f"LEEF:2.0|{DEVICE_VENDOR}|{DEVICE_PRODUCT}|{DEVICE_VERSION}|{self.name}|^{body}"

    def to_syslog(self, *, hostname: str = "candix") -> str:
        priority = 11 + _severity_number(self.severity) % 8
        return (
            f"<{priority}>1 - {hostname} candix - - - "
            f"severity={self.severity} finding={self.finding_id} endpoint={self.method} {self.endpoint} "
            f"name={self.name!r} param={self.parameter}"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "name": self.name,
            "severity": self.severity,
            "endpoint": self.endpoint,
            "method": self.method,
            "parameter": self.parameter,
            "cwe": list(self.cwe),
            "description": self.description,
            "scan_id": self.scan_id,
            "detected_at": self.detected_at,
            "extra": dict(self.extra),
        }


def events_from_report(report: Mapping[str, Any], *, min_severity: str = "info") -> list[SiemEvent]:
    order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    threshold = order.get(min_severity.lower(), 0)
    summary = report.get("summary") or {}
    scan_id = str(summary.get("scan_id", ""))
    events: list[SiemEvent] = []
    for finding in report.get("findings") or []:
        event = SiemEvent.from_finding(finding, scan_id=scan_id)
        if order.get(event.severity, 0) >= threshold:
            events.append(event)
    return events


def render_cef(events: Iterable[SiemEvent]) -> str:
    return "\n".join(event.to_cef() for event in events)


def render_leef(events: Iterable[SiemEvent]) -> str:
    return "\n".join(event.to_leef() for event in events)


def render_syslog(events: Iterable[SiemEvent]) -> str:
    return "\n".join(event.to_syslog() for event in events)


def render_ndjson(events: Iterable[SiemEvent]) -> str:
    return "\n".join(json.dumps(event.to_dict(), sort_keys=True) for event in events)


RENDERERS = {
    "cef": render_cef,
    "leef": render_leef,
    "syslog": render_syslog,
    "ndjson": render_ndjson,
}


def render(report: Mapping[str, Any], fmt: str = "cef", *, min_severity: str = "info") -> str:
    renderer = RENDERERS.get(fmt.lower())
    if renderer is None:
        raise ValueError(f"unsupported SIEM format: {fmt}")
    return renderer(events_from_report(report, min_severity=min_severity))
