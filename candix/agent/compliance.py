"""Map findings and coverage onto the controls a client recognises."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

_SEVERITY_WEIGHT = {"critical": 4.0, "high": 2.5, "medium": 1.2, "low": 0.5, "info": 0.1}


@dataclass
class Control:
    id: str
    title: str
    framework: str
    summary: str = ""
    cwes: tuple[str, ...] = ()
    categories: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "framework": self.framework,
            "summary": self.summary,
            "cwes": list(self.cwes),
            "categories": list(self.categories),
        }


CONTROLS: tuple[Control, ...] = (
    Control("V2.1", "Password security", "ASVS 4.0", "Passwords meet policy and are not enumerable by response.", ("CWE-521", "CWE-204"), ("authentication",)),
    Control("V2.2", "Authenticator lifecycle", "ASVS 4.0", "Credentials can be rotated and reset safely.", ("CWE-640",), ("authentication",)),
    Control("V3.1", "Session management", "ASVS 4.0", "Session ids rotate on login and are not exposed in URLs.", ("CWE-384", "CWE-598"), ("session",)),
    Control("V3.4", "Cookie attributes", "ASVS 4.0", "Session cookies are HttpOnly, Secure and SameSite.", ("CWE-1004", "CWE-614"), ("session", "headers")),
    Control("V4.1", "Access control", "ASVS 4.0", "Every request enforces authorization server side.", ("CWE-285", "CWE-639"), ("authorization", "idor", "access-control")),
    Control("V4.2", "Object level authorization", "ASVS 4.0", "Objects are scoped to the requesting principal.", ("CWE-639",), ("idor", "authorization")),
    Control("V5.2", "Sanitisation", "ASVS 4.0", "Untrusted input cannot change syntax of an interpreter.", ("CWE-79", "CWE-89", "CWE-78"), ("injection", "sqli", "xss", "command")),
    Control("V5.3", "Output encoding", "ASVS 4.0", "Output is encoded for the context it lands in.", ("CWE-79",), ("xss", "injection")),
    Control("V5.5", "Deserialisation", "ASVS 4.0", "Untrusted data is never deserialised into objects.", ("CWE-502",), ("deserialization",)),
    Control("V7.1", "Logging", "ASVS 4.0", "Security events are logged without secrets.", ("CWE-532",), ("logging",)),
    Control("V8.3", "Sensitive data", "ASVS 4.0", "Sensitive data is not stored or served in the clear.", ("CWE-311",), ("exposure", "data")),
    Control("V9.1", "Communications", "ASVS 4.0", "TLS is required and correctly configured.", ("CWE-319",), ("transport", "tls")),
    Control("V12.1", "File upload", "ASVS 4.0", "Uploads are validated and stored outside the web root.", ("CWE-434",), ("upload",)),
    Control("V12.6", "File download", "ASVS 4.0", "Downloads are authorized per object.", ("CWE-22", "CWE-639"), ("exposure", "path-traversal")),
    Control("V13.1", "API authorization", "ASVS 4.0", "APIs enforce the same rules as the UI.", ("CWE-285",), ("api", "idor")),
    Control("V13.2", "API schema", "ASVS 4.0", "Schemas are validated and not publicly documented by accident.", ("CWE-200",), ("api", "exposure")),
    Control("V14.3", "Configuration", "ASVS 4.0", "Debug, status and metadata endpoints are disabled in production.", ("CWE-16", "CWE-200"), ("exposure", "configuration")),
)


@dataclass
class ControlStatus:
    control: Control
    findings: list[dict[str, Any]] = field(default_factory=list)
    risk: float = 0.0

    @property
    def status(self) -> str:
        if not self.findings:
            return "pass"
        if any(str(item.get("severity")) in {"critical", "high"} for item in self.findings):
            return "fail"
        return "warn"

    def to_dict(self) -> dict[str, Any]:
        return {
            "control": self.control.to_dict(),
            "status": self.status,
            "risk": round(self.risk, 2),
            "findings": [item.get("id", "") for item in self.findings],
        }


@dataclass
class ComplianceReport:
    statuses: list[ControlStatus] = field(default_factory=list)
    framework: str = "ASVS 4.0"

    @property
    def failed(self) -> list[ControlStatus]:
        return [item for item in self.statuses if item.status == "fail"]

    @property
    def warned(self) -> list[ControlStatus]:
        return [item for item in self.statuses if item.status == "warn"]

    @property
    def passed(self) -> list[ControlStatus]:
        return [item for item in self.statuses if item.status == "pass"]

    def score(self) -> float:
        if not self.statuses:
            return 0.0
        penalty = sum(item.risk for item in self.statuses)
        return max(0.0, min(100.0, 100.0 - penalty))

    def to_dict(self) -> dict[str, Any]:
        return {
            "framework": self.framework,
            "score": round(self.score(), 1),
            "failed": [item.control.id for item in self.failed],
            "warned": [item.control.id for item in self.warned],
            "passed": [item.control.id for item in self.passed],
            "controls": [item.to_dict() for item in self.statuses],
            "summary": self.summary(),
        }

    def summary(self) -> str:
        return (
            f"{len(self.failed)} control(s) failed, {len(self.warned)} warn, "
            f"{len(self.passed)} pass (score {self.score():.0f})"
        )

    def markdown(self) -> str:
        lines = [
            f"| Control | Title | Status | Findings |",
            "| --- | --- | --- | --- |",
        ]
        for item in sorted(self.statuses, key=lambda entry: (entry.status != "fail", entry.control.id)):
            titles = ", ".join(str(finding.get("title", ""))[:40] for finding in item.findings[:2])
            lines.append(f"| {item.control.id} | {item.control.title} | {item.status} | {titles or '-'} |")
        return "\n".join(lines) + "\n"


def evaluate(findings: Iterable[dict[str, Any]], *, controls: Iterable[Control] = CONTROLS) -> ComplianceReport:
    items = list(findings)
    report = ComplianceReport()
    for control in controls:
        wanted = {category.lower() for category in control.categories}
        matched = [
            finding
            for finding in items
            if str(finding.get("category", "")).lower() in wanted
            or any(cwe in (finding.get("cwe") or []) for cwe in control.cwes)
        ]
        risk = sum(_SEVERITY_WEIGHT.get(str(finding.get("severity")), 0.2) for finding in matched)
        report.statuses.append(ControlStatus(control=control, findings=matched, risk=risk))
    return report


def gaps(report: ComplianceReport, *, limit: int = 5) -> list[str]:
    return [f"{item.control.id} {item.control.title}" for item in report.failed[:limit]]


def cwe_index(findings: Iterable[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for finding in findings:
        for cwe in finding.get("cwe") or []:
            counts[str(cwe)] = counts.get(str(cwe), 0) + 1
    return dict(sorted(counts.items(), key=lambda pair: -pair[1]))


def remediation_order(findings: Iterable[dict[str, Any]], *, limit: int = 5) -> list[dict[str, Any]]:
    """Findings sorted by severity, then by how cheap they are to fix."""

    cheap = {"headers", "session", "configuration", "exposure", "transport"}
    ranked = []
    for finding in findings:
        severity = str(finding.get("severity", "info"))
        weight = _SEVERITY_WEIGHT.get(severity, 0.2)
        category = str(finding.get("category", "")).lower()
        ease = 1.2 if category in cheap else 1.0
        ranked.append((weight * ease, finding))
    ranked.sort(key=lambda pair: -pair[0])
    return [finding for _score, finding in ranked[:limit]]
