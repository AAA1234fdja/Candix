"""Report model.

The renderers are intentionally dumb: all selection, ordering, scoring and
redaction happens here so that HTML, Markdown, JSON and SARIF cannot disagree
about which findings exist or how severe they are.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

from candix.core.clock import humanize_duration, isoformat
from candix.core.config import Config
from candix.core.finding import Finding, FindingSet, Remediation
from candix.core.ids import sha256
from candix.core.severity import Severity
from candix.engine import ScanResult


@dataclass
class SeverityBucket:
    severity: Severity
    count: int = 0

    @property
    def percent(self) -> float:
        return 0.0


@dataclass
class ReportModel:
    title: str
    scan_id: str
    generated_at: str
    started_at: str
    duration: float
    profile: str
    engagement: dict[str, Any]
    targets: list[dict[str, Any]]
    findings: list[Finding]
    counts: dict[str, int]
    risk_score: float
    chains: list[dict[str, Any]] = field(default_factory=list)
    proofs: list[dict[str, Any]] = field(default_factory=list)
    technologies: dict[str, Any] = field(default_factory=dict)
    waf: dict[str, Any] = field(default_factory=dict)
    phases: list[dict[str, Any]] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    evidence_count: int = 0
    methodology: list[str] = field(default_factory=list)
    appendix: dict[str, Any] = field(default_factory=dict)
    version: str = ""
    digest: str = ""

    # ------------------------------------------------------------------
    @classmethod
    def from_result(cls, result: ScanResult, *, title: str | None = None, min_severity: Severity = Severity.INFO) -> "ReportModel":
        ctx = result.context
        config: Config = ctx.config
        findings = [
            finding
            for finding in ctx.findings.sorted()
            if finding.severity.rank >= min_severity.rank
        ]
        model = cls(
            title=title or str(config.get("report.title", "Security assessment")),
            scan_id=ctx.id,
            generated_at=isoformat(),
            started_at=ctx.started_at,
            duration=ctx.elapsed,
            profile=str(config.get("profile")),
            engagement=ctx.engagement.summary() if ctx.engagement else {},
            targets=[target.to_dict() for target in ctx.targets],
            findings=findings,
            counts=_counts(findings),
            risk_score=round(sum(_weight(finding) for finding in findings), 2),
            chains=list(getattr(ctx, "metadata", {}).get("attack_chains", []) or result.summary().get("attack_chains", []) or []),
            proofs=list(getattr(ctx, "metadata", {}).get("proofs", []) or []),
            technologies=(result.fingerprint.to_dict() if result.fingerprint else {}),
            waf=(result.waf.to_dict() if result.waf else {}),
            phases=[
                {
                    "name": phase.name,
                    "duration": round(phase.duration, 3),
                    "ok": phase.ok,
                    "error": phase.error,
                }
                for phase in result.phases
            ],
            stats=dict(ctx.stats),
            warnings=list(ctx.warnings),
            evidence_count=ctx.evidence.count,
            methodology=_METHODOLOGY,
            appendix={
                "endpoints": ctx.endpoints.stats(),
                "http": ctx.http.snapshot(),
                "budget": ctx.budget.snapshot(),
                "options": ctx.options.to_dict(),
                "report_formats": list(config.get("report.formats", [])),
            },
            version=_version(),
        )
        model.digest = _digest(model)
        return model

    @classmethod
    def from_snapshot(cls, payload: dict[str, Any], *, min_severity: Severity = Severity.INFO) -> "ReportModel":
        """Rebuild a model from a previously generated JSON report."""

        summary = payload.get("summary") or {}
        findings = [
            Finding.from_dict(item)
            for item in payload.get("findings", [])
            if Severity.parse(str(item.get("severity", "info"))).rank >= min_severity.rank
        ]
        model = cls(
            title=str(summary.get("title") or payload.get("title") or "Security assessment"),
            scan_id=str(summary.get("scan_id") or payload.get("scan_id") or "unknown"),
            generated_at=str(summary.get("generated_at") or ""),
            started_at=str(summary.get("started_at") or ""),
            duration=float(summary.get("duration_seconds") or 0.0),
            profile=str(summary.get("profile") or "unknown"),
            engagement=dict(summary.get("engagement") or {}),
            targets=_normalise_targets(summary.get("targets") or []),
            findings=findings,
            counts=_counts(findings),
            risk_score=round(sum(_weight(finding) for finding in findings), 2),
            chains=list(payload.get("attack_chains") or []),
            proofs=list(payload.get("proofs") or []),
            technologies=dict(payload.get("technologies") or {}),
            waf=dict(payload.get("waf") or {}),
            phases=list(payload.get("phases") or []),
            stats=dict(payload.get("stats") or {}),
            warnings=list(summary.get("warnings") or []),
            evidence_count=int(summary.get("evidence_count") or 0),
            methodology=list(payload.get("methodology") or _METHODOLOGY),
            appendix=dict(payload.get("appendix") or {}),
            version=str(summary.get("version") or _version()),
        )
        model.digest = _digest(model)
        return model

    # ------------------------------------------------------------------
    @property
    def critical_findings(self) -> list[Finding]:
        return [finding for finding in self.findings if finding.severity is Severity.CRITICAL]

    @property
    def high_findings(self) -> list[Finding]:
        return [finding for finding in self.findings if finding.severity is Severity.HIGH]

    @property
    def verified_findings(self) -> list[Finding]:
        return [finding for finding in self.findings if finding.verified]

    @property
    def exploited_findings(self) -> list[Finding]:
        return [finding for finding in self.findings if finding.exploited]

    def by_category(self) -> dict[str, list[Finding]]:
        grouped: dict[str, list[Finding]] = {}
        for finding in self.findings:
            grouped.setdefault(finding.category, []).append(finding)
        return dict(sorted(grouped.items(), key=lambda pair: (-len(pair[1]), pair[0])))

    def by_severity(self) -> list[tuple[str, int]]:
        return [(severity.value, self.counts.get(severity.value, 0)) for severity in Severity if severity is not Severity.INFO] + [
            ("info", self.counts.get("info", 0))
        ]

    def remediation_plan(self) -> list[dict[str, Any]]:
        grouped: dict[str, dict[str, Any]] = {}
        for finding in self.findings:
            key = finding.remediation.summary or finding.category
            bucket = grouped.setdefault(
                key,
                {
                    "summary": key,
                    "severity": finding.severity.value,
                    "effort": finding.remediation.effort,
                    "owner_hint": finding.remediation.owner_hint,
                    "findings": [],
                    "steps": list(finding.remediation.steps),
                    "references": list(finding.remediation.references),
                    "verification": finding.remediation.verification,
                    "sla_days": finding.severity.sla_days,
                },
            )
            if finding.severity.rank > Severity.parse(bucket["severity"]).rank:
                bucket["severity"] = finding.severity.value
                bucket["sla_days"] = finding.severity.sla_days
            bucket["findings"].append({"id": finding.id, "title": finding.title, "url": finding.url})
        plan = list(grouped.values())
        order = {severity.value: severity.rank for severity in Severity}
        plan.sort(key=lambda item: (-order.get(item["severity"], 0), item["summary"]))
        return plan

    def summary(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "scan_id": self.scan_id,
            "generated_at": self.generated_at,
            "started_at": self.started_at,
            "duration_seconds": round(self.duration, 3),
            "duration_human": humanize_duration(self.duration),
            "profile": self.profile,
            "engagement": self.engagement,
            "targets": self.targets,
            "counts": self.counts,
            "risk_score": self.risk_score,
            "evidence_count": self.evidence_count,
            "verified": len(self.verified_findings),
            "exploited": len(self.exploited_findings),
            "warnings": self.warnings,
            "version": self.version,
            "digest": self.digest,
        }

    def to_dict(self, *, include_evidence: bool = True) -> dict[str, Any]:
        return {
            "summary": self.summary(),
            "findings": [finding.to_dict(include_evidence=include_evidence) for finding in self.findings],
            "attack_chains": self.chains,
            "proofs": self.proofs,
            "technologies": self.technologies,
            "waf": self.waf,
            "phases": self.phases,
            "stats": self.stats,
            "methodology": self.methodology,
            "remediation_plan": self.remediation_plan(),
            "appendix": self.appendix,
        }


def _counts(findings: Iterable[Finding]) -> dict[str, int]:
    counts = {severity.value: 0 for severity in Severity}
    total = 0
    for finding in findings:
        counts[finding.severity.value] += 1
        total += 1
    counts["total"] = total
    return counts


def _weight(finding: Finding) -> float:
    weights = {
        Severity.CRITICAL: 10.0,
        Severity.HIGH: 6.0,
        Severity.MEDIUM: 3.0,
        Severity.LOW: 1.0,
        Severity.INFO: 0.1,
    }
    factor = 1.0 if finding.verified else 0.6
    return weights[finding.severity] * factor


def _digest(model: "ReportModel") -> str:
    payload = [
        model.scan_id,
        model.started_at,
        model.title,
        *sorted(finding.id for finding in model.findings),
    ]
    return sha256("|".join(payload))[:32]


def _version() -> str:
    from candix import VERSION

    return VERSION


_METHODOLOGY = [
    "Scope validation: every request is checked against the engagement file before it is sent.",
    "Reconnaissance: breadth-first crawl, robots.txt and sitemap ingestion, JavaScript endpoint extraction, path discovery and technology fingerprinting.",
    "Detection: each detector performs a baseline comparison, injects a payload, and requires a reproducible difference before reporting.",
    "Verification: confirmed findings are re-tested with a structurally different payload or a control request.",
    "Exploitation (opt-in): proof-grade actions only - one bounded file read, one idempotent command, one internal URL.",
    "Evidence handling: every proof is stored with request and response bytes, redacted and hash-chained for integrity.",
]


def select_min_severity(value: str | Severity) -> Severity:
    return Severity.parse(value)


def group_by_detector(findings: Iterable[Finding]) -> dict[str, list[Finding]]:
    grouped: dict[str, list[Finding]] = {}
    for finding in findings:
        grouped.setdefault(finding.detector, []).append(finding)
    return grouped


def remediation_for_finding(finding: Finding) -> Remediation:
    return finding.remediation


def _normalise_targets(values: Any) -> list[dict[str, Any]]:
    """JSON snapshots store bare URLs; the renderers expect target dictionaries."""

    from urllib.parse import urlsplit

    normalised: list[dict[str, Any]] = []
    for value in values:
        if isinstance(value, dict):
            normalised.append(dict(value))
            continue
        text = str(value)
        parts = urlsplit(text)
        normalised.append(
            {
                "url": text,
                "host": parts.hostname or text,
                "port": parts.port or (443 if parts.scheme == "https" else 80),
                "scheme": parts.scheme or "http",
                "auth_context": "anonymous",
            }
        )
    return normalised
