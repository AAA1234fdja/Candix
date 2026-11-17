"""Report every agent run with the renderers the scanner already has.

An agent run produces findings that look slightly different from a scan finding:
they carry provenance, a proof flag and the intent that produced them. This
bridge maps both worlds onto :class:`ReportModel` so SARIF, HTML, JUnit or CSV
output needs no agent-specific renderer.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

from candix.core.clock import isoformat
from candix.core.finding import Finding
from candix.core.severity import Severity

_AGENT_FORMATS = ("markdown", "json", "html", "sarif", "csv", "junit", "jsonl", "summary")


@dataclass
class BridgeOptions:
    title: str = "Agent assessment"
    profile: str = "agent"
    include_evidence: bool = True
    min_severity: str = "info"


def _severity(value: Any) -> Severity:
    try:
        return Severity.parse(str(value))
    except Exception:
        return Severity.INFO


def _as_finding(payload: dict[str, Any]) -> Finding:
    data = dict(payload)
    data["severity"] = _severity(data.get("severity"))
    for key in ("evidence", "remediation", "tags"):
        data.setdefault(key, [] if key != "remediation" else {})
    try:
        return Finding.from_dict(data)
    except Exception:
        return Finding(
            title=str(payload.get("title", "agent finding")),
            severity=_severity(payload.get("severity")),
            detector=str(payload.get("detector", "agent")),
            category=str(payload.get("category", "general")),
            url=str(payload.get("url", "")),
            parameter=str(payload.get("parameter", "")),
            description=str(payload.get("description", "")),
            verified=bool(payload.get("verified")),
            exploited=bool(payload.get("exploited")),
        )


def to_model(result: Any, snapshot: dict[str, Any] | None = None, *, options: BridgeOptions | None = None) -> Any:
    """Build a :class:`ReportModel` from an agent ``TaskResult``."""

    from candix.report.model import ReportModel

    options = options or BridgeOptions()
    snapshot = snapshot or {}
    findings = [_as_finding(item) for item in result.findings]
    floor = _severity(options.min_severity)
    findings = [finding for finding in findings if finding.severity.rank >= floor.rank]
    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding.severity.value] = counts.get(finding.severity.value, 0) + 1
    budget = snapshot.get("budget", {}) or {}
    triage = snapshot.get("triage", {}) or {}
    phases = [
        {
            "name": intent.phase.value,
            "intent": intent.title,
            "tool": intent.tool,
            "status": getattr(intent.status, "value", str(intent.status)),
            "result": (intent.result or "")[:200],
        }
        for intent in result.intents
    ]
    coverage = snapshot.get("coverage", {}) or {}
    return ReportModel(
        title=options.title,
        scan_id=str(snapshot.get("id", getattr(result, "run_id", "agent"))),
        generated_at=isoformat(),
        started_at=str(snapshot.get("started_at", "")),
        duration=float(result.duration),
        profile=options.profile,
        engagement=dict(snapshot.get("engagement", {})),
        targets=[{"url": target} for target in snapshot.get("targets", [])],
        findings=findings,
        counts=counts,
        risk_score=float(triage.get("risk", 0.0)),
        chains=list(triage.get("chains", [])),
        proofs=list(result.proofs),
        technologies=dict(snapshot.get("technologies", {})),
        phases=phases,
        stats={
            "agent": {
                "goal": getattr(getattr(result, "goal", ""), "statement", ""),
                "stop_reason": result.stop_reason,
                "intents": result.counts(),
                "tool_calls": budget.get("tool_calls", 0),
                "turns": budget.get("turns", 0),
                "tokens": budget.get("tokens", 0),
                "coverage": coverage,
            },
            "triage": triage,
            "lessons": list(result.lessons),
            "journal": snapshot.get("journal", {}),
        },
        warnings=list(snapshot.get("errors", []))[:20],
        evidence_count=sum(len(finding.evidence) for finding in findings),
        methodology=[
            "scope the engagement and refuse anything outside it",
            "reconnaissance: crawl, fingerprint, map endpoints",
            "detection: run the detector catalogue",
            "verification: re-issue the request that produced each finding",
            "exploitation (when allowed): capture a proof of impact",
            "evidence: bind every claim to a stored exchange",
        ],
        appendix={
            "agent_run": {
                "stop_reason": result.stop_reason,
                "proofs": len(result.proofs),
                "blocked": sum(1 for intent in result.intents if getattr(intent.status, "value", "") == "blocked"),
                "approvals": snapshot.get("approvals", {}),
                "telemetry": snapshot.get("telemetry", {}),
            },
            "scope": list(snapshot.get("scope_directives", [])),
        },
    )


def render(result: Any, fmt: str, snapshot: dict[str, Any] | None = None, *, options: BridgeOptions | None = None) -> str:
    from candix.report.builder import RENDERERS, normalize_format

    name = normalize_format(fmt)
    if name not in RENDERERS:
        raise ValueError(f"unknown report format: {fmt}")
    model = to_model(result, snapshot, options=options)
    return RENDERERS[name].render(model)


def render_many(
    result: Any,
    formats: Iterable[str],
    snapshot: dict[str, Any] | None = None,
    *,
    options: BridgeOptions | None = None,
) -> dict[str, str]:
    output: dict[str, str] = {}
    for fmt in formats:
        try:
            output[fmt] = render(result, fmt, snapshot, options=options)
        except Exception as error:  # a broken renderer must not kill the run
            output[fmt] = f"error: {error}"
    return output


def available_formats() -> list[str]:
    from candix.report.builder import RENDERERS

    return sorted({*RENDERERS, *_AGENT_FORMATS})


def finding_rows(result: Any) -> list[tuple[str, str, str, str]]:
    """Compact rows for a terminal table: severity, title, endpoint, proof."""

    rows = []
    for item in result.findings:
        rows.append(
            (
                str(item.get("severity", "")).upper(),
                str(item.get("title", ""))[:60],
                str(item.get("url", ""))[:48],
                "yes" if item.get("verified") or item.get("exploited") else "no",
            )
        )
    return rows


def proof_markdown(proof: dict[str, Any], *, language: str = "http") -> str:
    """A fenced block a client can paste into a ticket."""

    title = str(proof.get("title") or proof.get("claim") or "proof")
    summary = str(proof.get("summary", ""))
    request = proof.get("request") or {}
    lines = [f"### {title}", "", summary[:600], ""]
    if isinstance(request, dict) and request.get("url"):
        method = str(request.get("method", "GET")).upper()
        lines.extend(["```" + language, f"{method} {request.get('url')} HTTP/1.1"])
        for name, value in (request.get("headers") or {}).items():
            lines.append(f"{name}: {value}")
        if request.get("body"):
            lines.extend(["", str(request.get("body"))[:800]])
        lines.extend(["```", ""])
    return "\n".join(lines)
