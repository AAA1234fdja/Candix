"""Markdown renderer."""

from __future__ import annotations

from typing import Any

from candix.core.clock import humanize_duration
from candix.report.model import ReportModel

_SEVERITY_BADGE = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "info": "INFO",
}


def render_markdown(model: ReportModel, *, include_evidence: bool = True, max_evidence_chars: int = 1200) -> str:
    lines: list[str] = []
    add = lines.append
    add(f"# {model.title}")
    add("")
    add(f"**Scan ID:** `{model.scan_id}`  ")
    add(f"**Generated:** {model.generated_at}  ")
    add(f"**Duration:** {humanize_duration(model.duration)}  ")
    add(f"**Profile:** {model.profile}  ")
    add(f"**Risk score:** {model.risk_score}")
    engagement = model.engagement or {}
    if engagement.get("client"):
        add(f"**Client:** {engagement.get('client')}  ")
    if engagement.get("engagement"):
        add(f"**Engagement:** {engagement.get('engagement')}  ")
    if model.digest:
        add(f"**Report digest:** `{model.digest}`")
    add("")
    add("> This report contains security testing results. Treat it as confidential and distribute only to the engagement stakeholders.")
    add("")

    add("## 1. Executive summary")
    add("")
    counts = model.counts
    add(
        f"Candix tested {len(model.targets)} target(s) and identified **{counts.get('total', 0)} findings**: "
        f"{counts.get('critical', 0)} critical, {counts.get('high', 0)} high, {counts.get('medium', 0)} medium, "
        f"{counts.get('low', 0)} low and {counts.get('info', 0)} informational. "
        f"{len(model.verified_findings)} findings were verified and {len(model.exploited_findings)} were exploited "
        "under the rules of engagement."
    )
    add("")
    if model.critical_findings:
        add("The most urgent issues are:")
        add("")
        for finding in model.critical_findings[:5]:
            add(f"- **{finding.title}** — {finding.url} ({finding.severity.value})")
        add("")
    if model.chains:
        add("### Attack paths")
        add("")
        for chain in model.chains[:5]:
            add(f"- **{chain.get('name')}** ({chain.get('severity')}): {chain.get('impact')}")
        add("")

    add("## 2. Findings overview")
    add("")
    add("| Severity | Count |")
    add("|---|---|")
    for severity in ("critical", "high", "medium", "low", "info"):
        add(f"| {_SEVERITY_BADGE[severity]} | {counts.get(severity, 0)} |")
    add(f"| **Total** | **{counts.get('total', 0)}** |")
    add("")
    if model.findings:
        add("| # | Severity | Title | Endpoint | Parameter | Verified |")
        add("|---|---|---|---|---|---|")
        for index, finding in enumerate(model.findings, start=1):
            parameter = f"`{finding.parameter}`" if finding.parameter else "-"
            add(
                f"| {index} | {_SEVERITY_BADGE[finding.severity.value]} | {finding.title} | "
                f"`{finding.method} {finding.url}` | {parameter} | {'yes' if finding.verified else 'no'} |"
            )
        add("")

    add("## 3. Detailed findings")
    add("")
    for index, finding in enumerate(model.findings, start=1):
        add(f"### 3.{index} {finding.title}")
        add("")
        add(f"- **Severity:** {finding.severity.value.upper()} (score {finding.effective_score:.1f})")
        if finding.vector:
            add(f"- **CVSS:** `{finding.vector}`")
        add(f"- **Confidence:** {finding.confidence.value}")
        add(f"- **Category:** {finding.category}")
        add(f"- **Endpoint:** `{finding.method} {finding.url}`")
        if finding.parameter:
            add(f"- **Parameter:** `{finding.parameter}` ({finding.location})")
        add(f"- **Verified:** {'yes' if finding.verified else 'no'}  |  **Exploited:** {'yes' if finding.exploited else 'no'}")
        if finding.cwe:
            add(f"- **CWE:** {', '.join(finding.cwe)}")
        if finding.tags:
            add(f"- **Tags:** {', '.join(sorted(finding.tags))}")
        add("")
        add(finding.description or "No description recorded.")
        add("")
        if finding.impact:
            add(f"**Impact.** {finding.impact}")
            add("")
        if finding.payload:
            add("**Proof payload**")
            add("")
            add("```")
            add(finding.payload[:2000])
            add("```")
            add("")
        if finding.exploited and finding.metadata.get("proof_output"):
            add("**Exploitation output**")
            add("")
            add("```")
            add(str(finding.metadata["proof_output"])[:2000])
            add("```")
            add("")
        if include_evidence and finding.evidence:
            add("**Evidence**")
            add("")
            for evidence in finding.evidence[:4]:
                add(f"- {evidence.kind}: {evidence.summary}" + (f" (`{evidence.path}`)" if evidence.path else ""))
                if evidence.exchange:
                    snippet = evidence.exchange.response_text()[:max_evidence_chars]
                    add("")
                    add("```http")
                    add(snippet.strip())
                    add("```")
                    add("")
        add("**Remediation**")
        add("")
        if finding.remediation.summary:
            add(finding.remediation.summary)
            add("")
        for step in finding.remediation.steps:
            add(f"1. {step}")
        if finding.remediation.verification:
            add("")
            add(f"**Verification:** {finding.remediation.verification}")
        if finding.remediation.references:
            add("")
            add("**References:** " + ", ".join(finding.remediation.references))
        add("")

    add("## 4. Remediation plan")
    add("")
    plan = model.remediation_plan()
    if not plan:
        add("No remediation actions are required.")
        add("")
    for index, item in enumerate(plan, start=1):
        add(f"### 4.{index} {item['summary']}")
        add("")
        add(f"- **Priority:** {item['severity'].upper()} (remediate within {item['sla_days']} days)")
        add(f"- **Effort:** {item['effort']}")
        if item.get("owner_hint"):
            add(f"- **Suggested owner:** {item['owner_hint']}")
        add(f"- **Findings:** {', '.join(f['id'] for f in item['findings'])}")
        add("")
        for step in item["steps"]:
            add(f"- {step}")
        add("")
        if item.get("verification"):
            add(f"**Verification:** {item['verification']}")
            add("")

    add("## 5. Methodology and scope")
    add("")
    add("**Targets**")
    add("")
    for target in model.targets:
        add(f"- {target.get('url')} ({target.get('auth_context', 'anonymous')})")
    add("")
    add("**Method**")
    add("")
    for item in model.methodology:
        add(f"- {item}")
    add("")
    if model.warnings:
        add("**Warnings and limitations**")
        add("")
        for warning in model.warnings:
            add(f"- {warning}")
        add("")

    add("## Appendix")
    add("")
    add("### Technology fingerprint")
    add("")
    technologies = (model.technologies or {}).get("technologies", [])
    if technologies:
        add("| Component | Category | Version | Confidence |")
        add("|---|---|---|---|")
        for technology in technologies:
            add(
                f"| {technology.get('name')} | {technology.get('category')} | "
                f"{technology.get('version') or '-'} | {technology.get('confidence')} |"
            )
    else:
        add("No technology fingerprint was recorded.")
    add("")
    if model.waf and model.waf.get("detected"):
        add(f"**WAF detected:** {model.waf.get('vendor')} (confidence {model.waf.get('confidence')})")
        add("")
    add("### Scan statistics")
    add("")
    for key, value in (model.stats or {}).items():
        add(f"- {key}: {value}")
    add("")
    add(f"Evidence records: {model.evidence_count}")
    add("")
    add("---")
    add("")
    add(f"Generated by Candix {model.version}. Findings are reproducible from the evidence directory; hashes are recorded in the evidence manifest.")
    add("")
    try:
        from candix.playbooks import for_report, render_report_playbooks

        matches = for_report(model.to_dict(include_evidence=False))
        if matches:
            add(render_report_playbooks(matches))
    except Exception:
        pass
    return "\n".join(lines)


def render_finding_markdown(finding: Any, *, include_evidence: bool = False) -> str:
    """Render one finding as a standalone markdown block."""

    severity = finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity)
    lines = [
        f"### {_SEVERITY_BADGE.get(severity, severity.upper())} — {finding.title}",
        "",
        f"- **Endpoint:** `{finding.method} {finding.url}`",
    ]
    if finding.parameter:
        lines.append(f"- **Parameter:** `{finding.parameter}` ({finding.location})")
    if finding.vector:
        lines.append(f"- **CVSS:** `{finding.vector}` ({finding.effective_score:.1f})")
    lines.append(f"- **Detector:** `{finding.detector}` · **confidence:** {finding.confidence.value}")
    lines.append(f"- **Verified:** {'yes' if finding.verified else 'no'} · **exploited:** {'yes' if finding.exploited else 'no'}")
    if finding.cwe:
        lines.append(f"- **CWE:** {', '.join(finding.cwe)}")
    lines.append("")
    if finding.description:
        lines.extend([finding.description, ""])
    if finding.impact:
        lines.extend([f"**Impact.** {finding.impact}", ""])
    if finding.payload:
        lines.extend(["**Proof payload**", "", "```", finding.payload[:2000], "```", ""])
    remediation = finding.remediation
    if remediation.summary or remediation.steps:
        lines.append("**Remediation**")
        lines.append("")
        if remediation.summary:
            lines.append(remediation.summary)
            lines.append("")
        for index, step in enumerate(remediation.steps, start=1):
            lines.append(f"{index}. {step}")
        if remediation.verification:
            lines.append("")
            lines.append(f"_Verification:_ {remediation.verification}")
        lines.append("")
    if include_evidence and finding.evidence:
        lines.append("**Evidence**")
        lines.append("")
        for evidence in finding.evidence[:3]:
            lines.append(f"- {evidence.kind}: {evidence.summary}")
        lines.append("")
    return "\n".join(lines)
