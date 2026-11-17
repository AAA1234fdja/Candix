"""Executive narrative generation.

The executive section answers three questions for a non-technical reader: how
exposed are we, what can an attacker actually do, and what should we fix first.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from candix.core.clock import humanize_duration
from candix.core.severity import Severity
from candix.report.model import ReportModel


@dataclass
class ExecutiveView:
    headline: str
    narrative: list[str]
    metrics: dict[str, Any]
    top_risks: list[dict[str, str]]
    actions: list[dict[str, str]]
    outlook: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "headline": self.headline,
            "narrative": list(self.narrative),
            "metrics": self.metrics,
            "top_risks": list(self.top_risks),
            "actions": list(self.actions),
            "outlook": self.outlook,
        }


def build_executive_view(model: ReportModel) -> ExecutiveView:
    counts = model.counts
    total = counts.get("total", 0)
    critical = counts.get("critical", 0)
    high = counts.get("high", 0)
    exploited = len(model.exploited_findings)
    if critical:
        headline = "Critical weaknesses allow direct compromise and require immediate remediation."
    elif high:
        headline = "Significant weaknesses were confirmed; remediation should start within the current sprint."
    elif total:
        headline = "The assessed surface is broadly sound, with remediation items to schedule."
    else:
        headline = "No weaknesses were identified within the tested scope."
    narrative: list[str] = []
    narrative.append(
        f"Candix assessed {len(model.targets)} target(s) over {humanize_duration(model.duration)} using the "
        f"'{model.profile}' profile. {total} findings were recorded, of which {counts.get('critical', 0)} are "
        f"critical and {high} are high severity. {len(model.verified_findings)} findings were verified by "
        f"reproducing them, and {exploited} were safely exploited to demonstrate business impact."
    )
    if model.chains:
        chains = ", ".join(chain.get("name", "") for chain in model.chains[:3])
        narrative.append(
            f"The findings combine into {len(model.chains)} realistic attack path(s), including: {chains}. "
            "These paths describe how individual defects can be chained, which is how real intrusions usually proceed."
        )
    if exerted := [finding for finding in model.findings if finding.exploited]:
        examples = "; ".join(f"{finding.title} on {finding.url}" for finding in exerted[:3])
        narrative.append(f"Exploitation was demonstrated for: {examples}. Evidence for each proof is included in the appendix.")
    if model.warnings:
        narrative.append(
            "The assessment had limitations: " + " ".join(model.warnings[:3])
        )
    metrics = {
        "targets": len(model.targets),
        "findings": total,
        "critical": critical,
        "high": high,
        "medium": counts.get("medium", 0),
        "low": counts.get("low", 0),
        "verified": len(model.verified_findings),
        "exploited": exploited,
        "risk_score": model.risk_score,
        "evidence_records": model.evidence_count,
        "duration": humanize_duration(model.duration),
    }
    top_risks: list[dict[str, str]] = []
    for finding in model.findings[:5]:
        top_risks.append(
            {
                "title": finding.title,
                "severity": finding.severity.value,
                "url": finding.url,
                "impact": finding.impact or finding.description,
                "id": finding.id,
            }
        )
    actions: list[dict[str, str]] = []
    for item in model.remediation_plan()[:5]:
        actions.append(
            {
                "action": item["summary"],
                "priority": item["severity"],
                "sla": f"{item['sla_days']} days",
                "effort": item["effort"],
                "owner": item.get("owner_hint", "Engineering"),
            }
        )
    if critical or exploited:
        outlook = (
            "Immediate action is required: the confirmed issues are reachable by an unauthenticated attacker in "
            "the tested configuration. Fix critical findings first, then re-test."
        )
    elif high:
        outlook = "The confirmed issues require a scheduled fix and a re-test within the next 30 days."
    else:
        outlook = "Maintain the current controls, address the scheduled findings and repeat the assessment after material changes."
    return ExecutiveView(
        headline=headline,
        narrative=narrative,
        metrics=metrics,
        top_risks=top_risks,
        actions=actions,
        outlook=outlook,
    )


def render_executive_markdown(model: ReportModel) -> str:
    view = build_executive_view(model)
    lines = ["# Executive summary", "", f"**{view.headline}**", ""]
    for paragraph in view.narrative:
        lines.append(paragraph)
        lines.append("")
    lines.append("## Key metrics")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("|---|---|")
    for key, value in view.metrics.items():
        lines.append(f"| {key.replace('_', ' ').title()} | {value} |")
    lines.append("")
    lines.append("## Top risks")
    lines.append("")
    for risk in view.top_risks:
        lines.append(f"- **{risk['severity'].upper()}** — {risk['title']} ({risk['url']})")
    lines.append("")
    lines.append("## Recommended actions")
    lines.append("")
    for action in view.actions:
        lines.append(
            f"1. {action['action']} — priority {action['priority']}, target {action['sla']}, effort {action['effort']}, owner {action['owner']}"
        )
    lines.append("")
    lines.append(view.outlook)
    lines.append("")
    return "\n".join(lines)
