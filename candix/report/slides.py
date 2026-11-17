"""Slide-deck export as a Reveal.js compatible markdown document."""

from __future__ import annotations

from typing import Any

from candix.core.clock import humanize_duration
from candix.report.executive import build_executive_view
from candix.report.model import ReportModel

SEVERITY_ORDER = ("critical", "high", "medium", "low")


def _slide(title: str, body: list[str], *, notes: str = "") -> str:
    block = [f"## {title}", ""]
    block.extend(body)
    if notes:
        block.extend(["", f"<!-- {notes} -->"])
    return "\n".join(block)


def render_slides(model: ReportModel, *, max_findings: int = 6) -> str:
    view = build_executive_view(model)
    counts = model.counts
    slides: list[str] = [
        "---",
        f"title: {model.title}",
        "theme: black",
        "transition: slide",
        "---",
        "",
        f"# {model.title}",
        "",
        f"**{model.scan_id}** · {model.generated_at}",
        "",
        (model.engagement or {}).get("client", ""),
        "",
        "---",
        "",
        _slide(
            "Executive summary",
            [
                f"**{view.headline}**",
                "",
                *[f"- {paragraph}" for paragraph in view.narrative[:2]],
            ],
            notes="Keep this slide to the decision the reader must make.",
        ),
        "",
        "---",
        "",
        _slide(
            "Exposure at a glance",
            [
                "| Severity | Count |",
                "|---|---|",
                *[f"| {severity.title()} | {counts.get(severity, 0)} |" for severity in SEVERITY_ORDER],
                f"| **Total** | **{counts.get('total', 0)}** |",
                "",
                f"Verified {len(model.verified_findings)} · exploited {len(model.exploited_findings)} · "
                f"risk score {model.risk_score:.1f} · duration {humanize_duration(model.duration)}",
            ],
        ),
    ]
    if model.chains:
        slides.extend(["", "---", ""])
        body = []
        for chain in model.chains[:4]:
            body.append(f"### {chain.get('name', 'Attack path')}")
            body.append(f"{chain.get('impact', '')}")
            body.append("")
        slides.append(_slide("How the findings combine", body))
    slides.extend(["", "---", ""])
    finding_body: list[str] = []
    for finding in model.findings[:max_findings]:
        finding_body.append(
            f"- **{finding.severity.value.upper()}** · {finding.title} — `{finding.method} {finding.url}`"
        )
    slides.append(_slide("What we found", finding_body or ["_No findings._"]))
    slides.extend(["", "---", ""])
    action_body = []
    for action in view.actions[:5]:
        action_body.append(f"- {action['action']} _({action['priority']}, {action['sla']}, effort {action['effort']})_")
    slides.append(_slide("What to fix first", action_body or ["- Maintain current controls and re-test after changes."]))
    slides.extend(["", "---", ""])
    slides.append(_slide("Limitations", [f"- {warning}" for warning in (model.warnings or ["None recorded."])]))
    slides.extend(["", "---", ""])
    slides.append(_slide(view.outlook.split(":")[0].title(), [view.outlook]))
    slides.extend(["", "---", "", "# Questions", "", "Evidence and full findings are in the accompanying report.", ""])
    return "\n".join(slides)


def slide_count(document: str) -> int:
    return max(1, document.count("\n---"))


def outline(model: ReportModel) -> list[dict[str, Any]]:
    return [
        {"title": "Title", "kind": "cover"},
        {"title": "Executive summary", "kind": "narrative", "findings": model.counts.get("total", 0)},
        {"title": "Exposure at a glance", "kind": "table", "severity": model.counts},
        {"title": "How the findings combine", "kind": "narrative", "chains": len(model.chains)},
        {"title": "What we found", "kind": "list", "findings": min(len(model.findings), 6)},
        {"title": "What to fix first", "kind": "list", "actions": min(len(model.remediation_plan()), 5)},
        {"title": "Limitations", "kind": "list", "warnings": len(model.warnings)},
        {"title": "Questions", "kind": "cover"},
    ]


def speaker_notes(model: ReportModel) -> str:
    view = build_executive_view(model)
    lines = [f"# Speaker notes — {model.title}", ""]
    for index, item in enumerate(outline(model), start=1):
        lines.append(f"## Slide {index}: {item['title']}")
        lines.append("")
        if item["kind"] == "cover":
            lines.append("State the engagement name, the window and who authorised the work.")
        elif item["kind"] == "table":
            lines.append("Read only the critical and high lines; the table is in the handout.")
        elif item["kind"] == "narrative":
            lines.append(view.narrative[min(index - 2, len(view.narrative) - 1)] if view.narrative else view.headline)
        else:
            lines.append("Pick the two items that matter to this audience and stop.")
        lines.append("")
    return "\n".join(lines)
