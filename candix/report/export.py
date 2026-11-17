"""Operational exports: remediation tracker, asset summary and shareable tables."""

from __future__ import annotations

import csv
import io
import json
from typing import Any, Iterable

from candix.report.model import ReportModel

TRACKER_COLUMNS = (
    "finding_id",
    "severity",
    "title",
    "endpoint",
    "parameter",
    "cwe",
    "cvss",
    "verified",
    "exploited",
    "owner",
    "status",
    "sla_days",
    "due_date",
    "remediation",
)


def remediation_tracker(model: ReportModel) -> list[dict[str, Any]]:
    from datetime import datetime, timedelta

    today = datetime.utcnow().date()
    rows: list[dict[str, Any]] = []
    for finding in model.findings:
        sla = {"critical": 3, "high": 14, "medium": 30, "low": 90, "info": 180}.get(finding.severity.value, 30)
        rows.append(
            {
                "finding_id": finding.id,
                "severity": finding.severity.value,
                "title": finding.title,
                "endpoint": f"{finding.method} {finding.url}",
                "parameter": finding.parameter,
                "cwe": ",".join(finding.cwe),
                "cvss": f"{finding.effective_score:.1f}",
                "verified": "yes" if finding.verified else "no",
                "exploited": "yes" if finding.exploited else "no",
                "owner": finding.remediation.owner_hint or "engineering",
                "status": "open",
                "sla_days": sla,
                "due_date": (today + timedelta(days=sla)).isoformat(),
                "remediation": finding.remediation.summary,
            }
        )
    return rows


def tracker_csv(model: ReportModel) -> str:
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=TRACKER_COLUMNS, extrasaction="ignore")
    writer.writeheader()
    for row in remediation_tracker(model):
        writer.writerow(row)
    return buffer.getvalue()


def tracker_json(model: ReportModel) -> str:
    return json.dumps({"scan_id": model.scan_id, "rows": remediation_tracker(model)}, indent=2, sort_keys=True)


def asset_summary(model: ReportModel) -> list[dict[str, Any]]:
    grouped: dict[str, dict[str, Any]] = {}
    for finding in model.findings:
        entry = grouped.setdefault(
            finding.url.split("?")[0],
            {"endpoint": finding.url.split("?")[0], "findings": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "max_cvss": 0.0},
        )
        entry["findings"] += 1
        entry[finding.severity.value] = entry.get(finding.severity.value, 0) + 1
        entry["max_cvss"] = max(entry["max_cvss"], round(finding.effective_score, 1))
    return sorted(grouped.values(), key=lambda item: (-item["critical"], -item["high"], -item["max_cvss"]))


def asset_table(model: ReportModel) -> str:
    lines = ["| Endpoint | Findings | Critical | High | Medium | Max CVSS |", "|---|---|---|---|---|---|"]
    for row in asset_summary(model):
        lines.append(
            f"| `{row['endpoint']}` | {row['findings']} | {row['critical']} | {row['high']} | {row['medium']} | {row['max_cvss']} |"
        )
    return "\n".join(lines)


def owner_breakdown(model: ReportModel) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in remediation_tracker(model):
        counts[row["owner"]] = counts.get(row["owner"], 0) + 1
    return dict(sorted(counts.items(), key=lambda pair: -pair[1]))


def evidence_manifest(model: ReportModel) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for finding in model.findings:
        for evidence in finding.evidence:
            entries.append(
                {
                    "finding_id": finding.id,
                    "kind": evidence.kind,
                    "summary": evidence.summary,
                    "path": evidence.path,
                    "sha256": evidence.sha256,
                }
            )
    return entries


def export_bundle(model: ReportModel, directory: str) -> dict[str, str]:
    from pathlib import Path

    target = Path(directory)
    target.mkdir(parents=True, exist_ok=True)
    written: dict[str, str] = {}
    tracker = target / f"tracker-{model.scan_id}.csv"
    tracker.write_text(tracker_csv(model), encoding="utf-8")
    written["tracker_csv"] = str(tracker)
    assets = target / f"assets-{model.scan_id}.md"
    assets.write_text(f"# Assets\n\n{asset_table(model)}\n", encoding="utf-8")
    written["assets_markdown"] = str(assets)
    manifest = target / f"evidence-{model.scan_id}.json"
    manifest.write_text(json.dumps(evidence_manifest(model), indent=2), encoding="utf-8")
    written["evidence_manifest"] = str(manifest)
    return written


def summarize_rows(rows: Iterable[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {"open": 0, "critical": 0, "high": 0}
    for row in rows:
        counts["open"] += 1 if row.get("status") == "open" else 0
        severity = str(row.get("severity", ""))
        if severity in {"critical", "high"}:
            counts[severity] += 1
    return counts
