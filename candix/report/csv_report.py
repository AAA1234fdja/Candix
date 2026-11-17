"""CSV renderer for spreadsheet consumers and ticketing imports."""

from __future__ import annotations

import csv
import io

from candix.report.model import ReportModel

_COLUMNS = (
    "id",
    "severity",
    "score",
    "confidence",
    "verified",
    "exploited",
    "title",
    "category",
    "cwe",
    "method",
    "url",
    "parameter",
    "location",
    "detector",
    "remediation",
    "sla_days",
)


def render_csv(model: ReportModel) -> str:
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=list(_COLUMNS), extrasaction="ignore")
    writer.writeheader()
    for finding in model.findings:
        writer.writerow(
            {
                "id": finding.id,
                "severity": finding.severity.value,
                "score": f"{finding.effective_score:.1f}",
                "confidence": finding.confidence.value,
                "verified": "yes" if finding.verified else "no",
                "exploited": "yes" if finding.exploited else "no",
                "title": finding.title,
                "category": finding.category,
                "cwe": " ".join(finding.cwe),
                "method": finding.method,
                "url": finding.url,
                "parameter": finding.parameter,
                "location": finding.location,
                "detector": finding.detector,
                "remediation": finding.remediation.summary,
                "sla_days": finding.severity.sla_days,
            }
        )
    return buffer.getvalue()
