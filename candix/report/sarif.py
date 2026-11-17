"""SARIF 2.1.0 renderer for code scanning and vulnerability dashboards."""

from __future__ import annotations

import json
from typing import Any

from candix import VERSION
from candix.core.severity import Severity
from candix.report.model import ReportModel

_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "none",
}


def render_sarif(model: ReportModel) -> str:
    rules: list[dict[str, Any]] = []
    rule_index: dict[str, int] = {}
    results: list[dict[str, Any]] = []
    for finding in model.findings:
        rule_id = finding.detector
        if rule_id not in rule_index:
            rule_index[rule_id] = len(rules)
            rules.append(
                {
                    "id": rule_id,
                    "name": finding.detector.replace("-", " ").title(),
                    "shortDescription": {"text": finding.title},
                    "fullDescription": {"text": finding.description or finding.title},
                    "help": {
                        "text": finding.remediation.summary or "See the finding description.",
                        "markdown": _remediation_markdown(finding),
                    },
                    "properties": {
                        "tags": sorted(finding.tags) + list(finding.cwe),
                        "security-severity": f"{finding.effective_score:.1f}",
                        "precision": finding.confidence.value,
                    },
                    "defaultConfiguration": {"level": _LEVEL[finding.severity]},
                }
            )
        result: dict[str, Any] = {
            "ruleId": rule_id,
            "ruleIndex": rule_index[rule_id],
            "level": _LEVEL[finding.severity],
            "message": {"text": f"{finding.title}: {finding.impact or finding.description}"},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": finding.url},
                        "region": {"startLine": 1},
                    }
                }
            ],
            "partialFingerprints": {"candixFinding": finding.fingerprint()},
            "properties": {
                "severity": finding.severity.value,
                "score": finding.effective_score,
                "confidence": finding.confidence.value,
                "verified": finding.verified,
                "exploited": finding.exploited,
                "parameter": finding.parameter,
                "cwe": list(finding.cwe),
                "owasp": list(finding.owasp),
                "findingId": finding.id,
            },
        }
        if finding.remediation.steps:
            result["fixes"] = [
                {
                    "description": {"text": finding.remediation.summary or "Apply the remediation steps."},
                    "artifactChanges": [],
                }
            ]
        results.append(result)
    payload = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Candix",
                        "version": VERSION,
                        "informationUri": "https://github.com/AAA1234fdja/Candix",
                        "rules": rules,
                    }
                },
                "automationDetails": {"id": model.scan_id},
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "startTimeUtc": model.started_at,
                        "endTimeUtc": model.generated_at,
                        "properties": {"profile": model.profile, "riskScore": model.risk_score},
                    }
                ],
                "results": results,
                "properties": {
                    "engagement": model.engagement,
                    "counts": model.counts,
                    "warnings": model.warnings,
                },
            }
        ],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


def _remediation_markdown(finding) -> str:
    lines = [f"**{finding.remediation.summary}**", ""]
    for step in finding.remediation.steps:
        lines.append(f"- {step}")
    if finding.remediation.references:
        lines.append("")
        lines.append("References:")
        for reference in finding.remediation.references:
            lines.append(f"- {reference}")
    return "\n".join(lines)
