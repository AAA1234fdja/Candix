"""JUnit XML export so CI dashboards show findings as failed checks."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Any

from candix.report.model import ReportModel

SUITE_NAME = "candix.findings"


def render_junit(model: ReportModel, *, fail_on: str = "high") -> str:
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    threshold = order.get(fail_on.lower(), 1)
    findings = list(model.findings)
    failures = [finding for finding in findings if order.get(finding.severity.value, 5) <= threshold]
    suite = ET.Element(
        "testsuite",
        {
            "name": SUITE_NAME,
            "tests": str(max(1, len(findings))),
            "failures": str(len(failures)),
            "errors": "0",
            "skipped": "0",
            "time": f"{model.duration:.3f}",
            "timestamp": model.generated_at or "",
            "hostname": _target_host(model.targets),
        },
    )
    properties = ET.SubElement(suite, "properties")
    for key, value in (
        ("scan_id", model.scan_id),
        ("profile", model.profile),
        ("risk_score", str(model.risk_score)),
        ("verified", str(len(model.verified_findings))),
        ("exploited", str(len(model.exploited_findings))),
        ("digest", model.digest),
    ):
        ET.SubElement(properties, "property", {"name": key, "value": value})
    if not findings:
        case = ET.SubElement(suite, "testcase", {"name": "no findings", "classname": SUITE_NAME, "time": "0"})
        ET.SubElement(case, "system-out").text = "Candix completed without findings in scope."
    for finding in findings:
        testcase = ET.SubElement(
            suite,
            "testcase",
            {
                "name": f"[{finding.severity.value}] {finding.title}",
                "classname": f"candix.{finding.category}",
                "time": "0",
            },
        )
        if finding in failures:
            failure = ET.SubElement(
                testcase,
                "failure",
                {"message": f"{finding.severity.value}: {finding.title}", "type": finding.category},
            )
            failure.text = _failure_text(finding)
        if finding.payload:
            ET.SubElement(testcase, "system-out").text = _bounded(finding.payload, 2000)
    if model.warnings:
        ET.SubElement(suite, "system-err").text = "\n".join(model.warnings[:20])
    _indent(suite)
    return ET.tostring(suite, encoding="unicode")


def _failure_text(finding: Any) -> str:
    lines = [
        f"endpoint: {finding.method} {finding.url}",
        f"severity: {finding.severity.value}",
        f"confidence: {finding.confidence.value}",
        f"verified: {finding.verified}",
        f"exploited: {finding.exploited}",
    ]
    if finding.parameter:
        lines.append(f"parameter: {finding.parameter} ({finding.location})")
    if finding.vector:
        lines.append(f"cvss: {finding.vector} ({finding.effective_score:.1f})")
    lines.append("")
    lines.append(finding.description)
    if finding.impact:
        lines.append("")
        lines.append(f"impact: {finding.impact}")
    if finding.remediation.summary:
        lines.append("")
        lines.append(f"remediation: {finding.remediation.summary}")
        for step in finding.remediation.steps[:5]:
            lines.append(f"  - {step}")
    return _bounded("\n".join(lines), 8000)


def _bounded(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[:limit] + "... [truncated]"


def _indent(element: ET.Element, level: int = 0) -> None:
    padding = "\n" + "  " * level
    if len(element):
        if not element.text or not element.text.strip():
            element.text = padding + "  "
        for child in element:
            _indent(child, level + 1)
        if not child.tail or not child.tail.strip():
            child.tail = padding
    if level and (not element.tail or not element.tail.strip()):
        element.tail = padding


def junit_summary(model: ReportModel, *, fail_on: str = "high") -> dict[str, Any]:
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    threshold = order.get(fail_on.lower(), 1)
    failing = [finding for finding in model.findings if order.get(finding.severity.value, 5) <= threshold]
    return {
        "suite": SUITE_NAME,
        "tests": len(model.findings),
        "failures": len(failing),
        "exit_code": 1 if failing else 0,
        "threshold": fail_on,
    }


def parse_junit(document: str) -> dict[str, Any]:
    root = ET.fromstring(document)
    return {
        "name": root.get("name", ""),
        "tests": int(root.get("tests", 0) or 0),
        "failures": int(root.get("failures", 0) or 0),
        "cases": [case.get("name", "") for case in root.findall("testcase")][:50],
    }


def _target_host(targets: Any) -> str:
    """Targets are stored as URL strings in JSON snapshots but dicts in memory."""

    if not targets:
        return ""
    first = targets[0]
    if isinstance(first, dict):
        return str(first.get("host", "") or first.get("url", ""))
    from urllib.parse import urlsplit

    text = str(first)
    return urlsplit(text).hostname or text
