"""Reference material embedded in reports so readers interpret scores correctly."""

from __future__ import annotations

from typing import Any

SEVERITY_DEFINITIONS: dict[str, dict[str, str]] = {
    "critical": {
        "definition": "Direct, unauthenticated compromise of the application or its data.",
        "examples": "remote code execution, authentication bypass, SQL injection returning credentials",
        "sla": "72 hours",
        "colour": "#f43f5e",
    },
    "high": {
        "definition": "Serious weakness that enables data access or account takeover with limited preconditions.",
        "examples": "stored cross-site scripting, file read, exposed secrets, IDOR on customer records",
        "sla": "14 days",
        "colour": "#fb7185",
    },
    "medium": {
        "definition": "Weakness that needs user interaction or additional conditions to be exploited.",
        "examples": "reflected scripting behind authentication, missing rate limits, verbose errors",
        "sla": "30 days",
        "colour": "#f59e0b",
    },
    "low": {
        "definition": "Defence-in-depth gap with limited direct impact.",
        "examples": "missing security headers, version disclosure, weak cookie attributes",
        "sla": "90 days",
        "colour": "#38bdf8",
    },
    "info": {
        "definition": "Observation with no demonstrated security impact.",
        "examples": "technology fingerprint, GraphQL introspection, permissive methods",
        "sla": "next review",
        "colour": "#94a3b8",
    },
}

CONFIDENCE_DEFINITIONS: dict[str, str] = {
    "confirmed": "Reproduced with a control request and reviewed manually or by a proof.",
    "likely": "Strong evidence, but one assumption remains unverified.",
    "possible": "Signal detected without a reliable control comparison.",
    "informational": "Collected for inventory, not a security claim.",
}

METRIC_DEFINITIONS: dict[str, str] = {
    "risk_score": "Sum of severity weights adjusted by verification status; use it for trend direction, not as a CVSS replacement.",
    "cvss": "CVSS 3.1 base score computed from the vector recorded on the finding.",
    "verified": "The finding was reproduced by the tool with a control request or a proof of exploitation.",
    "exploited": "A permitted technique demonstrated impact and produced evidence.",
    "evidence_records": "Number of request/response artefacts stored with hashes for later review.",
}

CWE_SUMMARIES: dict[str, str] = {
    "CWE-20": "Improper input validation",
    "CWE-22": "Path traversal",
    "CWE-78": "OS command injection",
    "CWE-79": "Cross-site scripting",
    "CWE-89": "SQL injection",
    "CWE-94": "Code injection",
    "CWE-200": "Exposure of sensitive information",
    "CWE-287": "Improper authentication",
    "CWE-352": "Cross-site request forgery",
    "CWE-384": "Session fixation",
    "CWE-434": "Unrestricted upload of dangerous file type",
    "CWE-502": "Deserialization of untrusted data",
    "CWE-611": "XML external entity",
    "CWE-614": "Sensitive cookie without Secure attribute",
    "CWE-770": "Allocation without limits (rate limiting)",
    "CWE-918": "Server-side request forgery",
    "CWE-942": "Permissive cross-domain policy",
    "CWE-1004": "Sensitive cookie without HttpOnly",
    "CWE-1021": "Improper restriction of rendered UI layers",
    "CWE-1336": "Template injection",
}


def severity_table() -> list[dict[str, str]]:
    return [
        {
            "severity": name,
            "definition": item["definition"],
            "examples": item["examples"],
            "sla": item["sla"],
        }
        for name, item in SEVERITY_DEFINITIONS.items()
    ]


def describe_metric(name: str) -> str:
    return METRIC_DEFINITIONS.get(name, "")


def cwe_label(identifier: str) -> str:
    return CWE_SUMMARIES.get(identifier.upper(), "")


def annotate_cwes(values: Any) -> list[dict[str, str]]:
    result: list[dict[str, str]] = []
    for value in values or ():
        identifier = str(value).upper()
        result.append({"id": identifier, "summary": cwe_label(identifier)})
    return result


def render_markdown() -> str:
    lines = ["## Glossary", "", "| Severity | Meaning | Examples | Target fix time |", "|---|---|---|---|"]
    for row in severity_table():
        lines.append(f"| {row['severity'].title()} | {row['definition']} | {row['examples']} | {row['sla']} |")
    lines.extend(["", "### Confidence levels", ""])
    for name, definition in CONFIDENCE_DEFINITIONS.items():
        lines.append(f"- **{name.title()}** — {definition}")
    lines.extend(["", "### Metrics", ""])
    for name, definition in METRIC_DEFINITIONS.items():
        lines.append(f"- **{name.replace('_', ' ')}** — {definition}")
    return "\n".join(lines)


def html_rows() -> str:
    """Small HTML fragment reused by custom dashboards."""

    import html as html_module

    rows = []
    for name, item in SEVERITY_DEFINITIONS.items():
        rows.append(
            "<tr>"
            f"<td><span style='color:{item['colour']};font-weight:700'>{html_module.escape(name.upper())}</span></td>"
            f"<td>{html_module.escape(item['definition'])}</td>"
            f"<td>{html_module.escape(item['examples'])}</td>"
            f"<td>{html_module.escape(item['sla'])}</td>"
            "</tr>"
        )
    return "\n".join(rows)
