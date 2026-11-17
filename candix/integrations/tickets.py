"""Ticketing integrations: Jira, GitHub issues, GitLab issues and ServiceNow."""

from __future__ import annotations

import re
from typing import Any

from candix.integrations.base import Integration, Notification, IntegrationError, register


def _slug(value: str, limit: int = 60) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9 ._/-]+", "", value or "").strip()
    return cleaned[:limit] or "candix finding"


def _finding_body(notification: Notification, finding: dict[str, Any]) -> str:
    lines = [
        f"*Severity:* {finding.get('severity', 'info')}",
        f"*Endpoint:* `{finding.get('method', 'GET')} {finding.get('url', '')}`",
    ]
    if finding.get("parameter"):
        lines.append(f"*Parameter:* `{finding.get('parameter')}` ({finding.get('location', '')})")
    if finding.get("vector"):
        lines.append(f"*CVSS:* `{finding.get('vector')}`")
    lines.append("")
    lines.append(finding.get("description", ""))
    if finding.get("impact"):
        lines.append("")
        lines.append(f"*Impact:* {finding.get('impact')}")
    remediation = finding.get("remediation") or {}
    if remediation:
        lines.append("")
        lines.append(f"*Remediation:* {remediation.get('summary', '')}")
        for step in remediation.get("steps", [])[:6]:
            lines.append(f"- {step}")
    lines.append("")
    lines.append(f"_Detected by candix during scan `{notification.summary.get('scan_id', '')}`._")
    return "\n".join(lines)


@register("jira")
class JiraIntegration(Integration):
    """Creates one Jira issue per finding (or a single roll-up issue)."""

    def __init__(self, *, issue_type: str = "Bug", per_finding: bool = True, severity_map: dict[str, str] | None = None, **options: Any) -> None:
        super().__init__(**options)
        self.issue_type = issue_type
        self.per_finding = per_finding
        self.severity_map = severity_map or {
            "critical": "Highest",
            "high": "High",
            "medium": "Medium",
            "low": "Low",
            "info": "Lowest",
        }
        self.pending: list[dict[str, Any]] = []

    def target_url(self) -> str:
        base = self.endpoint.rstrip("/")
        if base.endswith("/rest/api/2/issue") or base.endswith("/rest/api/3/issue"):
            return base
        return f"{base}/rest/api/2/issue"

    def request_headers(self) -> dict[str, str]:
        headers = super().request_headers()
        if self.token:
            headers["Authorization"] = f"Basic {self.token}"
        return headers

    def build_payload(self, notification: Notification) -> dict[str, Any]:
        if self.per_finding and notification.findings:
            finding = notification.findings[0]
            return {
                "fields": {
                    "project": {"key": self.project},
                    "summary": _slug(finding.get("title", "candix finding"), 240),
                    "description": _finding_body(notification, finding),
                    "issuetype": {"name": self.issue_type},
                    "labels": ["candix", str(finding.get("severity", "info"))],
                    "priority": {"name": self.severity_map.get(str(finding.get("severity", "info")), "Medium")},
                }
            }
        return {
            "fields": {
                "project": {"key": self.project},
                "summary": _slug(notification.title, 240),
                "description": notification.body,
                "issuetype": {"name": self.issue_type},
                "labels": ["candix", "scan"],
            }
        }

    def send_all(self, notification: Notification) -> list[Any]:
        from candix.integrations.base import IntegrationResult

        if not self.per_finding or not notification.findings:
            return [self.send(notification)]
        results = []
        for finding in notification.findings:
            subset = Notification(
                title=finding.get("title", "candix finding"),
                body=notification.body,
                severity=str(finding.get("severity", "info")),
                summary=notification.summary,
                findings=[finding],
                link=notification.link,
                tags=list(notification.tags),
                metadata=dict(notification.metadata),
            )
            results.append(self.send(subset))
        return results


@register("github")
class GitHubIntegration(Integration):
    """Opens GitHub issues through the REST API."""

    def __init__(self, *, repo: str = "", labels: list[str] | None = None, per_finding: bool = True, **options: Any) -> None:
        super().__init__(**options)
        self.repo = repo or self.project
        self.labels = labels or ["security", "candix"]
        self.per_finding = per_finding

    @property
    def configured(self) -> bool:
        return bool(self.repo and (self.token or self.dry_run))

    def target_url(self) -> str:
        base = self.endpoint.rstrip("/") if self.endpoint else "https://api.github.com"
        return f"{base}/repos/{self.repo}/issues"

    def request_headers(self) -> dict[str, str]:
        headers = super().request_headers()
        headers["Accept"] = "application/vnd.github+json"
        headers["X-GitHub-Api-Version"] = "2022-11-28"
        return headers

    def build_payload(self, notification: Notification) -> dict[str, Any]:
        finding = notification.findings[0] if (self.per_finding and notification.findings) else None
        title = f"[{str(finding.get('severity', '')).upper()}] {finding.get('title')}" if finding else notification.title
        body = _finding_body(notification, finding) if finding else notification.body
        if notification.link:
            body += f"\n\n[Full report]({notification.link})"
        labels = list(self.labels)
        if finding and finding.get("severity"):
            labels.append(f"severity:{finding['severity']}")
        return {"title": _slug(str(title), 240), "body": body[:60000], "labels": labels}

    def send_all(self, notification: Notification) -> list[Any]:
        if not self.per_finding or not notification.findings:
            return [self.send(notification)]
        results = []
        for finding in notification.findings:
            subset = Notification(
                title=finding.get("title", "candix finding"),
                body=notification.body,
                severity=str(finding.get("severity", "info")),
                summary=notification.summary,
                findings=[finding],
                link=notification.link,
                tags=list(notification.tags),
                metadata=dict(notification.metadata),
            )
            results.append(self.send(subset))
        return results


@register("gitlab")
class GitLabIntegration(Integration):
    """Creates GitLab issues for a project."""

    def __init__(self, *, project_id: str = "", labels: str = "security,candix", per_finding: bool = False, **options: Any) -> None:
        super().__init__(**options)
        self.project_id = project_id or self.project
        self.labels = labels
        self.per_finding = per_finding

    def target_url(self) -> str:
        base = self.endpoint.rstrip("/") if self.endpoint else "https://gitlab.com/api/v4"
        return f"{base}/projects/{self.project_id}/issues"

    def build_payload(self, notification: Notification) -> dict[str, Any]:
        finding = notification.findings[0] if (self.per_finding and notification.findings) else None
        title = finding.get("title") if finding else notification.title
        description = _finding_body(notification, finding) if finding else notification.body
        return {
            "title": _slug(str(title), 240),
            "description": description[:60000],
            "labels": self.labels,
        }


@register("servicenow")
class ServiceNowIntegration(Integration):
    """Creates an incident in ServiceNow."""

    def __init__(self, *, table: str = "incident", **options: Any) -> None:
        super().__init__(**options)
        self.table = table

    def target_url(self) -> str:
        base = self.endpoint.rstrip("/") if self.endpoint else ""
        return f"{base}/api/now/table/{self.table}"

    def request_headers(self) -> dict[str, str]:
        headers = super().request_headers()
        headers["Accept"] = "application/json"
        return headers

    def build_payload(self, notification: Notification) -> dict[str, Any]:
        counts = notification.summary.get("counts") or {}
        impact = {"critical": "1", "high": "1", "medium": "2", "low": "3"}.get(notification.severity, "3")
        return {
            "short_description": notification.title[:160],
            "description": notification.body[:4000],
            "category": "security",
            "impact": impact,
            "urgency": impact,
            "caller_id": "candix",
            "work_notes": f"critical={counts.get('critical', 0)} high={counts.get('high', 0)} total={counts.get('total', 0)}",
        }


@register("defectdojo")
class DefectDojoIntegration(Integration):
    """Imports a Candix report into DefectDojo as a generic scan."""

    def __init__(self, *, product_name: str = "", engagement_id: str = "", scan_type: str = "Candix Scan", report: dict[str, Any] | None = None, **options: Any) -> None:
        super().__init__(**options)
        self.product_name = product_name
        self.engagement_id = engagement_id
        self.scan_type = scan_type
        self.report = report or {}

    def target_url(self) -> str:
        base = self.endpoint.rstrip("/") if self.endpoint else ""
        return f"{base}/api/v2/import-scan/" if base else ""

    def build_payload(self, notification: Notification) -> dict[str, Any]:
        return {
            "scan_type": self.scan_type,
            "engagement": self.engagement_id,
            "verified": True,
            "active": True,
            "minimum_severity": "Low",
            "tags": ["candix"],
            "product_name": self.product_name,
            "report": self.report,
        }

    def send(self, notification: Notification) -> Any:
        from candix.integrations.base import IntegrationResult

        if not self.endpoint:
            return IntegrationResult(integration=self.name, ok=False, message="DefectDojo endpoint is not configured")
        if not self.engagement_id:
            return IntegrationResult(integration=self.name, ok=False, message="engagement_id is required")
        return super().send(notification)


def ticket_for(finding: dict[str, Any], notification: Notification) -> dict[str, Any]:
    """Helper used by tests and dry runs to preview a ticket body."""

    if not finding.get("title"):
        raise IntegrationError("finding has no title")
    return {"summary": _slug(finding["title"], 240), "body": _finding_body(notification, finding)}
