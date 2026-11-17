"""Finding verification: re-issue the request that produced a finding."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from candix.agent.tools import ToolContext, ToolRegistry, ToolResult


@dataclass
class VerificationResult:
    finding_id: str
    url: str
    status: str = "unknown"
    evidence: str = ""
    attempts: int = 0
    note: str = ""
    at: float = field(default_factory=time.time)

    @property
    def reproduced(self) -> bool:
        return self.status == "reproduced"

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "url": self.url,
            "status": self.status,
            "evidence": self.evidence[:1500],
            "attempts": self.attempts,
            "note": self.note,
        }


class Verifier:
    """Confirms a finding by repeating the request and comparing shape."""

    def __init__(self, registry: ToolRegistry, context: ToolContext, *, attempts: int = 2, max_findings: int = 20) -> None:
        self.registry = registry
        self.context = context
        self.attempts = max(1, attempts)
        self.max_findings = max_findings

    def verify(self, finding: dict[str, Any]) -> VerificationResult:
        url = str(finding.get("url") or "")
        method = str(finding.get("method") or "GET").upper()
        identifier = str(finding.get("id") or finding.get("title") or url)
        if not url:
            return VerificationResult(identifier, url, status="skipped", note="finding has no URL")
        decision = self.context.guard.check_url(url, method=method)
        if not decision.allowed:
            return VerificationResult(identifier, url, status="blocked", note=decision.reason)
        statuses: list[int] = []
        bodies: list[str] = []
        for _attempt in range(self.attempts):
            result: ToolResult = self.registry.execute("http.request", {"url": url, "method": method, "max_bytes": 8000}, self.context)
            if not result.ok:
                return VerificationResult(identifier, url, status="error", note=result.error, attempts=len(statuses) + 1)
            statuses.append(int(result.data.get("status", 0) or 0))
            bodies.append(str(result.data.get("body", "")))
        stable = len(set(statuses)) == 1 and len(set(len(body) for body in bodies)) == 1
        status = "reproduced" if stable and statuses and statuses[0] < 500 else "not_reproduced"
        note = "" if stable else "response changed between attempts"
        return VerificationResult(
            identifier,
            url,
            status=status,
            evidence=bodies[0][:1200],
            attempts=len(statuses),
            note=note,
        )

    def verify_all(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for finding in findings[: self.max_findings]:
            results.append(self.verify(finding).to_dict())
        return results
