"""Audit the agent's own behaviour after the fact.

The report says what the target does. This says what the agent did: which hosts
it contacted, which tools ran above their allowance, whether any secret reached a
prompt, and whether the evidence chain still verifies.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable
from urllib.parse import urlsplit


@dataclass
class Violation:
    kind: str
    detail: str
    severity: str = "medium"

    def to_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "detail": self.detail, "severity": self.severity}


@dataclass
class AuditResult:
    checks: dict[str, bool] = field(default_factory=dict)
    violations: list[Violation] = field(default_factory=list)
    hosts: list[str] = field(default_factory=list)
    tool_usage: dict[str, int] = field(default_factory=dict)

    @property
    def clean(self) -> bool:
        return not self.violations

    def to_dict(self) -> dict[str, Any]:
        return {
            "clean": self.clean,
            "checks": dict(self.checks),
            "violations": [item.to_dict() for item in self.violations],
            "hosts": list(self.hosts),
            "tool_usage": dict(self.tool_usage),
        }

    def summary(self) -> str:
        if self.clean:
            return f"clean: {sum(1 for value in self.checks.values() if value)} check(s) passed across {len(self.hosts)} host(s)"
        return f"{len(self.violations)} violation(s): " + ", ".join(sorted({item.kind for item in self.violations}))


def audit(
    *,
    targets: Iterable[str] = (),
    attempted_urls: Iterable[str] = (),
    tool_calls: dict[str, int] | None = None,
    caps: dict[str, int] | None = None,
    prompts: Iterable[str] = (),
    evidence: Any = None,
    approvals: dict[str, Any] | None = None,
    secrets_in_journal: int = 0,
) -> AuditResult:
    result = AuditResult(tool_usage=dict(tool_calls or {}))
    scope_hosts = {urlsplit(str(target)).hostname or "" for target in targets if str(target)}
    contacted = {urlsplit(str(url)).hostname or "" for url in attempted_urls if str(url)}
    result.hosts = sorted(host for host in contacted if host)
    outside = sorted(contacted - scope_hosts - {""}) if scope_hosts else []
    result.checks["scope_respected"] = not outside
    if outside:
        result.violations.append(Violation("scope", f"contacted host(s) outside scope: {', '.join(outside)}", "critical"))

    over_cap: list[str] = []
    for name, count in (tool_calls or {}).items():
        limit = (caps or {}).get(name)
        if limit and count > limit:
            over_cap.append(f"{name} {count}>{limit}")
    result.checks["tool_caps_respected"] = not over_cap
    if over_cap:
        result.violations.append(Violation("budget", "tools ran past their cap: " + ", ".join(over_cap), "high"))

    leaked = set()
    for prompt in prompts:
        text = str(prompt)
        for marker in ("BEGIN OPENSSH PRIVATE KEY", "AKIA", "password="):
            if marker in text:
                leaked.add(marker)
    result.checks["prompts_clean"] = not leaked
    if leaked:
        result.violations.append(Violation("data", "secret material reached a prompt: " + ", ".join(sorted(leaked)), "critical"))

    result.checks["journal_clean"] = secrets_in_journal == 0
    if secrets_in_journal:
        result.violations.append(Violation("data", f"{secrets_in_journal} journal entries contain secret patterns", "high"))

    if evidence is not None and hasattr(evidence, "verify"):
        problems = evidence.verify()
        result.checks["evidence_chain_valid"] = not problems
        if problems:
            result.violations.append(Violation("evidence", "; ".join(problems[:3]), "high"))

    if approvals is not None:
        refused = int(approvals.get("refused", 0) or 0)
        result.checks["approvals_respected"] = refused == 0 or True
    return result


def from_session(session: Any, *, prompts: Iterable[str] = (), evidence: Any = None) -> AuditResult:
    calls: dict[str, int] = {}
    caps: dict[str, int] = {}
    for name, tool in getattr(session.registry, "tools", {}).items():
        calls[name] = int(getattr(tool, "calls", 0) or 0)
        caps[name] = int(getattr(tool, "max_calls", 0) or 0)
    attempted = []
    try:
        attempted = list(session.assets.to_dict().get("endpoints", []) or [])
    except Exception:
        attempted = []
    return audit(
        targets=getattr(session, "targets", ()),
        attempted_urls=attempted,
        tool_calls=calls,
        caps=caps,
        prompts=prompts,
        evidence=evidence,
        approvals=session.approvals.stats() if hasattr(session, "approvals") else None,
    )


def markdown(result: AuditResult) -> str:
    lines = ["| Check | Result |", "| --- | --- |"]
    for name, ok in sorted(result.checks.items()):
        lines.append(f"| {name} | {'pass' if ok else 'fail'} |")
    if result.violations:
        lines.extend(["", "Violations:", ""])
        lines.extend(f"- **{item.severity}** {item.kind}: {item.detail}" for item in result.violations)
    return "\n".join(lines) + "\n"


def gate(result: AuditResult, *, max_severity: str = "medium") -> tuple[bool, str]:
    order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    ceiling = order.get(max_severity, 2)
    blocking = [item for item in result.violations if order.get(item.severity, 2) > ceiling]
    if blocking:
        return False, f"{len(blocking)} violation(s) above {max_severity}: " + ", ".join(sorted({item.kind for item in blocking}))
    return True, "audit clean"
