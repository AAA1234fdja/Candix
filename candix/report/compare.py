"""Compare two scans: what was fixed, what persists and what is new."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

from candix.core.clock import humanize_duration
from candix.core.severity import Severity

_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


@dataclass
class FingerprintedFinding:
    key: str
    title: str
    severity: str
    url: str
    method: str
    parameter: str
    verified: bool
    exploited: bool
    fingerprint: str

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> "FingerprintedFinding":
        severity = payload.get("severity")
        if isinstance(severity, dict):
            severity = severity.get("name") or severity.get("value") or "info"
        return cls(
            key=str(payload.get("id") or ""),
            title=str(payload.get("title") or ""),
            severity=str(severity or "info").lower(),
            url=str(payload.get("url") or ""),
            method=str(payload.get("method") or "GET").upper(),
            parameter=str(payload.get("parameter") or ""),
            verified=bool(payload.get("verified")),
            exploited=bool(payload.get("exploited")),
            fingerprint=str(payload.get("dedupe_key") or payload.get("fingerprint") or _fallback_fingerprint(payload)),
        )


def _fallback_fingerprint(payload: dict[str, Any]) -> str:
    parts = [
        str(payload.get("category") or payload.get("detector") or ""),
        str(payload.get("method") or "").upper(),
        str(payload.get("url") or "").split("?")[0],
        str(payload.get("parameter") or "").lower(),
        str(payload.get("title") or "").lower(),
    ]
    return "|".join(parts)


def _index(findings: Iterable[dict[str, Any]]) -> dict[str, FingerprintedFinding]:
    indexed: dict[str, FingerprintedFinding] = {}
    for payload in findings:
        item = FingerprintedFinding.from_payload(payload)
        indexed.setdefault(item.fingerprint, item)
    return indexed


def _rank(severity: str) -> int:
    try:
        return _SEVERITY_ORDER.index(severity.lower())
    except ValueError:
        return len(_SEVERITY_ORDER)


def _counts(items: Iterable[FingerprintedFinding]) -> dict[str, int]:
    counts = {severity: 0 for severity in _SEVERITY_ORDER}
    for item in items:
        counts[item.severity] = counts.get(item.severity, 0) + 1
    counts["total"] = sum(count for severity, count in counts.items() if severity != "total")
    return counts


def compare_snapshots(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    """Return new, resolved and persisting findings between two scan documents."""

    before_index = _index(before.get("findings", []))
    after_index = _index(after.get("findings", []))
    new_keys = [key for key in after_index if key not in before_index]
    resolved_keys = [key for key in before_index if key not in after_index]
    persisting_keys = [key for key in after_index if key in before_index]
    new = sorted((after_index[key] for key in new_keys), key=lambda item: (_rank(item.severity), item.title))
    resolved = sorted((before_index[key] for key in resolved_keys), key=lambda item: (_rank(item.severity), item.title))
    persisting = sorted((after_index[key] for key in persisting_keys), key=lambda item: (_rank(item.severity), item.title))
    before_counts = _counts(before_index.values())
    after_counts = _counts(after_index.values())
    delta = {severity: after_counts.get(severity, 0) - before_counts.get(severity, 0) for severity in _SEVERITY_ORDER}
    return {
        "before": _summarize(before, before_counts),
        "after": _summarize(after, after_counts),
        "counts": {
            "new": len(new),
            "resolved": len(resolved),
            "persisting": len(persisting),
            "before_total": before_counts["total"],
            "after_total": after_counts["total"],
        },
        "delta": delta,
        "new": [item.__dict__ for item in new],
        "resolved": [item.__dict__ for item in resolved],
        "persisting": [item.__dict__ for item in persisting],
        "verdict": _verdict(new, resolved),
    }


def _summarize(document: dict[str, Any], counts: dict[str, int]) -> dict[str, Any]:
    summary = document.get("summary") or {}
    return {
        "scan_id": summary.get("scan_id") or document.get("scan_id") or "",
        "generated_at": summary.get("generated_at") or document.get("generated_at") or "",
        "title": summary.get("title") or document.get("title") or "",
        "risk_score": summary.get("risk_score", 0),
        "counts": {**counts},
    }


def _verdict(new: list[FingerprintedFinding], resolved: list[FingerprintedFinding]) -> str:
    critical_new = [item for item in new if item.severity == "critical"]
    if critical_new:
        return "regressed: new critical findings appeared since the previous scan"
    if len(new) > len(resolved):
        return "regressed: more findings were introduced than fixed"
    if resolved and not new:
        return "improved: every previously reported finding was resolved"
    if resolved:
        return "progressing: findings were fixed, some remain or were introduced"
    if new:
        return "changed: new findings without resolution activity"
    return "unchanged: the same findings persist"


def render_comparison_markdown(comparison: dict[str, Any]) -> str:
    counts = comparison["counts"]
    before = comparison["before"]
    after = comparison["after"]
    lines = ["# Scan comparison", ""]
    lines.append(f"- **verdict:** {comparison['verdict']}")
    lines.append(f"- **previous:** `{before['scan_id']}` ({before['counts']['total']} findings, risk {before['risk_score']})")
    lines.append(f"- **current:** `{after['scan_id']}` ({after['counts']['total']} findings, risk {after['risk_score']})")
    lines.append(f"- **new:** {counts['new']} · **resolved:** {counts['resolved']} · **persisting:** {counts['persisting']}")
    lines.append("")
    lines.append("| Severity | Before | After | Delta |")
    lines.append("|---|---|---|---|")
    for severity in _SEVERITY_ORDER:
        delta = comparison["delta"].get(severity, 0)
        marker = f"+{delta}" if delta > 0 else str(delta)
        lines.append(f"| {severity} | {before['counts'].get(severity, 0)} | {after['counts'].get(severity, 0)} | {marker} |")
    lines.append("")
    for section, heading in (("new", "New findings"), ("resolved", "Resolved findings"), ("persisting", "Still open")):
        items = comparison[section]
        lines.append(f"## {heading} ({len(items)})")
        lines.append("")
        if not items:
            lines.append("_None._")
            lines.append("")
            continue
        for item in items:
            lines.append(f"- **{item['severity'].upper()}** — {item['title']} ({item['method']} {item['url']})")
        lines.append("")
    return "\n".join(lines)


def trend(comparisons: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Collapse a series of comparisons into a per-scan risk timeline."""

    points: list[dict[str, Any]] = []
    for item in comparisons:
        after = item["after"]
        points.append(
            {
                "scan_id": after["scan_id"],
                "generated_at": after["generated_at"],
                "findings": after["counts"]["total"],
                "risk_score": after["risk_score"],
            }
        )
    return points


def summarize_delta(comparison: dict[str, Any]) -> str:
    counts = comparison["counts"]
    if counts["new"] == 0 and counts["resolved"] == 0:
        return "no change between scans"
    return (
        f"{counts['new']} new, {counts['resolved']} resolved, {counts['persisting']} persisting "
        f"({humanize_duration(0) and ''})"
    ).strip()


def severity_of(item: dict[str, Any]) -> Severity:
    return Severity.parse(str(item.get("severity", "info")))
