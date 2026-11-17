"""Compare two runs: what is new, what was fixed, what regressed."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from candix.core.severity import Severity


def _key(finding: dict[str, Any]) -> str:
    parts = [
        str(finding.get("category", "")).lower(),
        str(finding.get("title", "")).lower(),
        str(finding.get("url", "")).lower(),
        str(finding.get("parameter", "")).lower(),
    ]
    return "|".join(parts)


@dataclass
class Change:
    kind: str
    finding: dict[str, Any]
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "title": str(self.finding.get("title", "")),
            "severity": str(self.finding.get("severity", "")),
            "url": str(self.finding.get("url", "")),
            "detail": self.detail,
        }


@dataclass
class Diff:
    new: list[Change] = field(default_factory=list)
    fixed: list[Change] = field(default_factory=list)
    persisting: list[Change] = field(default_factory=list)
    escalated: list[Change] = field(default_factory=list)
    downgraded: list[Change] = field(default_factory=list)

    @property
    def changed(self) -> bool:
        return bool(self.new or self.fixed or self.escalated or self.downgraded)

    def to_dict(self) -> dict[str, Any]:
        return {
            "new": [change.to_dict() for change in self.new],
            "fixed": [change.to_dict() for change in self.fixed],
            "persisting": [change.to_dict() for change in self.persisting],
            "escalated": [change.to_dict() for change in self.escalated],
            "downgraded": [change.to_dict() for change in self.downgraded],
            "counts": self.counts(),
        }

    def counts(self) -> dict[str, int]:
        return {
            "new": len(self.new),
            "fixed": len(self.fixed),
            "persisting": len(self.persisting),
            "escalated": len(self.escalated),
            "downgraded": len(self.downgraded),
        }

    def summary(self) -> str:
        counts = self.counts()
        if not self.changed:
            return "no change between runs"
        return ", ".join(f"{value} {name}" for name, value in counts.items() if value) or "no change"

    def markdown(self) -> str:
        lines = ["| Change | Severity | Finding | Endpoint |", "| --- | --- | --- | --- |"]
        for label, changes in (
            ("new", self.new),
            ("escalated", self.escalated),
            ("fixed", self.fixed),
            ("downgraded", self.downgraded),
            ("persisting", self.persisting),
        ):
            for change in changes:
                lines.append(
                    f"| {label} | {change.finding.get('severity', '')} | "
                    f"{str(change.finding.get('title', ''))[:50]} | {str(change.finding.get('url', ''))[:40]} |"
                )
        return "\n".join(lines) + "\n"


def _rank(finding: dict[str, Any]) -> int:
    try:
        return Severity.parse(str(finding.get("severity", "info"))).rank
    except Exception:
        return 0


def compare(before: Iterable[dict[str, Any]], after: Iterable[dict[str, Any]]) -> Diff:
    first = {(_key(finding)): finding for finding in before}
    second = {(_key(finding)): finding for finding in after}
    diff = Diff()
    for key, finding in second.items():
        if key not in first:
            diff.new.append(Change("new", finding))
            continue
        old = first[key]
        old_rank, new_rank = _rank(old), _rank(finding)
        if new_rank > old_rank:
            diff.escalated.append(Change("escalated", finding, f"{old.get('severity')} -> {finding.get('severity')}"))
        elif new_rank < old_rank:
            diff.downgraded.append(Change("downgraded", finding, f"{old.get('severity')} -> {finding.get('severity')}"))
        else:
            diff.persisting.append(Change("persisting", finding))
    for key, finding in first.items():
        if key not in second:
            diff.fixed.append(Change("fixed", finding))
    return diff


def from_results(before: Any, after: Any) -> Diff:
    return compare(getattr(before, "findings", []), getattr(after, "findings", []))


def from_files(before: str | Path, after: str | Path) -> Diff:
    def load(path: str | Path) -> list[dict[str, Any]]:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        if isinstance(payload, list):
            return [item for item in payload if isinstance(item, dict)]
        if isinstance(payload, dict):
            for key in ("findings", "results"):
                items = payload.get(key)
                if isinstance(items, list):
                    return [item for item in items if isinstance(item, dict)]
        return []

    return compare(load(before), load(after))


def regression_gate(diff: Diff, *, fail_on: str = "high", allow_new: int = 0) -> tuple[bool, str]:
    """Decide whether a re-run should fail a CI job."""

    try:
        floor = Severity.parse(fail_on)
    except Exception:
        floor = Severity.HIGH
    blocking = [
        change for change in diff.new + diff.escalated if _rank(change.finding) >= floor.rank
    ]
    if blocking:
        return False, f"{len(blocking)} new or escalated finding(s) at or above {floor.value}"
    if len(diff.new) > allow_new:
        return False, f"{len(diff.new)} new finding(s) exceed the allowance of {allow_new}"
    return True, "no regressions"


def badges(diff: Diff) -> dict[str, str]:
    counts = diff.counts()
    return {
        "new": str(counts["new"]),
        "fixed": str(counts["fixed"]),
        "persisting": str(counts["persisting"]),
        "total": str(sum(counts.values())),
    }


def summary_table(diff: Diff) -> str:
    rows = ["change,count"]
    for name, value in diff.counts().items():
        rows.append(f"{name},{value}")
    return "\n".join(rows) + "\n"


def significant(diff: Diff, *, limit: int = 10) -> list[Change]:
    ordered = sorted(diff.new + diff.escalated + diff.downgraded + diff.fixed, key=lambda change: -_rank(change.finding))
    return ordered[:limit]


def from_report(path: str | Path) -> list[dict[str, Any]]:
    """Read findings from an agent JSON document or a bare findings list."""

    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        findings = payload.get("findings")
        if isinstance(findings, list):
            return [item for item in findings if isinstance(item, dict)]
    return []


def exit_code(diff: "Diff", *, fail_on: str = "high", allow_new: int = 0) -> int:
    from candix.agent.triage import severity_rank

    threshold = severity_rank(fail_on)
    blocking = [
        change
        for change in [*diff.new, *diff.escalated]
        if severity_rank(str(change.finding.get("severity", "info"))) >= threshold
    ]
    return 10 if len(blocking) > allow_new else 0
