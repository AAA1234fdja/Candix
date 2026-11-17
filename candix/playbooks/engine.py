"""Map findings and reports onto playbooks."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from candix.playbooks.catalog import Playbook, playbook

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_TITLE_HINTS = (
    "command injection",
    "sql injection",
    "cross-site scripting",
    "template injection",
    "path traversal",
    "file read",
    "server-side request forgery",
    "cross-site request",
    "authentication",
    "exposed",
    "disclosure",
    "deserial",
    "smuggl",
)


@dataclass
class PlaybookMatch:
    playbook: Playbook
    finding_ids: list[str]
    severity: str
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "playbook": self.playbook.to_dict(),
            "finding_ids": list(self.finding_ids),
            "severity": self.severity,
            "reason": self.reason,
        }


class _LightFinding:
    def __init__(self, payload: Mapping[str, Any]) -> None:
        severity = payload.get("severity", "info")
        if isinstance(severity, Mapping):
            severity = severity.get("name", "info")
        self.category = str(payload.get("category", "") or payload.get("detector", "")).lower()
        self.detector = str(payload.get("detector", "")).lower()
        self.title = str(payload.get("title", ""))
        self.severity = str(severity).lower()
        self.tags = tuple(payload.get("tags") or ())
        self.url = str(payload.get("url", ""))
        self.parameter = str(payload.get("parameter", ""))


def _keys_for(finding: Any) -> list[str]:
    keys: list[str] = []
    for attribute in ("category", "detector"):
        value = getattr(finding, attribute, "")
        if value:
            keys.append(str(value).lower())
    for tag in getattr(finding, "tags", ()) or ():
        keys.append(str(tag).lower())
    title = str(getattr(finding, "title", "")).lower()
    for phrase in _TITLE_HINTS:
        if phrase in title:
            keys.append(phrase.split()[0].rstrip("-"))
    return keys


def for_finding(finding: Any) -> Playbook | None:
    for key in _keys_for(finding):
        match = playbook(key)
        if match is not None:
            return match
    return None


def _order(severity: str) -> int:
    return _SEVERITY_ORDER.get(severity.lower(), 5)


def _worst(left: str, right: str) -> str:
    return left if _order(left) <= _order(right) else right


def for_report(report: Mapping[str, Any]) -> list[PlaybookMatch]:
    matches: dict[str, PlaybookMatch] = {}
    for payload in report.get("findings") or []:
        finding = _LightFinding(payload)
        match = for_finding(finding)
        if match is None:
            continue
        existing = matches.get(match.id)
        identifier = str(payload.get("id", ""))
        if existing is None:
            matches[match.id] = PlaybookMatch(
                playbook=match,
                finding_ids=[identifier],
                severity=finding.severity,
                reason=f"{finding.category or match.category} finding",
            )
        else:
            existing.finding_ids.append(identifier)
            existing.severity = _worst(existing.severity, finding.severity)
    return sorted(matches.values(), key=lambda item: (_order(item.severity), item.playbook.id))


def render_playbook_markdown(match: PlaybookMatch) -> str:
    book = match.playbook
    lines = [
        f"### Playbook: {book.title}",
        "",
        f"**Objective.** {book.objective}",
        "",
        f"**Applies to.** {', '.join(match.finding_ids) or 'this report'} (`{match.severity}`)",
        "",
        "**Prerequisites**",
        "",
    ]
    lines.extend(f"- {item}" for item in book.prerequisites)
    lines.extend(["", "**Steps**", ""])
    lines.extend(f"{index}. {step}" for index, step in enumerate(book.steps, start=1))
    lines.extend(["", "**Confirm before reporting**", ""])
    lines.extend(f"- {item}" for item in book.confirm)
    lines.extend(["", f"**Impact.** {book.impact}", "", "**Detection opportunities**", ""])
    lines.extend(f"- {item}" for item in book.detections)
    if book.references:
        lines.extend(["", "**References**", ""])
        lines.extend(f"- {item}" for item in book.references)
    return "\n".join(lines)


def render_report_playbooks(matches: Iterable[PlaybookMatch]) -> str:
    materialized = list(matches)
    blocks = ["## Playbooks", ""]
    if not materialized:
        blocks.append("_No playbook matched the reported findings._")
        return "\n".join(blocks)
    for match in materialized:
        blocks.append(render_playbook_markdown(match))
        blocks.append("")
    return "\n".join(blocks)


def summarize_matches(matches: Iterable[PlaybookMatch]) -> dict[str, Any]:
    materialized = list(matches)
    return {
        "count": len(materialized),
        "playbooks": [match.playbook.id for match in materialized],
        "severity": materialized[0].severity if materialized else "info",
        "findings_covered": sum(len(match.finding_ids) for match in materialized),
    }
