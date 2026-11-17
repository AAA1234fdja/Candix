"""Timeline view that summarises how a scan unfolded."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Iterable

from candix.core.clock import humanize_duration


@dataclass
class TimelineEntry:
    at: float
    kind: str
    label: str
    detail: str = ""

    @property
    def relative(self) -> str:
        return f"+{self.at:6.1f}s"

    def to_dict(self) -> dict[str, Any]:
        return {"at": round(self.at, 2), "kind": self.kind, "label": self.label, "detail": self.detail}


@dataclass
class Timeline:
    started: float = field(default_factory=time.monotonic)
    entries: list[TimelineEntry] = field(default_factory=list)

    def add(self, kind: str, label: str, detail: str = "") -> TimelineEntry:
        entry = TimelineEntry(at=time.monotonic() - self.started, kind=kind, label=label, detail=detail)
        self.entries.append(entry)
        return entry

    def of_kind(self, kind: str) -> list[TimelineEntry]:
        return [entry for entry in self.entries if entry.kind == kind]

    def duration(self) -> float:
        if not self.entries:
            return 0.0
        return self.entries[-1].at

    def phases(self) -> list[TimelineEntry]:
        return [entry for entry in self.entries if entry.kind == "phase"]

    def sparkline(self, buckets: int = 24) -> list[int]:
        total = max(0.001, self.duration())
        counts = [0] * buckets
        for entry in self.entries:
            index = min(buckets - 1, int(entry.at / total * buckets))
            counts[index] += 1
        return counts

    def to_dict(self) -> dict[str, Any]:
        return {
            "duration": round(self.duration(), 2),
            "entries": [entry.to_dict() for entry in self.entries],
            "sparkline": self.sparkline(),
        }

    def render(self, *, width: int = 70, limit: int = 20) -> list[str]:
        lines = []
        for entry in self.entries[-limit:]:
            marker = {"phase": "▶", "finding": "!", "proof": "✓", "warning": "~", "note": "·"}.get(entry.kind, "·")
            text = f"{entry.relative} {marker} {entry.label}"
            if entry.detail:
                text += f" — {entry.detail}"
            lines.append(text[:width])
        return lines or ["no events yet"]


def from_state(state: Any) -> Timeline:
    """Build a timeline from a DashboardState-like object."""

    timeline = Timeline()
    for stamp, message in getattr(state, "recent_events", lambda limit=50: [])():
        timeline.add("event", message, stamp)
    return timeline


def summarise(entries: Iterable[dict[str, Any]]) -> dict[str, Any]:
    materialized = list(entries)
    kinds: dict[str, int] = {}
    for entry in materialized:
        kind = str(entry.get("kind", "event"))
        kinds[kind] = kinds.get(kind, 0) + 1
    duration = float(materialized[-1].get("at", 0)) if materialized else 0.0
    return {"entries": len(materialized), "kinds": kinds, "duration": humanize_duration(duration)}
