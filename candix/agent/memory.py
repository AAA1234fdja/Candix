"""Lessons learned across runs.

A lesson is a short, reusable statement plus the evidence that produced it. The
store is plain JSON on disk, scored with a BM25-flavoured similarity so the
planner can be reminded of what worked without stuffing every past run into the
prompt.
"""

from __future__ import annotations

import json
import math
import re
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

_WORD = re.compile(r"[a-z0-9_./-]+")


def _terms(text: str) -> list[str]:
    return [token for token in _WORD.findall(str(text).lower()) if len(token) > 2]


@dataclass
class Lesson:
    text: str
    tags: list[str] = field(default_factory=list)
    weight: float = 1.0
    id: str = field(default_factory=lambda: f"lesson-{uuid.uuid4().hex[:8]}")
    created_at: float = field(default_factory=time.time)
    uses: int = 0
    wins: int = 0
    source_run: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "text": self.text,
            "tags": list(self.tags),
            "weight": round(self.weight, 3),
            "created_at": self.created_at,
            "uses": self.uses,
            "wins": self.wins,
            "source_run": self.source_run,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "Lesson":
        return cls(
            text=str(payload.get("text", "")),
            tags=[str(item) for item in payload.get("tags") or []],
            weight=float(payload.get("weight", 1.0) or 1.0),
            id=str(payload.get("id") or f"lesson-{uuid.uuid4().hex[:8]}"),
            created_at=float(payload.get("created_at", time.time())),
            uses=int(payload.get("uses", 0) or 0),
            wins=int(payload.get("wins", 0) or 0),
            source_run=str(payload.get("source_run", "")),
        )

    @property
    def precision(self) -> float:
        return self.wins / self.uses if self.uses else 0.0


class MemoryStore:
    """Persistent lessons with retrieval and decay."""

    def __init__(self, path: str | Path | None = None, *, limit: int = 500) -> None:
        self.path = Path(path) if path else None
        self.limit = limit
        self.lessons: list[Lesson] = []
        if self.path and self.path.exists():
            self.load()

    # ------------------------------------------------------------------
    def add(self, text: str, *, tags: Iterable[str] = (), source_run: str = "", weight: float = 1.0) -> Lesson:
        text = " ".join(str(text).split())[:400]
        for existing in self.lessons:
            if existing.text.lower() == text.lower():
                existing.weight = max(existing.weight, weight)
                existing.tags = sorted({*existing.tags, *tags})
                self.save()
                return existing
        lesson = Lesson(text=text, tags=sorted({str(tag) for tag in tags}), weight=weight, source_run=source_run)
        self.lessons.append(lesson)
        self._trim()
        self.save()
        return lesson

    def _trim(self) -> None:
        if len(self.lessons) <= self.limit:
            return
        self.lessons.sort(key=lambda item: (item.weight * (1 + item.precision), item.created_at), reverse=True)
        self.lessons = self.lessons[: self.limit]

    # ------------------------------------------------------------------
    def search(self, query: str, *, limit: int = 5) -> list[Lesson]:
        terms = _terms(query)
        if not terms:
            return self.top(limit)
        documents = [[*_terms(lesson.text), *[tag.lower() for tag in lesson.tags]] for lesson in self.lessons]
        if not documents:
            return []
        average = sum(len(document) for document in documents) / len(documents) or 1.0
        frequency: dict[str, int] = {}
        for document in documents:
            for term in set(document):
                frequency[term] = frequency.get(term, 0) + 1
        total = len(documents)
        scored: list[tuple[float, Lesson]] = []
        k1, b = 1.5, 0.75
        for lesson, document in zip(self.lessons, documents):
            score = 0.0
            for term in set(terms):
                tf = document.count(term)
                if not tf:
                    continue
                idf = math.log(1 + (total - frequency.get(term, 0) + 0.5) / (frequency.get(term, 0) + 0.5))
                denominator = tf + k1 * (1 - b + b * len(document) / average)
                score += idf * (tf * (k1 + 1)) / denominator
            if score:
                scored.append((score * lesson.weight * (1 + lesson.precision), lesson))
        scored.sort(key=lambda item: (-item[0], -item[1].created_at))
        return [lesson for _score, lesson in scored[:limit]]

    def top(self, limit: int = 5) -> list[Lesson]:
        ordered = sorted(self.lessons, key=lambda item: (item.weight * (1 + item.precision), item.created_at), reverse=True)
        return ordered[:limit]

    def reward(self, lesson_id: str, *, win: bool = True) -> None:
        for lesson in self.lessons:
            if lesson.id == lesson_id:
                lesson.uses += 1
                lesson.wins += 1 if win else 0
                lesson.weight = min(3.0, lesson.weight + (0.05 if win else -0.02))
                self.save()
                return

    def decay(self, factor: float = 0.98) -> None:
        for lesson in self.lessons:
            lesson.weight = max(0.1, lesson.weight * factor)
        self.save()

    # ------------------------------------------------------------------
    def save(self) -> None:
        if self.path is None:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"schema": "candix.memory/1", "lessons": [lesson.to_dict() for lesson in self.lessons]}
        self.path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")

    def load(self) -> int:
        if self.path is None or not self.path.exists():
            return 0
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return 0
        self.lessons = [Lesson.from_dict(item) for item in payload.get("lessons") or []]
        return len(self.lessons)

    def snapshot(self) -> dict[str, Any]:
        return {
            "path": str(self.path) if self.path else "",
            "lessons": len(self.lessons),
            "tags": sorted({tag for lesson in self.lessons for tag in lesson.tags}),
            "top": [lesson.text for lesson in self.top(5)],
        }

    def as_prompt(self, query: str = "", *, limit: int = 5) -> str:
        lessons = self.search(query, limit=limit) if query else self.top(limit)
        if not lessons:
            return ""
        return "\n".join(f"- {lesson.text}" for lesson in lessons)
