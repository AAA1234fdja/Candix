"""Todos that survive a stop.

A run that hits the turn cap, waits for an approval or loses its provider should
not forget what it meant to do next. The todolist is the durable half of the
blackboard: items are added, claimed, completed or parked, and the next run reads
them before it plans anything new.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

OPEN = "open"
CLAIMED = "claimed"
DONE = "done"
PARKED = "parked"
CANCELLED = "cancelled"

_TERMINAL = {DONE, CANCELLED}


@dataclass
class Todo:
    text: str
    priority: float = 0.5
    tags: list[str] = field(default_factory=list)
    status: str = OPEN
    id: str = field(default_factory=lambda: f"todo-{int(time.time() * 1000) % 10**9}-{len(str(time.time()))}")
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    attempts: int = 0
    owner: str = ""
    blocked_by: str = ""
    evidence: list[str] = field(default_factory=list)

    @property
    def terminal(self) -> bool:
        return self.status in _TERMINAL

    def claim(self, owner: str = "agent") -> "Todo":
        self.status = CLAIMED
        self.owner = owner
        self.attempts += 1
        self.updated_at = time.time()
        return self

    def complete(self, *, evidence: Iterable[str] = ()) -> "Todo":
        self.status = DONE
        self.evidence.extend(str(item) for item in evidence)
        self.updated_at = time.time()
        return self

    def park(self, reason: str = "") -> "Todo":
        self.status = PARKED
        self.blocked_by = reason[:200]
        self.updated_at = time.time()
        return self

    def reopen(self) -> "Todo":
        if self.status in _TERMINAL:
            return self
        self.status = OPEN
        self.blocked_by = ""
        self.updated_at = time.time()
        return self

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "text": self.text,
            "priority": self.priority,
            "tags": list(self.tags),
            "status": self.status,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "attempts": self.attempts,
            "owner": self.owner,
            "blocked_by": self.blocked_by,
            "evidence": list(self.evidence),
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "Todo":
        return cls(
            text=str(payload.get("text", "")),
            priority=float(payload.get("priority", 0.5)),
            tags=[str(item) for item in payload.get("tags") or []],
            status=str(payload.get("status", OPEN)),
            id=str(payload.get("id", "")),
            created_at=float(payload.get("created_at", time.time())),
            updated_at=float(payload.get("updated_at", time.time())),
            attempts=int(payload.get("attempts", 0)),
            owner=str(payload.get("owner", "")),
            blocked_by=str(payload.get("blocked_by", "")),
            evidence=[str(item) for item in payload.get("evidence") or []],
        )


class TodoList:
    def __init__(self, path: str | Path = "") -> None:
        self.path = Path(path) if path else None
        self.items: list[Todo] = []
        if self.path is not None and self.path.exists():
            self.load()

    # ------------------------------------------------------------------
    def add(self, text: str, *, priority: float = 0.5, tags: Iterable[str] = ()) -> Todo:
        todo = Todo(text=text.strip(), priority=float(priority), tags=[str(tag) for tag in tags])
        self.items.append(todo)
        self._changed()
        return todo

    def next(self) -> Todo | None:
        candidates = [item for item in self.items if item.status in {OPEN, PARKED}]
        if not candidates:
            return None
        candidates.sort(key=lambda item: (-item.priority, item.created_at))
        return candidates[0]

    def claim_next(self, owner: str = "agent") -> Todo | None:
        todo = self.next()
        if todo is None:
            return None
        todo.claim(owner)
        self._changed()
        return todo

    def complete(self, todo: Todo, *, evidence: Iterable[str] = ()) -> Todo:
        todo.complete(evidence=evidence)
        self._changed()
        return todo

    def park(self, todo: Todo, reason: str = "") -> Todo:
        todo.park(reason)
        self._changed()
        return todo

    def cancel(self, todo: Todo) -> Todo:
        todo.status = CANCELLED
        todo.updated_at = time.time()
        self._changed()
        return todo

    def prune(self) -> int:
        before = len(self.items)
        self.items = [item for item in self.items if not item.terminal]
        removed = before - len(self.items)
        if removed:
            self._changed()
        return removed

    def open_items(self) -> list[Todo]:
        return [item for item in self.items if item.status in {OPEN, CLAIMED, PARKED}]

    def by_tag(self, tag: str) -> list[Todo]:
        return [item for item in self.items if tag in item.tags]

    def summary(self) -> str:
        counts: dict[str, int] = {}
        for item in self.items:
            counts[item.status] = counts.get(item.status, 0) + 1
        text = ", ".join(f"{name}={count}" for name, count in sorted(counts.items())) or "empty"
        return f"{len(self.items)} todo(s): {text}"

    def prompt_block(self, *, limit: int = 8) -> str:
        items = [item for item in self.open_items()][:limit]
        if not items:
            return ""
        return "\n".join(f"- ({item.priority:.2f}) {item.text}" + (f" [parked: {item.blocked_by}]" if item.blocked_by else "") for item in items)

    # ------------------------------------------------------------------
    def _changed(self) -> None:
        if self.path is not None:
            self.save()

    def save(self) -> str:
        if self.path is None:
            return ""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps([item.to_dict() for item in self.items], indent=2), encoding="utf-8")
        return str(self.path)

    def load(self) -> int:
        if self.path is None or not self.path.exists():
            return 0
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return 0
        if not isinstance(payload, list):
            return 0
        self.items = [Todo.from_dict(item) for item in payload if isinstance(item, dict)]
        return len(self.items)

    def seed_from_result(self, result: Any) -> int:
        """Turn the gaps of a finished run into todos for the next one."""

        added = 0
        for intent in getattr(result, "intents", []):
            status = getattr(intent.status, "value", str(intent.status))
            if status in {"failed", "blocked"}:
                self.add(
                    f"retry {intent.tool or intent.title}: {str(intent.result or intent.title)[:120]}",
                    priority=0.7,
                    tags=("retry", status),
                )
                added += 1
        for lesson in getattr(result, "lessons", []) or []:
            text = lesson.get("text", "") if isinstance(lesson, dict) else str(lesson)
            if text and ("slow" in text.lower() or "failed" in text.lower()):
                self.add(f"address: {text[:140]}", priority=0.4, tags=("lesson",))
                added += 1
        return added


def merge(first: TodoList, second: TodoList) -> TodoList:
    merged = TodoList(first.path)
    known = {item.text.strip().lower() for item in first.items}
    merged.items = list(first.items)
    for item in second.items:
        if item.text.strip().lower() not in known:
            merged.items.append(item)
            known.add(item.text.strip().lower())
    merged._changed()
    return merged


def from_prompt(prompt: str, *, limit: int = 6) -> list[str]:
    """Extract '-' bullets from a model answer so they can become todos."""

    lines = []
    for raw in (prompt or "").splitlines():
        stripped = raw.strip()
        if stripped.startswith(("- ", "* ")):
            text = stripped[2:].strip()
            if len(text) > 6:
                lines.append(text[:200])
        if len(lines) >= limit:
            break
    return lines
