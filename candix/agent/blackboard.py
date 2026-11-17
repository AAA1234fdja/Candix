"""Per-run shared state the planner and workers both read."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from candix.agent.facts import Fact, FactStore


@dataclass
class Todo:
    id: str
    text: str
    created_at: float = field(default_factory=time.time)
    done: bool = False
    owner: str = "planner"
    priority: float = 0.5

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "text": self.text,
            "done": self.done,
            "owner": self.owner,
            "priority": self.priority,
        }


@dataclass
class Blackboard:
    """Shared, append-mostly memory for one goal.

    Notes are cheap and free-form; the todolist is structured so the planner can
    carry unfinished work across wake-ups; facts live in the typed store.
    """

    facts: FactStore = field(default_factory=FactStore)
    todos: list[Todo] = field(default_factory=list)
    notes: list[dict[str, Any]] = field(default_factory=list)
    open_questions: list[str] = field(default_factory=list)
    hypotheses: list[str] = field(default_factory=list)
    artefacts: dict[str, str] = field(default_factory=dict)
    counters: dict[str, int] = field(default_factory=dict)

    # ------------------------------------------------------------------
    def todo(self, text: str, *, priority: float = 0.5, owner: str = "planner") -> Todo:
        item = Todo(id=f"todo-{len(self.todos) + 1}", text=text, priority=priority, owner=owner)
        self.todos.append(item)
        return item

    def complete(self, todo_id: str) -> bool:
        for item in self.todos:
            if item.id == todo_id:
                item.done = True
                return True
        return False

    def open_todos(self) -> list[Todo]:
        return [item for item in self.todos if not item.done]

    def question(self, text: str) -> None:
        if text and text not in self.open_questions:
            self.open_questions.append(text)

    def answered(self, text: str) -> None:
        self.open_questions = [item for item in self.open_questions if item != text]

    def hypothesise(self, text: str) -> None:
        if text and text not in self.hypotheses:
            self.hypotheses.append(text)

    def note(self, text: str, *, kind: str = "note", author: str = "") -> None:
        self.notes.append({"text": text, "kind": kind, "author": author, "at": time.time()})

    def add_fact(self, fact: Fact) -> Fact:
        stored, action = self.facts.add(fact)
        self.counters[f"facts.{action}"] = self.counters.get(f"facts.{action}", 0) + 1
        return stored

    def bump(self, name: str, by: int = 1) -> None:
        self.counters[name] = self.counters.get(name, 0) + by

    # ------------------------------------------------------------------
    def render(self, *, limit: int = 20) -> str:
        lines: list[str] = []
        if self.hypotheses:
            lines.append("Hypotheses:")
            lines.extend(f"- {item}" for item in self.hypotheses[-limit:])
        if self.open_questions:
            lines.append("Open questions:")
            lines.extend(f"- {item}" for item in self.open_questions[-limit:])
        open_items = self.open_todos()
        if open_items:
            lines.append("Todolist:")
            lines.extend(f"- [{item.id}] {item.text}" for item in open_items[-limit:])
        if len(self.facts):
            lines.append("Known facts:")
            lines.extend(f"- ({fact.source.value}/{fact.confidence.value}) {fact.claim}" for fact in list(self.facts)[-limit:])
        return "\n".join(lines)

    def snapshot(self) -> dict[str, Any]:
        return {
            "facts": self.facts.snapshot(),
            "conflicts": [conflict.to_dict() for conflict in self.facts.conflicts],
            "todos": [item.to_dict() for item in self.todos],
            "notes": list(self.notes[-50:]),
            "open_questions": list(self.open_questions),
            "hypotheses": list(self.hypotheses),
            "artefacts": dict(self.artefacts),
            "counters": dict(self.counters),
        }
