"""A conversation that knows its own budget.

Messages accumulate until the window is full and then the least useful ones are
summarised away. Tool results are the first to go, older turns second, and the
system prompt never. Everything is serialisable so a run can be resumed.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any, Iterable, Iterator

from candix.llm.tokens import estimate_message, estimate_messages, fit_messages, truncate_text
from candix.llm.types import Message, Role, ToolCall


@dataclass
class Turn:
    index: int
    role: str
    content: str
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    at: float = field(default_factory=time.time)
    tokens: int = 0
    pinned: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "role": self.role,
            "content": self.content[:4000],
            "tool_calls": self.tool_calls,
            "at": self.at,
            "tokens": self.tokens,
            "pinned": self.pinned,
        }

    def to_message(self) -> Message:
        calls = [ToolCall(name=str(item.get("name", "")), arguments=dict(item.get("arguments") or {})) for item in self.tool_calls]
        return Message(role=Role(self.role), content=self.content, tool_calls=calls)


class Conversation:
    def __init__(self, *, system: str = "", max_tokens: int = 12000, reserve_output: int = 1200) -> None:
        self.max_tokens = max_tokens
        self.reserve_output = reserve_output
        self.turns: list[Turn] = []
        self.summary = ""
        self.compactions = 0
        if system:
            self.append("system", system, pinned=True)

    # ------------------------------------------------------------------
    def append(self, role: str, content: str, *, tool_calls: Iterable[Any] = (), pinned: bool = False) -> Turn:
        normalised = [
            {"name": call.name, "arguments": dict(call.arguments)} if hasattr(call, "name") else dict(call)
            for call in tool_calls
        ]
        message = Message(role=Role(role), content=content)
        turn = Turn(
            index=len(self.turns),
            role=role,
            content=content,
            tool_calls=normalised,
            tokens=estimate_message(message),
            pinned=pinned or role == "system",
        )
        self.turns.append(turn)
        return turn

    def system(self, content: str) -> Turn:
        existing = self.first("system")
        if existing is not None:
            existing.content = content
            existing.tokens = estimate_message(Message.system(content))
            return existing
        return self.append("system", content, pinned=True)

    def user(self, content: str, *, pinned: bool = False) -> Turn:
        return self.append("user", content, pinned=pinned)

    def assistant(self, content: str, *, tool_calls: Iterable[Any] = ()) -> Turn:
        return self.append("assistant", content, tool_calls=tool_calls)

    def tool(self, name: str, content: str) -> Turn:
        return self.append("tool", content)

    # ------------------------------------------------------------------
    def first(self, role: str) -> Turn | None:
        return next((turn for turn in self.turns if turn.role == role), None)

    def last(self, role: str = "") -> Turn | None:
        for turn in reversed(self.turns):
            if not role or turn.role == role:
                return turn
        return None

    def __len__(self) -> int:
        return len(self.turns)

    def __iter__(self) -> Iterator[Turn]:
        return iter(self.turns)

    @property
    def tokens(self) -> int:
        return sum(turn.tokens for turn in self.turns) + (estimate_message(Message.system(self.summary)) if self.summary else 0)

    def _reserve(self) -> int:
        # a reserve larger than the window would make every prompt "too big"
        return min(self.reserve_output, max(0, self.max_tokens // 2))

    def budget_left(self) -> int:
        return self.max_tokens - self._reserve() - self.tokens

    # ------------------------------------------------------------------
    def messages(self) -> list[Message]:
        output: list[Message] = []
        if self.summary:
            output.append(Message.system("Summary of earlier turns:\n" + self.summary))
        output.extend(turn.to_message() for turn in self.turns)
        return output

    def compact(self, *, keep_last: int = 6) -> dict[str, Any]:
        """Collapse old turns into the rolling summary until the budget fits."""

        before = self.tokens
        dropped: list[Turn] = []
        if self.budget_left() >= 0:
            return {"compacted": False, "before": before, "after": before, "dropped": 0}
        pinned = [turn for turn in self.turns if turn.pinned]
        recent = self.turns[-keep_last:] if keep_last else []
        middle = [turn for turn in self.turns if not turn.pinned and turn not in recent]
        for turn in middle:
            if self.budget_left() >= 0:
                break
            dropped.append(turn)
            self.turns.remove(turn)
        if dropped:
            self.summary = self._summarise(self.summary, dropped)
            self.compactions += 1
        # step two: shrink what remains (tool results first, then older turns)
        for role in ("tool", "assistant", "user"):
            for turn in self.turns:
                if self.budget_left() >= 0:
                    break
                if turn.pinned or turn.role != role:
                    continue
                over = -self.budget_left()
                target = max(48, turn.tokens - over)
                turn.content = truncate_text(turn.content, target)
                turn.tokens = estimate_message(Message(role=Role(role), content=turn.content))
        # step three: the summary itself can be the last thing over budget
        guard = 0
        while self.budget_left() < 0 and self.summary and guard < 8:
            overshoot = -self.budget_left()
            self.summary = truncate_text(self.summary, max(40, estimate_message(Message.system(self.summary)) - overshoot))
            guard += 1
        return {
            "compacted": bool(dropped) or before != self.tokens,
            "before": before,
            "after": self.tokens,
            "dropped": len(dropped),
            "summary_tokens": estimate_message(Message.system(self.summary)) if self.summary else 0,
            "fits": self.budget_left() >= 0,
        }

    def _summarise(self, previous: str, dropped: Iterable[Turn]) -> str:
        lines = [previous.strip()] if previous.strip() else []
        for turn in dropped:
            text = " ".join(turn.content.split())[:180]
            if not text:
                continue
            names = ", ".join(item.get("name", "") for item in turn.tool_calls if item.get("name"))
            suffix = f" [{names}]" if names else ""
            lines.append(f"- {turn.role}{suffix}: {text}")
        joined = "\n".join(lines)
        return truncate_text(joined, 240, marker="\n… [{n} characters of history dropped]")

    def fit(self, *, max_tokens: int | None = None) -> dict[str, Any]:
        result = fit_messages(
            self.messages(),
            max_tokens=max_tokens or self.max_tokens,
            reserve_output=self._reserve(),
        )
        return {
            "dropped": result.dropped,
            "truncated": result.truncated,
            "estimated_tokens": result.estimated_tokens,
            "messages": len(result.messages),
        }

    # ------------------------------------------------------------------
    def fork(self, *, keep_last: int = 4) -> "Conversation":
        clone = Conversation(system="", max_tokens=self.max_tokens, reserve_output=self.reserve_output)
        clone.summary = self.summary
        clone.turns = [turn for turn in self.turns[:1]]
        clone.turns.extend(self.turns[-keep_last:]) if keep_last else None
        return clone

    def pin(self, index: int) -> None:
        if 0 <= index < len(self.turns):
            self.turns[index].pinned = True

    def drop_tools(self) -> int:
        removed = [turn for turn in self.turns if turn.role == "tool" and not turn.pinned]
        for turn in removed:
            self.turns.remove(turn)
        return len(removed)

    def to_dict(self) -> dict[str, Any]:
        return {
            "turns": [turn.to_dict() for turn in self.turns],
            "summary": self.summary,
            "tokens": self.tokens,
            "compactions": self.compactions,
            "max_tokens": self.max_tokens,
        }

    def save(self, path: str) -> str:
        from pathlib import Path

        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")
        return str(target)

    @classmethod
    def load(cls, path: str) -> "Conversation":
        from pathlib import Path

        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        conversation = cls(max_tokens=int(payload.get("max_tokens", 12000)))
        conversation.summary = str(payload.get("summary", ""))
        for item in payload.get("turns", []):
            conversation.turns.append(
                Turn(
                    index=int(item.get("index", 0)),
                    role=str(item.get("role", "user")),
                    content=str(item.get("content", "")),
                    tool_calls=list(item.get("tool_calls") or []),
                    at=float(item.get("at", 0.0)),
                    tokens=int(item.get("tokens", 0)),
                    pinned=bool(item.get("pinned", False)),
                )
            )
        conversation.compactions = int(payload.get("compactions", 0))
        return conversation


def transcript(conversation: Conversation, *, limit: int = 40) -> str:
    lines = []
    for turn in conversation.turns[-limit:]:
        if turn.role == "system":
            continue
        calls = "".join(f" -> {item.get('name')}" for item in turn.tool_calls)
        lines.append(f"{turn.role}{calls}: {' '.join(turn.content.split())[:200]}")
    return "\n".join(lines)


def estimate(conversation: Conversation) -> dict[str, int]:
    return {
        "turns": len(conversation.turns),
        "tokens": conversation.tokens,
        "budget_left": conversation.budget_left(),
        "tool_turns": sum(1 for turn in conversation.turns if turn.role == "tool"),
    }
