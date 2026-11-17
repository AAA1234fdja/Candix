"""Append-only, hash-chained run journal."""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator


def _digest(payload: dict[str, Any], prev: str) -> str:
    blob = json.dumps(payload, sort_keys=True, ensure_ascii=False) + prev
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


@dataclass
class JournalEntry:
    seq: int
    kind: str
    payload: dict[str, Any]
    at: float
    prev: str
    digest: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "seq": self.seq,
            "kind": self.kind,
            "payload": self.payload,
            "at": self.at,
            "prev": self.prev,
            "digest": self.digest,
        }

    def line(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, ensure_ascii=False)


class Journal:
    """JSONL journal where each entry commits to the previous one.

    The chain makes silent edits detectable: rewriting an entry changes its
    digest and every digest after it, which ``verify()`` reports.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.entries: list[JournalEntry] = []
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.path.exists():
            self._load()

    # ------------------------------------------------------------------
    def append(self, kind: str, payload: dict[str, Any] | None = None) -> JournalEntry:
        prev = self.entries[-1].digest if self.entries else "genesis"
        body = {"kind": kind, "payload": payload or {}, "at": time.time()}
        entry = JournalEntry(
            seq=len(self.entries) + 1,
            kind=kind,
            payload=dict(payload or {}),
            at=float(body["at"]),
            prev=prev,
            digest=_digest({"seq": len(self.entries) + 1, **body}, prev),
        )
        self.entries.append(entry)
        with self.path.open("a", encoding="utf-8") as stream:
            stream.write(entry.line() + "\n")
        return entry

    def _load(self) -> None:
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            self.entries.append(
                JournalEntry(
                    seq=int(payload.get("seq", 0)),
                    kind=str(payload.get("kind", "")),
                    payload=dict(payload.get("payload") or {}),
                    at=float(payload.get("at", 0.0)),
                    prev=str(payload.get("prev", "")),
                    digest=str(payload.get("digest", "")),
                )
            )

    # ------------------------------------------------------------------
    def verify(self) -> list[str]:
        problems: list[str] = []
        prev = "genesis"
        for index, entry in enumerate(self.entries, start=1):
            if entry.seq != index:
                problems.append(f"entry {index}: sequence is {entry.seq}")
            if entry.prev != prev:
                problems.append(f"entry {index}: previous digest mismatch")
            expected = _digest({"seq": entry.seq, "kind": entry.kind, "payload": entry.payload, "at": entry.at}, prev)
            if entry.digest != expected:
                problems.append(f"entry {index}: digest mismatch (content was modified)")
            prev = entry.digest
        return problems

    def of_kind(self, kind: str) -> list[JournalEntry]:
        return [entry for entry in self.entries if entry.kind == kind]

    def tail(self, count: int = 10) -> list[JournalEntry]:
        return self.entries[-count:]

    def __iter__(self) -> Iterator[JournalEntry]:
        return iter(self.entries)

    def __len__(self) -> int:
        return len(self.entries)

    def summary(self) -> dict[str, Any]:
        grouped: dict[str, int] = {}
        for entry in self.entries:
            grouped[entry.kind] = grouped.get(entry.kind, 0) + 1
        return {
            "path": str(self.path),
            "entries": len(self.entries),
            "kinds": grouped,
            "head": self.entries[0].digest if self.entries else "",
            "tail": self.entries[-1].digest if self.entries else "",
        }


class NullJournal:
    """Drop-in replacement when journaling is disabled."""

    def append(self, kind: str, payload: dict[str, Any] | None = None) -> None:
        return None

    def verify(self) -> list[str]:
        return []

    def summary(self) -> dict[str, Any]:
        return {"entries": 0, "kinds": {}, "disabled": True}

    def of_kind(self, kind: str) -> list[Any]:
        return []

    def __len__(self) -> int:
        return 0
