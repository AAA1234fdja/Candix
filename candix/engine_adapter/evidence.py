"""Evidence adapter — engine/evidence store."""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
import os


@dataclass
class Evidence:
    id: str
    task_id: str
    kind: str
    content: str
    digest: str
    created_at: int = field(default_factory=lambda: int(time.time()))


class EvidenceAdapter:
    def __init__(self, data_dir: str | Path | None = None):
        self.data_dir = Path(data_dir or os.getenv("CANDIX_DATA_DIR", "data/evidence"))
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self._store: list[Evidence] = []

    def put(self, task_id: str, kind: str, content: str | bytes) -> Evidence:
        if isinstance(content, bytes):
            content = content.decode(errors="replace")
        digest = hashlib.sha256(content.encode()).hexdigest()
        eid = digest[:16]
        ev = Evidence(id=eid, task_id=task_id, kind=kind, content=content, digest=digest)
        self._store.append(ev)
        try:
            p = self.data_dir / task_id / f"{eid}.json"
            p.parent.mkdir(parents=True, exist_ok=True)
            import json
            p.write_text(json.dumps(ev.__dict__, ensure_ascii=False, indent=2))
        except Exception:
            pass
        return ev

    def list(self, task_id: str | None = None) -> list[Evidence]:
        if task_id:
            return [e for e in self._store if e.task_id == task_id]
        return list(self._store)

    def get(self, eid: str) -> Evidence | None:
        for e in self._store:
            if e.id == eid:
                return e
        return None
