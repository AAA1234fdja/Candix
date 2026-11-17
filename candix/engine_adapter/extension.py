"""Extension adapter — engine/extension (browser capture) en Python."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any


@dataclass
class CapturedRequest:
    id: str
    url: str
    method: str
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    captured_at: float = field(default_factory=time.time)
    tab_id: int = 0

@dataclass
class ExtensionSession:
    id: str
    task_id: str
    connected: bool = True
    requests: list[CapturedRequest] = field(default_factory=list)

class ExtensionBridge:
    """Puente con la browser extension que captura tráfico real."""

    def __init__(self):
        self.sessions: dict[str, ExtensionSession] = {}

    def register_session(self, session_id: str, task_id: str) -> ExtensionSession:
        sess = ExtensionSession(id=session_id, task_id=task_id)
        self.sessions[session_id] = sess
        return sess

    def capture(self, session_id: str, url: str, method: str = "GET", headers: dict[str, str] | None = None, body: str = "") -> CapturedRequest | None:
        sess = self.sessions.get(session_id)
        if not sess:
            return None
        req = CapturedRequest(id=f"{session_id}-{len(sess.requests)}", url=url, method=method, headers=headers or {}, body=body)
        sess.requests.append(req)
        return req

    def get_requests(self, session_id: str, task_id: str | None = None) -> list[CapturedRequest]:
        sess = self.sessions.get(session_id)
        if not sess:
            return []
        if task_id and sess.task_id != task_id:
            return []
        return list(sess.requests)

    def disconnect(self, session_id: str) -> None:
        if session_id in self.sessions:
            self.sessions[session_id].connected = False

    def snapshot(self) -> dict[str, Any]:
        return {"sessions": len(self.sessions), "total_requests": sum(len(s.requests) for s in self.sessions.values())}
