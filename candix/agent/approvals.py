"""Human-in-the-loop approval queue."""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable

from candix.agent.models import Intent


class ApprovalStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"


@dataclass
class ApprovalRequest:
    intent: Intent
    reason: str
    risk: float = 0.0
    id: str = field(default_factory=lambda: f"apr-{uuid.uuid4().hex[:8]}")
    status: ApprovalStatus = ApprovalStatus.PENDING
    created_at: float = field(default_factory=time.time)
    decided_at: float = 0.0
    decided_by: str = ""
    note: str = ""
    ttl: float = 900.0

    @property
    def expired(self) -> bool:
        return self.status is ApprovalStatus.PENDING and self.ttl and time.time() - self.created_at > self.ttl

    def approve(self, by: str = "operator", note: str = "") -> "ApprovalRequest":
        self.status = ApprovalStatus.APPROVED
        self.decided_at = time.time()
        self.decided_by = by or "operator"
        self.note = note
        return self

    def reject(self, by: str = "operator", note: str = "") -> "ApprovalRequest":
        self.status = ApprovalStatus.REJECTED
        self.decided_at = time.time()
        self.decided_by = by or "operator"
        self.note = note
        return self

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "intent_id": self.intent.id,
            "title": self.intent.title,
            "phase": self.intent.phase.value,
            "reason": self.reason,
            "risk": round(self.risk, 3),
            "status": self.status.value,
            "created_at": self.created_at,
            "decided_at": self.decided_at,
            "decided_by": self.decided_by,
            "note": self.note,
        }

    def prompt(self) -> str:
        arguments = json.dumps(self.intent.arguments, ensure_ascii=False, sort_keys=True)
        lines = [
            f"[{self.id}] {self.intent.phase.value.upper()} — {self.intent.title}",
            f"  risk: {self.risk:.2f}  reason: {self.reason}",
            f"  tool: {self.intent.tool or 'agent'} {arguments[:300]}",
        ]
        if self.intent.description:
            lines.append(f"  details: {self.intent.description[:300]}")
        return "\n".join(lines)


class ApprovalQueue:
    """Collects requests and resolves them through a policy or a callback."""

    def __init__(
        self,
        *,
        auto_approve: Callable[[ApprovalRequest], bool] | None = None,
        on_request: Callable[[ApprovalRequest], None] | None = None,
        path: str | Path | None = None,
    ) -> None:
        self.requests: list[ApprovalRequest] = []
        self.auto_approve = auto_approve
        self.on_request = on_request
        self.path = Path(path) if path else None
        self.by_id: dict[str, ApprovalRequest] = {}

    # ------------------------------------------------------------------
    def request(self, intent: Intent, reason: str, *, risk: float = 0.0) -> ApprovalRequest:
        request = ApprovalRequest(intent=intent, reason=reason, risk=risk)
        self.requests.append(request)
        self.by_id[request.id] = request
        if self.auto_approve is not None and self.auto_approve(request):
            request.approve(by="policy", note="auto-approved by policy")
        elif self.on_request is not None:
            self.on_request(request)
        self._persist()
        return request

    def resolve(self, request_id: str, *, approved: bool, by: str = "operator", note: str = "") -> ApprovalRequest | None:
        request = self.by_id.get(request_id)
        if request is None or request.status is not ApprovalStatus.PENDING:
            return request
        request.approve(by, note) if approved else request.reject(by, note)
        self._persist()
        return request

    def pending(self) -> list[ApprovalRequest]:
        return [request for request in self.requests if request.status is ApprovalStatus.PENDING and not request.expired]

    def expire(self) -> int:
        expired = 0
        for request in self.requests:
            if request.expired:
                request.status = ApprovalStatus.EXPIRED
                request.note = request.note or "expired without a decision"
                expired += 1
        if expired:
            self._persist()
        return expired

    def approved_ids(self) -> set[str]:
        return {request.intent.id for request in self.requests if request.status is ApprovalStatus.APPROVED}

    def stats(self) -> dict[str, Any]:
        grouped: dict[str, int] = {}
        for request in self.requests:
            grouped[request.status.value] = grouped.get(request.status.value, 0) + 1
        return {"total": len(self.requests), "by_status": grouped, "pending": len(self.pending())}

    # ------------------------------------------------------------------
    def _persist(self) -> None:
        if self.path is None:
            return
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            payload = {"schema": "candix.approvals/1", "requests": [request.to_dict() for request in self.requests]}
            self.path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        except OSError:
            return

    def load(self) -> int:
        if self.path is None or not self.path.exists():
            return 0
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return 0
        loaded = 0
        for item in payload.get("requests") or []:
            intent = Intent(title=str(item.get("title", "")), phase=item.get("phase", "recon"))
            if item.get("intent_id"):
                intent.id = str(item["intent_id"])
            request = ApprovalRequest(
                intent=intent,
                reason=str(item.get("reason", "")),
                risk=float(item.get("risk", 0.0) or 0.0),
                id=str(item.get("id") or f"apr-{uuid.uuid4().hex[:8]}"),
                status=ApprovalStatus(str(item.get("status", "pending"))),
                created_at=float(item.get("created_at", time.time())),
                decided_at=float(item.get("decided_at", 0.0) or 0.0),
                decided_by=str(item.get("decided_by", "")),
                note=str(item.get("note", "")),
            )
            self.requests.append(request)
            self.by_id[request.id] = request
            loaded += 1
        return loaded
