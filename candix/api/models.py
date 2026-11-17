"""Request and job models for the HTTP API."""

from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from candix.core.clock import isoformat
from candix.core.severity import Severity

TERMINAL_STATES = ("succeeded", "failed", "cancelled")


class ApiError(Exception):
    def __init__(self, status: int, message: str, **context: Any) -> None:
        super().__init__(message)
        self.status = status
        self.message = message
        self.context = context

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"error": self.message}
        if self.context:
            payload["details"] = self.context
        return payload


@dataclass
class ScanRequest:
    targets: list[str]
    profile: str = "standard"
    exploit: bool = False
    engagement: str = ""
    authorized: str = ""
    authorized_by: str = "api"
    formats: list[str] = field(default_factory=lambda: ["json", "html", "markdown"])
    max_rps: float | None = None
    max_pages: int | None = None
    detectors: list[str] = field(default_factory=list)
    categories: list[str] = field(default_factory=list)
    min_severity: str = "info"
    max_proofs: int | None = None
    include_subdomains: bool | None = None
    title: str = ""

    @classmethod
    def from_payload(cls, payload: Any) -> "ScanRequest":
        if not isinstance(payload, dict):
            raise ApiError(400, "request body must be a JSON object")
        targets = payload.get("targets")
        if isinstance(targets, str):
            targets = [targets]
        if not isinstance(targets, list) or not targets:
            raise ApiError(400, "targets must be a non-empty list")
        cleaned = [str(item).strip() for item in targets if str(item).strip()]
        if not cleaned:
            raise ApiError(400, "targets must contain at least one non-empty string")
        formats = payload.get("formats") or ["json", "html", "markdown"]
        if isinstance(formats, str):
            formats = [part.strip() for part in formats.split(",") if part.strip()]
        severity = str(payload.get("min_severity", "info")).lower()
        if severity not in {item.value for item in Severity}:
            raise ApiError(400, f"invalid min_severity: {severity}")
        request = cls(
            targets=cleaned,
            profile=str(payload.get("profile", "standard")).lower(),
            exploit=bool(payload.get("exploit", False)),
            engagement=str(payload.get("engagement", "") or ""),
            authorized=str(payload.get("authorized", "") or ""),
            authorized_by=str(payload.get("authorized_by", "api") or "api"),
            formats=[str(item) for item in formats],
            max_rps=_optional_float(payload.get("max_rps")),
            max_pages=_optional_int(payload.get("max_pages")),
            detectors=[str(item) for item in payload.get("detectors", []) or []],
            categories=[str(item) for item in payload.get("categories", []) or []],
            min_severity=severity,
            max_proofs=_optional_int(payload.get("max_proofs")),
            include_subdomains=_optional_bool(payload.get("include_subdomains")),
            title=str(payload.get("title", "") or ""),
        )
        if not request.engagement and not request.authorized:
            raise ApiError(403, "an engagement document or authorized operator name is required")
        return request

    def to_dict(self) -> dict[str, Any]:
        return {
            "targets": list(self.targets),
            "profile": self.profile,
            "exploit": self.exploit,
            "engagement": self.engagement,
            "authorized_by": self.authorized_by,
            "formats": list(self.formats),
            "max_rps": self.max_rps,
            "max_pages": self.max_pages,
            "detectors": list(self.detectors),
            "categories": list(self.categories),
            "min_severity": self.min_severity,
            "max_proofs": self.max_proofs,
            "title": self.title,
        }


def _optional_float(value: Any) -> float | None:
    if value in (None, ""):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        raise ApiError(400, f"expected a number, got {value!r}")


def _optional_int(value: Any) -> int | None:
    if value in (None, ""):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        raise ApiError(400, f"expected an integer, got {value!r}")


def _optional_bool(value: Any) -> bool | None:
    if value in (None, ""):
        return None
    if isinstance(value, bool):
        return value
    return str(value).lower() in {"1", "true", "yes", "on"}


@dataclass
class ScanJob:
    id: str
    request: ScanRequest
    state: str = "queued"
    created_at: str = field(default_factory=isoformat)
    started_at: str = ""
    finished_at: str = ""
    progress: float = 0.0
    phase: str = "queued"
    message: str = ""
    error: str = ""
    counts: dict[str, int] = field(default_factory=dict)
    risk_score: float = 0.0
    artifacts: dict[str, str] = field(default_factory=dict)
    report: dict[str, Any] = field(default_factory=dict)
    events: list[dict[str, Any]] = field(default_factory=list)
    cancel: threading.Event = field(default_factory=threading.Event, repr=False)

    @property
    def terminal(self) -> bool:
        return self.state in TERMINAL_STATES

    def event(self, name: str, payload: dict[str, Any] | None = None) -> None:
        self.events.append({"at": isoformat(), "event": name, "payload": payload or {}})
        if len(self.events) > 500:
            self.events = self.events[-500:]

    def to_dict(self, *, include_report: bool = False) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "id": self.id,
            "state": self.state,
            "phase": self.phase,
            "progress": round(self.progress, 3),
            "created_at": self.created_at,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "message": self.message,
            "error": self.error,
            "counts": dict(self.counts),
            "risk_score": self.risk_score,
            "artifacts": dict(self.artifacts),
            "request": self.request.to_dict(),
            "events": list(self.events[-50:]),
        }
        if include_report:
            payload["report"] = self.report
        return payload


class JobStore:
    """Thread-safe in-memory job registry with a bounded history."""

    def __init__(self, *, limit: int = 200) -> None:
        self._lock = threading.RLock()
        self._jobs: dict[str, ScanJob] = {}
        self._order: list[str] = []
        self.limit = limit

    def create(self, request: ScanRequest) -> ScanJob:
        job = ScanJob(id=f"job-{uuid.uuid4().hex[:12]}", request=request)
        with self._lock:
            self._jobs[job.id] = job
            self._order.append(job.id)
            while len(self._order) > self.limit:
                oldest = self._order.pop(0)
                self._jobs.pop(oldest, None)
        return job

    def get(self, job_id: str) -> ScanJob:
        with self._lock:
            job = self._jobs.get(job_id)
        if job is None:
            raise ApiError(404, f"unknown job: {job_id}")
        return job

    def list(self, *, state: str = "", limit: int = 50) -> list[ScanJob]:
        with self._lock:
            jobs = [self._jobs[job_id] for job_id in reversed(self._order) if job_id in self._jobs]
        if state:
            jobs = [job for job in jobs if job.state == state]
        return jobs[:limit]

    def counts(self) -> dict[str, int]:
        with self._lock:
            result: dict[str, int] = {}
            for job in self._jobs.values():
                result[job.state] = result.get(job.state, 0) + 1
            return result

    def prune(self, *, keep: int = 50) -> int:
        removed = 0
        with self._lock:
            terminal = [job for job in self._jobs.values() if job.terminal]
            terminal.sort(key=lambda job: job.created_at)
            excess = max(0, len(terminal) - keep)
            for job in terminal[:excess]:
                self._jobs.pop(job.id, None)
                if job.id in self._order:
                    self._order.remove(job.id)
                removed += 1
        return removed

    def wait(self, job_id: str, *, timeout: float = 0.0, interval: float = 0.25) -> ScanJob:
        deadline = time.monotonic() + timeout if timeout else None
        while True:
            job = self.get(job_id)
            if job.terminal:
                return job
            if deadline is not None and time.monotonic() >= deadline:
                return job
            time.sleep(interval)
