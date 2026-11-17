"""Python client for the Candix HTTP API."""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Iterator, Mapping


class ClientError(Exception):
    def __init__(self, status: int, message: str, payload: Any = None) -> None:
        super().__init__(message)
        self.status = status
        self.message = message
        self.payload = payload


@dataclass
class Job:
    id: str
    state: str
    phase: str = ""
    progress: float = 0.0
    counts: dict[str, int] = None  # type: ignore[assignment]
    risk_score: float = 0.0
    error: str = ""
    artifacts: dict[str, str] = None  # type: ignore[assignment]
    raw: dict[str, Any] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        self.counts = dict(self.counts or {})
        self.artifacts = dict(self.artifacts or {})
        self.raw = dict(self.raw or {})

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "Job":
        return cls(
            id=str(payload.get("id", "")),
            state=str(payload.get("state", "unknown")),
            phase=str(payload.get("phase", "")),
            progress=float(payload.get("progress", 0.0) or 0.0),
            counts=dict(payload.get("counts") or {}),
            risk_score=float(payload.get("risk_score", 0.0) or 0.0),
            error=str(payload.get("error", "")),
            artifacts=dict(payload.get("artifacts") or {}),
            raw=dict(payload),
        )

    @property
    def finished(self) -> bool:
        return self.state in {"succeeded", "failed", "cancelled"}

    @property
    def total(self) -> int:
        return int(self.counts.get("total", 0))


class CandixClient:
    """Thin, dependency-free client used by CI jobs and tests."""

    def __init__(self, base_url: str = "http://127.0.0.1:8088", *, token: str = "", timeout: float = 30.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout

    # ------------------------------------------------------------------
    def _request(self, method: str, path: str, body: Any = None, *, timeout: float | None = None) -> Any:
        url = f"{self.base_url}{path}"
        data = json.dumps(body).encode("utf-8") if body is not None else None
        headers = {"Accept": "application/json"}
        if data is not None:
            headers["Content-Type"] = "application/json"
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        request = urllib.request.Request(url, data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=timeout or self.timeout) as handle:
                raw = handle.read()
                content_type = handle.headers.get("Content-Type", "")
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")
            try:
                payload = json.loads(detail)
            except json.JSONDecodeError:
                payload = {"error": detail[:500]}
            raise ClientError(exc.code, payload.get("error", str(exc)), payload) from exc
        except urllib.error.URLError as exc:
            raise ClientError(0, f"connection failed: {exc}") from exc
        if "application/json" in content_type:
            try:
                return json.loads(raw.decode("utf-8"))
            except json.JSONDecodeError:
                return raw.decode("utf-8", "replace")
        return raw.decode("utf-8", "replace")

    # ------------------------------------------------------------------
    def health(self) -> dict[str, Any]:
        return self._request("GET", "/health")

    def version(self) -> dict[str, Any]:
        return self._request("GET", "/version")

    def detectors(self) -> dict[str, Any]:
        return self._request("GET", "/detectors")

    def submit(
        self,
        targets: list[str] | str,
        *,
        authorized: str = "",
        engagement: str = "",
        profile: str = "standard",
        exploit: bool = False,
        formats: list[str] | None = None,
        max_rps: float | None = None,
        max_proofs: int | None = None,
        min_severity: str = "info",
        title: str = "",
    ) -> Job:
        body: dict[str, Any] = {
            "targets": [targets] if isinstance(targets, str) else list(targets),
            "profile": profile,
            "exploit": exploit,
            "min_severity": min_severity,
        }
        if authorized:
            body["authorized"] = authorized
        if engagement:
            body["engagement"] = engagement
        if formats:
            body["formats"] = list(formats)
        if max_rps is not None:
            body["max_rps"] = max_rps
        if max_proofs is not None:
            body["max_proofs"] = max_proofs
        if title:
            body["title"] = title
        payload = self._request("POST", "/scans", body)
        return Job(id=str(payload.get("id", "")), state=str(payload.get("state", "queued")), raw=dict(payload))

    def job(self, job_id: str, *, wait: float = 0.0) -> Job:
        suffix = f"?wait={wait}" if wait else ""
        return Job.from_payload(self._request("GET", f"/scans/{job_id}{suffix}", timeout=(wait or 0) + self.timeout))

    def jobs(self, *, state: str = "", limit: int = 50) -> list[Job]:
        query = f"?state={state}&limit={limit}" if state else f"?limit={limit}"
        payload = self._request("GET", f"/scans{query}")
        return [Job.from_payload(item) for item in payload.get("jobs", [])]

    def events(self, job_id: str) -> list[dict[str, Any]]:
        payload = self._request("GET", f"/jobs/{job_id}/events")
        return list(payload.get("events", []))

    def report(self, job_id: str, fmt: str = "json") -> Any:
        payload = self._request("GET", f"/scans/{job_id}/report?format={fmt}")
        return payload if isinstance(payload, (dict, list)) else payload

    def cancel(self, job_id: str) -> Job:
        return Job.from_payload(self._request("POST", f"/scans/{job_id}/cancel", {}))

    # ------------------------------------------------------------------
    def wait(self, job_id: str, *, timeout: float = 1800.0, interval: float = 1.0) -> Job:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            job = self.job(job_id)
            if job.finished:
                return job
            time.sleep(interval)
        raise ClientError(0, f"job {job_id} did not finish within {timeout}s")

    def stream(self, job_id: str, *, interval: float = 1.0) -> Iterator[Job]:
        seen = 0
        while True:
            job = self.job(job_id)
            events = self.events(job_id)
            for event in events[seen:]:
                yield job
            seen = len(events)
            if job.finished:
                return
            time.sleep(interval)

    def run(
        self,
        targets: list[str] | str,
        *,
        timeout: float = 1800.0,
        poll: float = 1.0,
        **options: Any,
    ) -> Job:
        job = self.submit(targets, **options)
        return self.wait(job.id, timeout=timeout, interval=poll)


def summarize_job(job: Job) -> str:
    counts = job.counts
    return (
        f"{job.id}: {job.state} · total {counts.get('total', 0)} "
        f"(critical {counts.get('critical', 0)}, high {counts.get('high', 0)}) · risk {job.risk_score}"
    )
