"""Request, time and bandwidth budgets.

A red team harness that ignores resource limits is an availability risk. The
budget is checked before every request, every response body read and every
proof execution. When a limit is hit the scan stops opening new work but keeps
enough capacity to finish writing the report.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from candix.core.clock import humanize_bytes, humanize_duration
from candix.core.errors import BudgetExceeded


@dataclass
class BudgetLimits:
    max_requests: int = 20000
    max_seconds: float = 1800.0
    max_bytes: int = 500 * 1024 * 1024
    max_findings: int = 10000
    max_requests_per_host: int = 0

    @classmethod
    def from_config(cls, config: Any) -> "BudgetLimits":
        return cls(
            max_requests=int(config.get("scan.max_requests", 20000)),
            max_seconds=float(config.get("scan.deadline_seconds", 1800.0) or 0.0),
            max_bytes=int(config.get("http.max_body_bytes", 2_000_000)) * 512,
            max_findings=10000,
            max_requests_per_host=int(config.get("safety.max_requests_per_host", 0) or 0),
        )


class Budget:
    """Thread-safe resource accounting."""

    def __init__(
        self,
        limits: BudgetLimits | None = None,
        *,
        kill_switch: str | Path | None = None,
        on_exhausted: Callable[[str], None] | None = None,
    ) -> None:
        self.limits = limits or BudgetLimits()
        self.kill_switch = Path(kill_switch) if kill_switch else None
        self.on_exhausted = on_exhausted
        self.requests = 0
        self.bytes = 0
        self.findings = 0
        self.retries = 0
        self.errors = 0
        self.started = time.monotonic()
        self.stopped = False
        self.stop_reason = ""
        self._lock = threading.Lock()
        self._per_host: dict[str, int] = {}
        self._listeners: list[Callable[[str], None]] = []

    # ------------------------------------------------------------------
    def add_listener(self, callback: Callable[[str], None]) -> None:
        self._listeners.append(callback)

    def _stop(self, reason: str) -> None:
        if self.stopped:
            return
        self.stopped = True
        self.stop_reason = reason
        if self.on_exhausted:
            try:
                self.on_exhausted(reason)
            except Exception:  # pragma: no cover - listener errors are not fatal
                pass
        for listener in self._listeners:
            try:
                listener(reason)
            except Exception:  # pragma: no cover
                pass

    def _check_kill_switch(self) -> None:
        if self.kill_switch and self.kill_switch.exists():
            self._stop(f"kill switch present: {self.kill_switch}")

    def check(self) -> None:
        """Raise if the budget is exhausted or the kill switch was triggered."""

        self._check_kill_switch()
        if self.stopped:
            raise BudgetExceeded(f"scan stopped: {self.stop_reason}")
        elapsed = time.monotonic() - self.started
        if self.limits.max_seconds and elapsed >= self.limits.max_seconds:
            self._stop("time budget exhausted")
            raise BudgetExceeded("time budget exhausted", elapsed=humanize_duration(elapsed))
        if self.requests >= self.limits.max_requests:
            self._stop("request budget exhausted")
            raise BudgetExceeded("request budget exhausted", requests=self.requests)
        if self.limits.max_bytes and self.bytes >= self.limits.max_bytes:
            self._stop("bandwidth budget exhausted")
            raise BudgetExceeded("bandwidth budget exhausted", bytes=self.bytes)

    def acquire_request(self, host: str = "", count: int = 1) -> None:
        self.check()
        with self._lock:
            if host and self.limits.max_requests_per_host:
                used = self._per_host.get(host, 0)
                if used + count > self.limits.max_requests_per_host:
                    raise BudgetExceeded(
                        "per-host request budget exhausted",
                        host=host,
                        limit=self.limits.max_requests_per_host,
                    )
                self._per_host[host] = used + count
            self.requests += count

    def record_response(self, size: int) -> None:
        with self._lock:
            self.bytes += max(0, size)

    def record_retry(self) -> None:
        with self._lock:
            self.retries += 1

    def record_error(self) -> None:
        with self._lock:
            self.errors += 1

    def record_finding(self) -> None:
        with self._lock:
            self.findings += 1
            if self.findings > self.limits.max_findings:
                self._stop("finding cap reached")

    def stop(self, reason: str = "operator requested") -> None:
        self._stop(reason)

    # ------------------------------------------------------------------
    @property
    def elapsed(self) -> float:
        return time.monotonic() - self.started

    @property
    def remaining_requests(self) -> int:
        return max(0, self.limits.max_requests - self.requests)

    @property
    def remaining_seconds(self) -> float:
        if not self.limits.max_seconds:
            return float("inf")
        return max(0.0, self.limits.max_seconds - self.elapsed)

    def snapshot(self) -> dict[str, Any]:
        return {
            "requests": self.requests,
            "max_requests": self.limits.max_requests,
            "bytes": self.bytes,
            "max_bytes": self.limits.max_bytes,
            "findings": self.findings,
            "retries": self.retries,
            "errors": self.errors,
            "elapsed_seconds": round(self.elapsed, 3),
            "elapsed_human": humanize_duration(self.elapsed),
            "bytes_human": humanize_bytes(self.bytes),
            "stopped": self.stopped,
            "stop_reason": self.stop_reason,
            "remaining_requests": self.remaining_requests,
        }

    def summary_line(self) -> str:
        return (
            f"{self.requests}/{self.limits.max_requests} requests, "
            f"{humanize_bytes(self.bytes)}, {humanize_duration(self.elapsed)}"
        )

    def __str__(self) -> str:  # pragma: no cover - display helper
        return self.summary_line()
