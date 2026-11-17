"""Thread-safe dashboard state shared with the scan thread."""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Any, Iterator

from candix.core.clock import humanize_duration
from candix.core.severity import Severity

VIEWS = ("dashboard", "findings", "detail", "proofs", "stats", "help")
SORTS = ("severity", "endpoint", "title", "recent")
FILTERS = ("all", "critical", "high", "medium", "low", "info")


@dataclass
class PhaseState:
    name: str
    started: float = field(default_factory=time.monotonic)
    finished: float | None = None
    details: dict[str, Any] = field(default_factory=dict)

    @property
    def duration(self) -> float:
        return (self.finished or time.monotonic()) - self.started

    @property
    def done(self) -> bool:
        return self.finished is not None


class DashboardState:
    """Everything the screen needs, mutated by the scan thread."""

    def __init__(self, *, max_findings: int = 2000, max_events: int = 400) -> None:
        self._lock = threading.RLock()
        self.findings: list[Any] = []
        self.proofs: list[dict[str, Any]] = []
        self.phases: dict[str, PhaseState] = {}
        self.events: list[tuple[str, str]] = []
        self.counts: dict[str, int] = {severity.value: 0 for severity in Severity}
        self.counts["total"] = 0
        self.view = "dashboard"
        self.selected = 0
        self.scroll = 0
        self.filter = "all"
        self.sort = "severity"
        self.paused = False
        self.finished = False
        self.started = time.monotonic()
        self.scan_id = ""
        self.targets: list[str] = []
        self.profile = ""
        self.status = "starting"
        self.exploit_enabled = False
        self.proofs_attempted = 0
        self.proofs_succeeded = 0
        self.requests = 0
        self.errors = 0
        self.report_path = ""
        self.max_findings = max_findings
        self.max_events = max_events

    # ------------------------------------------------------------------
    # mutation
    # ------------------------------------------------------------------
    def bind(self, *, scan_id: str, targets: list[str], profile: str, exploit: bool) -> None:
        with self._lock:
            self.scan_id = scan_id
            self.targets = list(targets)
            self.profile = profile
            self.exploit_enabled = exploit

    def push_event(self, message: str, kind: str = "info") -> None:
        with self._lock:
            stamp = time.strftime("%H:%M:%S")
            self.events.append((stamp, f"{kind}: {message}"))
            if len(self.events) > self.max_events:
                self.events = self.events[-self.max_events :]

    def start_phase(self, name: str) -> None:
        with self._lock:
            self.phases[name] = PhaseState(name=name)
            self.status = name
            self.push_event(f"phase {name} started")

    def finish_phase(self, name: str, details: dict[str, Any] | None = None) -> None:
        with self._lock:
            phase = self.phases.setdefault(name, PhaseState(name=name))
            phase.finished = time.monotonic()
            phase.details.update(details or {})
            self.push_event(f"phase {name} finished in {humanize_duration(phase.duration)}")

    def add_finding(self, finding: Any) -> None:
        with self._lock:
            if len(self.findings) >= self.max_findings:
                return
            self.findings.append(finding)
            severity = finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity)
            self.counts[severity] = self.counts.get(severity, 0) + 1
            self.counts["total"] += 1
            self.push_event(f"{severity} · {finding.title}", kind="finding")

    def add_proof(self, proof: dict[str, Any]) -> None:
        with self._lock:
            self.proofs.append(proof)
            self.proofs_attempted = max(self.proofs_attempted, len(self.proofs))
            self.proofs_succeeded += 1
            self.push_event(f"proof · {proof.get('title', 'exploit')}", kind="proof")

    def finish(self, *, report_path: str = "") -> None:
        with self._lock:
            self.finished = True
            self.status = "complete"
            self.report_path = report_path
            self.push_event("scan complete", kind="done")

    # ------------------------------------------------------------------
    # views
    # ------------------------------------------------------------------
    def set_view(self, view: str) -> None:
        with self._lock:
            if view not in VIEWS:
                raise ValueError(f"unknown view: {view}")
            self.view = view
            self.scroll = 0

    def cycle_filter(self) -> str:
        with self._lock:
            index = FILTERS.index(self.filter) if self.filter in FILTERS else 0
            self.filter = FILTERS[(index + 1) % len(FILTERS)]
            self.selected = 0
            self.scroll = 0
            self.push_event(f"filter: {self.filter}")
            return self.filter

    def cycle_sort(self) -> str:
        with self._lock:
            index = SORTS.index(self.sort) if self.sort in SORTS else 0
            self.sort = SORTS[(index + 1) % len(SORTS)]
            self.push_event(f"sort: {self.sort}")
            return self.sort

    def visible_findings(self) -> list[Any]:
        with self._lock:
            items = list(self.findings)
            if self.filter != "all":
                items = [
                    item
                    for item in items
                    if (item.severity.value if hasattr(item.severity, "value") else str(item.severity)) == self.filter
                ]
            if self.sort == "severity":
                items.sort(key=lambda item: (item.severity_rank, -item.effective_score, item.title.lower()))
            elif self.sort == "endpoint":
                items.sort(key=lambda item: (item.url, item.title.lower()))
            elif self.sort == "title":
                items.sort(key=lambda item: item.title.lower())
            else:
                items.reverse()
            return items

    def current_finding(self) -> Any | None:
        items = self.visible_findings()
        if not items:
            return None
        self.selected = max(0, min(self.selected, len(items) - 1))
        return items[self.selected]

    def select_next(self) -> None:
        with self._lock:
            items = self.visible_findings()
            if items:
                self.selected = min(len(items) - 1, self.selected + 1)

    def select_previous(self) -> None:
        with self._lock:
            self.selected = max(0, self.selected - 1)

    # ------------------------------------------------------------------
    def elapsed(self) -> float:
        return time.monotonic() - self.started

    def progress(self) -> float:
        with self._lock:
            if not self.phases:
                return 0.0
            done = sum(1 for phase in self.phases.values() if phase.done)
            return min(1.0, done / max(1, len(self.phases)))

    def recent_events(self, limit: int = 12) -> list[tuple[str, str]]:
        with self._lock:
            return list(self.events[-limit:])

    def phase_rows(self) -> list[tuple[str, str, str]]:
        with self._lock:
            rows = []
            for phase in self.phases.values():
                state = "done" if phase.done else "running"
                rows.append((phase.name, humanize_duration(phase.duration), state))
            return rows

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "scan_id": self.scan_id,
                "status": self.status,
                "elapsed": round(self.elapsed(), 2),
                "counts": dict(self.counts),
                "findings": len(self.findings),
                "proofs": len(self.proofs),
                "phases": [phase.name for phase in self.phases.values()],
                "report": self.report_path,
            }


class EventBridge:
    """Adapts engine progress events into state mutations."""

    def __init__(self, state: DashboardState) -> None:
        self.state = state

    def __call__(self, event: str, payload: dict[str, Any]) -> None:
        handler = getattr(self, f"_on_{event.replace('.', '_')}", None)
        if handler is not None:
            handler(payload or {})
            return
        if event.startswith("phase_"):
            name = str((payload or {}).get("phase") or (payload or {}).get("name") or "")
            if not name:
                return
            if event.endswith("started"):
                self.state.start_phase(name)
            else:
                self.state.finish_phase(name, (payload or {}).get("details") or {})

    def _on_finding(self, payload: dict[str, Any]) -> None:
        finding = payload.get("finding")
        if finding is None and "title" in payload:
            from candix.core.finding import Finding

            try:
                finding = Finding.from_dict(payload, include_evidence=False)
            except Exception:
                finding = None
        if finding is not None:
            self.state.add_finding(finding)

    def _on_exploitation_succeeded(self, payload: dict[str, Any]) -> None:
        self.state.add_proof(dict(payload))

    def _on_scan_finished(self, payload: dict[str, Any]) -> None:
        counts = payload.get("counts")
        if isinstance(counts, dict):
            self.state.counts.update(counts)
        self.state.finish(report_path=str(payload.get("report_path", "") or ""))

    def _on_warning(self, payload: dict[str, Any]) -> None:
        self.state.push_event(str(payload.get("message", "")), kind="warning")
