"""Progress reporting for long scans on a plain terminal."""

from __future__ import annotations

import sys
import threading
import time
from typing import Any, TextIO

from candix.cli.output import counts_bar, paint, rule, severity_text

PHASE_LABELS = {
    "preflight": "preflight",
    "recon": "reconnaissance",
    "detect": "detection",
    "exploit": "exploitation",
    "report": "reporting",
}


class ScanProgress:
    """Prints phase transitions and the findings each phase produced."""

    def __init__(self, *, stream: TextIO | None = None, verbose: bool = False, quiet: bool = False) -> None:
        self.stream = stream or sys.stdout
        self.verbose = verbose
        self.quiet = quiet
        self.started = time.monotonic()
        self._lock = threading.Lock()
        self._phase_started: dict[str, float] = {}
        self._last_line = 0.0

    def write(self, text: str) -> None:
        if self.quiet:
            return
        with self._lock:
            self.stream.write(text + "\n")
            self.stream.flush()

    def handle(self, event: str, payload: dict[str, Any]) -> None:
        if self.quiet:
            return
        handler = getattr(self, f"_on_{event}", None)
        if handler is not None:
            handler(payload or {})
        elif self.verbose:
            detail = ", ".join(f"{key}={value}" for key, value in sorted((payload or {}).items())[:4])
            self.write(paint(f"  · {event}", "grey") + (f" {paint(detail, 'grey')}" if detail else ""))

    def _on_phase_started(self, payload: dict[str, Any]) -> None:
        phase = str(payload.get("phase") or payload.get("name") or "phase")
        self._phase_started[phase] = time.monotonic()
        label = PHASE_LABELS.get(phase, phase)
        self.write("")
        self.write(rule(label.capitalize()))

    def _on_phase_finished(self, payload: dict[str, Any]) -> None:
        phase = str(payload.get("phase") or payload.get("name") or "")
        elapsed = time.monotonic() - self._phase_started.get(phase, self.started)
        details = payload.get("details") or {}
        summary = ""
        if isinstance(details, dict):
            interesting = {
                key: details[key]
                for key in ("pages_fetched", "endpoints_added", "paths_found", "detectors", "findings", "proofs")
                if key in details
            }
            if interesting:
                summary = " · ".join(f"{key.replace('_', ' ')} {value}" for key, value in interesting.items())
        suffix = f" {paint(f'({elapsed:.1f}s)', 'grey')}"
        if summary:
            suffix += f" {paint(summary, 'grey')}"
        self.write(f"  {paint('✓', 'green')} {PHASE_LABELS.get(phase, phase)}{suffix}")

    def _on_finding(self, payload: dict[str, Any]) -> None:
        severity = str(payload.get("severity", "info")).lower()
        title = str(payload.get("title", "finding"))
        url = str(payload.get("url", ""))
        self.write(
            f"  {severity_text(severity, width=8)} {title}"
            + (f" {paint(url, 'grey')}" if url else "")
        )

    def _on_exploitation_succeeded(self, payload: dict[str, Any]) -> None:
        technique = str(payload.get("technique", "exploit"))
        title = str(payload.get("title", ""))
        self.write(f"  {paint('exploited', 'green')} {paint(technique, 'bold')} {paint(title, 'grey')}")

    def _on_exploitation_failed(self, payload: dict[str, Any]) -> None:
        technique = str(payload.get("technique", "exploit"))
        reason = str(payload.get("reason", ""))[:100]
        if self.verbose:
            self.write(f"  {paint('blocked', 'yellow')} {technique} {paint(reason, 'grey')}")

    def _on_warning(self, payload: dict[str, Any]) -> None:
        message = str(payload.get("message", "")).strip()
        if message:
            self.write(f"  {paint('warning', 'yellow')} {message}")

    def _on_scan_finished(self, payload: dict[str, Any]) -> None:
        counts = payload.get("counts") or payload.get("findings") or {}
        elapsed = time.monotonic() - self.started
        self.write("")
        self.write(rule("summary"))
        if counts:
            self.write(f"  {counts_bar(counts)}  {paint(f'in {elapsed:.1f}s', 'grey')}")


class Spinner:
    """Minimal spinner used while waiting on a single blocking operation."""

    FRAMES = ("⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏")

    def __init__(self, message: str, *, stream: TextIO | None = None, enabled: bool = True) -> None:
        self.message = message
        self.stream = stream or sys.stdout
        self.enabled = enabled and self._isatty()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def _isatty(self) -> bool:
        try:
            return bool(self.stream.isatty())
        except Exception:
            return False

    def __enter__(self) -> "Spinner":
        if not self.enabled:
            return self
        self._thread = threading.Thread(target=self._spin, daemon=True)
        self._thread.start()
        return self

    def _spin(self) -> None:
        index = 0
        while not self._stop.is_set():
            frame = self.FRAMES[index % len(self.FRAMES)]
            self.stream.write(f"\r  {frame} {self.message}")
            self.stream.flush()
            index += 1
            self._stop.wait(0.08)
        self.stream.write("\r" + " " * (len(self.message) + 6) + "\r")
        self.stream.flush()

    def __exit__(self, *_: Any) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=1.0)


def heartbeat(interval: float = 2.0) -> Any:
    """Iterator that yields timestamps at a fixed interval (used by importers)."""

    def generator() -> Any:
        while True:
            started = time.monotonic()
            yield started
            remaining = interval - (time.monotonic() - started)
            if remaining > 0:
                time.sleep(remaining)

    return generator()
