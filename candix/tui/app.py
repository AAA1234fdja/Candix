"""Curses application loop with a headless fallback."""

from __future__ import annotations

import queue
import sys
import threading
import time
from typing import Any, Sequence

try:
    import curses  # type: ignore

    HAS_CURSES = True
except ImportError:
    curses = None  # type: ignore
    HAS_CURSES = False

from candix import VERSION
from candix.core.clock import humanize_duration
from candix.tui import views, widgets
from candix.tui.keys import (
    ACTION_BOTTOM,
    ACTION_DASHBOARD,
    ACTION_DETAIL,
    ACTION_EXPORT,
    ACTION_FINDINGS,
    ACTION_HELP,
    ACTION_NEXT,
    ACTION_PREVIOUS,
    ACTION_PROOFS,
    ACTION_QUIT,
    ACTION_STATS,
    ACTION_TOP,
    key_to_action,
    handle_action,
)
from candix.tui.state import DashboardState, EventBridge

COLORS: dict[str, int] = {name: 0 for name in widgets.PAIRS}

REFRESH_INTERVAL = 0.25


class ScanWorker(threading.Thread):
    """Runs the engine while the UI keeps the terminal responsive."""

    def __init__(
        self,
        state: DashboardState,
        targets: Sequence[str],
        *,
        config: Any,
        engagement: Any,
        exploit: bool,
        max_proofs: int,
        report_dir: str,
    ) -> None:
        super().__init__(daemon=True, name="candix-tui-scan")
        self.state = state
        self.targets = list(targets)
        self.config = config
        self.engagement = engagement
        self.exploit = exploit
        self.max_proofs = max_proofs
        self.report_dir = report_dir
        self.result: Any = None
        self.error: str = ""

    def run(self) -> None:  # pragma: no cover - exercised through the app
        from candix.engine import scan

        bridge = EventBridge(self.state)
        self.config.set("exploit.enabled", self.exploit)
        self.config.set("exploit.max_proofs", self.max_proofs)
        try:
            self.result = scan(
                self.targets,
                config=self.config,
                engagement=self.engagement,
                exploit=self.exploit,
                artifacts_dir=self.report_dir,
                on_progress=bridge,
            )
            self.state.finish(report_path="")
        except Exception as exc:
            self.error = str(exc)
            self.state.push_event(f"scan failed: {exc}", kind="warning")
            self.state.finished = True


def run_tui(
    targets: Sequence[str],
    *,
    config: Any,
    engagement: Any = None,
    exploit: bool = False,
    max_proofs: int = 6,
    report_dir: str = "artifacts",
) -> int:
    """Launch the dashboard, or fall back to a plain run when there is no terminal."""

    targets = [target for target in targets if target]
    if not targets:
        sys.stderr.write("no targets supplied; pass at least one URL\n")
        return 2
    if not HAS_CURSES:
        sys.stderr.write(
            "TUI requires curses (Unix) or 'windows-curses' on Windows. "
            "Falling back to headless mode — use --json for machine-readable output.\n"
        )
        return _headless(targets, config=config, engagement=engagement, exploit=exploit, max_proofs=max_proofs)
    if not _interactive():
        return _headless(targets, config=config, engagement=engagement, exploit=exploit, max_proofs=max_proofs)
    try:
        return curses.wrapper(  # type: ignore
            _main,
            targets,
            config,
            engagement,
            exploit,
            max_proofs,
            report_dir,
        )
    except Exception as exc:  # pragma: no cover - terminal too small or unsupported
        # curses.error and ImportError both land here
        sys.stderr.write(f"curses unavailable ({exc}); falling back to headless mode\n")
        return _headless(targets, config=config, engagement=engagement, exploit=exploit, max_proofs=max_proofs)


def _interactive() -> bool:
    try:
        return bool(sys.stdout.isatty() and sys.stdin.isatty())
    except Exception:
        return False


def _main(
    screen: Any,
    targets: Sequence[str],
    config: Any,
    engagement: Any,
    exploit: bool,
    max_proofs: int,
    report_dir: str,
) -> int:
    global COLORS
    COLORS = widgets.init_colors()
    try:
        curses.curs_set(0)  # type: ignore
    except Exception:
        pass
    screen.nodelay(True)
    screen.keypad(True)
    try:
        curses.mousemask(0)  # type: ignore
    except Exception:
        pass
    state = DashboardState()
    state.bind(scan_id="scanning", targets=list(targets), profile=str(config.get("profile")), exploit=exploit)
    state.push_event(f"candix {VERSION} dashboard ready", kind="info")
    worker = ScanWorker(
        state,
        targets,
        config=config,
        engagement=engagement,
        exploit=exploit,
        max_proofs=max_proofs,
        report_dir=report_dir,
    )
    worker.start()
    key_queue: queue.Queue[str] = queue.Queue()
    last_draw = 0.0
    previous_view = state.view
    while True:
        now = time.monotonic()
        if now - last_draw >= REFRESH_INTERVAL and not state.paused:
            views.render(screen, state)
            if HAS_CURSES:
                curses.doupdate()  # type: ignore
            last_draw = now
        try:
            ch = screen.getch()
        except Exception:
            ch = -1
        if ch != -1:
            action = key_to_action(ch)
            if action is None and state.view == "help":
                state.set_view(previous_view or "dashboard")
                continue
            if action == ACTION_QUIT:
                break
            if action == ACTION_HELP:
                previous_view = state.view
                state.set_view("help")
                continue
            if action == ACTION_DASHBOARD:
                state.set_view("dashboard")
            elif action == ACTION_FINDINGS:
                state.set_view("findings")
            elif action == ACTION_DETAIL:
                if state.visible_findings():
                    state.set_view("detail")
            elif action == ACTION_PROOFS:
                state.set_view("proofs")
            elif action == ACTION_STATS:
                state.set_view("stats")
            elif action == ACTION_EXPORT:
                _export(state)
            else:
                handle_action(state, action) if action else None
        if worker.finished and not state.finished:
            state.finish()
        if worker.error and not state.finished:
            state.push_event(worker.error, kind="warning")
            state.finished = True
        if state.finished and not worker.is_alive():
            views.render(screen, state)
            if HAS_CURSES:
                curses.doupdate()  # type: ignore
            screen.nodelay(False)
            try:
                screen.timeout(15000)
                screen.getch()
            except Exception:
                pass
            break
    worker.join(timeout=3.0)
    if worker.result is not None:
        _write_reports(worker.result, report_dir)
    return 0


def _export(state: DashboardState) -> None:
    import json
    from pathlib import Path

    target = Path("reports") / f"{state.scan_id or 'dashboard'}-findings.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(
            {
                "summary": state.snapshot(),
                "findings": [finding.to_dict(include_evidence=False) for finding in state.visible_findings()],
                "proofs": list(state.proofs),
            },
            indent=2,
            sort_keys=True,
            default=str,
        ),
        encoding="utf-8",
    )
    state.push_event(f"exported findings to {target}", kind="done")


def _write_reports(result: Any, directory: str) -> None:
    from candix.report import build_report

    try:
        build_report(result, outdir=directory, formats="html,json,markdown")
    except Exception:
        pass


def _headless(
    targets: Sequence[str],
    *,
    config: Any,
    engagement: Any,
    exploit: bool,
    max_proofs: int,
) -> int:
    from candix.cli import output as out
    from candix.cli.progress import ScanProgress
    from candix.engine import scan

    progress = ScanProgress(verbose=True)
    config.set("exploit.enabled", exploit)
    config.set("exploit.max_proofs", max_proofs)
    result = scan(targets, config=config, engagement=engagement, exploit=exploit, on_progress=progress.handle)
    summary = result.summary()
    out.print_json(summary) if False else None
    print(out.rule("results"))
    print(out.kv_table([
        ("duration", humanize_duration(result.duration)),
        ("findings", out.counts_bar(summary.get("findings") or {})),
        ("risk score", summary.get("risk_score", 0)),
    ], indent=2))
    for finding in result.findings.sorted()[:15]:
        print(out.finding_line(finding))
    return 0


def describe_layout() -> dict[str, Any]:
    return {
        "header": ["title", "scan id", "status", "clock", "severity chips"],
        "body": {"dashboard": "phases, activity, severity mix", "findings": "list and detail", "proofs": "proof table", "stats": "counters"},
        "footer": "key bindings",
        "refresh_seconds": REFRESH_INTERVAL,
    }
