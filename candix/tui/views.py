"""Screen renderers."""

from __future__ import annotations

import time
from typing import Any

from candix.core.clock import humanize_duration
from candix.tui import widgets
from candix.tui.keys import help_lines
from candix.tui.state import DashboardState

HEADER_HEIGHT = 3
FOOTER_HEIGHT = 2


def draw_header(window: Any, state: DashboardState, *, width: int, colors: dict[str, int]) -> int:
    columns = width
    title = " CANDIX "
    status = state.status
    mode = "EXPLOIT" if state.exploit_enabled else "DETECT"
    clock = time.strftime("%H:%M:%S")
    widgets.safe_addstr(window, 0, 0, title, widgets.attr(colors["title"], bold=True), width=columns)
    widgets.safe_addstr(window, 0, len(title) + 1, f"{state.scan_id or 'pending'} · {state.profile} · {mode}",
                        widgets.attr(colors["dim"]), width=columns - len(title) - 12)
    right = f"{status} · {clock} "
    widgets.safe_addstr(window, 0, max(0, columns - len(right) - 1), right, widgets.attr(colors["accent"]), width=len(right))
    elapsed = humanize_duration(state.elapsed())
    chips = widgets.severity_chip(state.counts, max(10, columns // 3))
    line = f" {elapsed} · findings {state.counts.get('total', 0)} ({chips}) · proofs {len(state.proofs)}"
    widgets.safe_addstr(window, 1, 0, line, 0, width=columns)
    widgets.safe_addstr(window, 2, 0, widgets.divider(columns), widgets.attr(colors["dim"]), width=columns)
    return HEADER_HEIGHT


def draw_footer(window: Any, state: DashboardState, *, width: int, colors: dict[str, int]) -> None:
    height, _ = window.getmaxyx()
    widgets.safe_addstr(window, height - FOOTER_HEIGHT, 0, widgets.divider(width), widgets.attr(colors["dim"]), width=width)
    hints = [
        ("q", "quit"),
        ("f", "findings"),
        ("enter", "detail"),
        ("/", "filter"),
        ("p", "proofs"),
        ("s", "stats"),
        ("?", "help"),
    ]
    widgets.safe_addstr(window, height - 1, 0, widgets.footer(hints, width), widgets.attr(colors["dim"]), width=width)


def draw_dashboard(window: Any, state: DashboardState, *, top: int, height: int, width: int) -> None:
    colors = _colors()
    left_width = max(38, int(width * 0.55))
    _phase_panel(window, state, top, 0, height, left_width - 1)
    _event_panel(window, state, top, left_width, height, width - left_width)
    _severity_panel(window, state, top, 0, 0, left_width - 1)


def _severity_panel(window: Any, state: DashboardState, top: int, left: int, height: int, width: int) -> None:
    colors = _colors()
    y = top + height - 7
    widgets.draw_box(window, y, left, 7, width, "severity mix", colors["accent"])
    total = max(1, state.counts.get("total", 0))
    row = y + 1
    for severity in widgets.severities():
        count = state.counts.get(severity, 0)
        label = f" {severity.ljust(8)} {count:>3} "
        widgets.safe_addstr(window, row, left + 2, label, widgets.attr(colors.get(severity, colors["dim"])), width=width - 4)
        bar_width = max(6, width - 22)
        widgets.draw_bar(window, row, left + 16, bar_width, count / total, colors.get(severity, colors["dim"]))
        row += 1


def _phase_panel(window: Any, state: DashboardState, top: int, left: int, height: int, width: int) -> None:
    colors = _colors()
    panel_height = max(6, height - 8)
    widgets.draw_box(window, top, left, panel_height, width, "phases", colors["accent"])
    rows = state.phase_rows()
    if rows:
        widgets.draw_table(window, top + 1, left + 2, width - 4, ["phase", "time", "state"], rows, column_widths=[16, 10, 10], max_rows=panel_height - 2)
    else:
        widgets.safe_addstr(window, top + 2, left + 2, "waiting for the first phase…", widgets.attr(colors["dim"]), width=width - 4)
    detail = state.current_finding()
    y = top + panel_height + 1
    if detail is not None:
        widgets.draw_box(window, y, left, 6, width, "latest finding", colors.get(detail.severity.value, colors["dim"]))
        widgets.safe_addstr(window, y + 1, left + 2, widgets.truncate(detail.title, width - 4), widgets.attr(colors.get(detail.severity.value, colors["dim"]), bold=True), width=width - 4)
        widgets.safe_addstr(window, y + 2, left + 2, f"{detail.method} {widgets.truncate(detail.url, width - 8)}", widgets.attr(colors["dim"]), width=width - 4)
        if detail.parameter:
            line = f"param {detail.parameter} ({detail.location}) · {detail.confidence.value}"
            widgets.safe_addstr(window, y + 3, left + 2, line, 0, width=width - 4)
        widgets.safe_addstr(window, y + 4, left + 2, widgets.truncate(detail.description, width - 6), 0, width=width - 6)
    else:
        widgets.draw_box(window, y, left, 6, width, "latest finding", colors["dim"])
        widgets.safe_addstr(window, y + 2, left + 2, "no findings yet", widgets.attr(colors["dim"]), width=width - 4)


def _event_panel(window: Any, state: DashboardState, top: int, left: int, height: int, width: int) -> None:
    colors = _colors()
    widgets.draw_box(window, top, left, height, width, "activity", colors["accent"])
    events = state.recent_events(max(4, height - 4))
    row = top + 1
    for stamp, message in events:
        kind = message.split(":", 1)[0]
        pair = {"finding": colors["high"], "proof": colors["ok"], "warning": colors["warn"], "done": colors["ok"]}.get(kind, colors["dim"])
        text = f"{stamp} {message.split(': ', 1)[-1]}"
        widgets.safe_addstr(window, row, left + 2, widgets.truncate(text, width - 4), widgets.attr(pair), width=width - 4)
        row += 1
        if row >= top + height - 1:
            break
    if state.report_path:
        widgets.safe_addstr(window, top + height - 2, left + 2, widgets.truncate(state.report_path, width - 4), widgets.attr(colors["ok"]), width=width - 4)


def draw_findings(window: Any, state: DashboardState, *, top: int, height: int, width: int) -> None:
    colors = _colors()
    widgets.draw_box(window, top, 0, height, width, f"findings · filter {state.filter} · sort {state.sort}", colors["accent"])
    items = state.visible_findings()
    if not items:
        widgets.safe_addstr(window, top + 2, 2, "no findings match the current filter", widgets.attr(colors["dim"]), width=width - 4)
        return
    list_width = max(30, int(width * 0.5))
    visible_rows = max(1, height - 2)
    state.selected = min(state.selected, len(items) - 1)
    state.scroll = max(0, min(state.scroll, max(0, len(items) - visible_rows)))
    if state.selected < state.scroll:
        state.scroll = state.selected
    if state.selected >= state.scroll + visible_rows:
        state.scroll = state.selected - visible_rows + 1
    row = top + 1
    for index in range(state.scroll, min(len(items), state.scroll + visible_rows)):
        finding = items[index]
        severity = finding.severity.value
        marker = "▸" if index == state.selected else " "
        label = f"{marker} {severity[0].upper()} {widgets.truncate(finding.title, list_width - 6)}"
        style = widgets.attr(colors.get(severity, colors["dim"]), bold=index == state.selected)
        widgets.safe_addstr(window, row, 2, label, style, width=list_width)
        row += 1
        if row >= top + height - 1:
            break
    detail = items[state.selected]
    x = list_width + 1
    detail_width = width - x - 2
    if detail_width > 20:
        _finding_detail(window, detail, top + 1, x, height - 2, detail_width)


def _finding_detail(window: Any, finding: Any, top: int, left: int, height: int, width: int) -> None:
    colors = _colors()
    severity = finding.severity.value
    row = top
    lines: list[tuple[str, int]] = [
        (finding.title, widgets.attr(colors.get(severity, colors["dim"]), bold=True)),
        (f"{finding.method} {finding.url}", widgets.attr(colors["dim"])),
        (f"{severity.upper()} · {finding.effective_score:.1f} · {finding.confidence.value}", 0),
    ]
    if finding.parameter:
        lines.append((f"parameter {finding.parameter} ({finding.location})", 0))
    lines.append(("", 0))
    for line in widgets.wrap_text(finding.description, width - 2):
        lines.append((line, 0))
    if finding.impact:
        lines.append(("", 0))
        for line in widgets.wrap_text(f"Impact: {finding.impact}", width - 2):
            lines.append((line, 0))
    if finding.remediation.summary:
        lines.append(("", 0))
        for line in widgets.wrap_text(f"Fix: {finding.remediation.summary}", width - 2):
            lines.append((line, widgets.attr(colors["ok"])))
    for text, style in lines:
        if row >= top + height:
            break
        widgets.safe_addstr(window, row, left, widgets.truncate(text, width), style, width=width)
        row += 1


def draw_proofs(window: Any, state: DashboardState, *, top: int, height: int, width: int) -> None:
    colors = _colors()
    widgets.draw_box(window, top, 0, height, width, "exploitation proofs", colors["ok"])
    if not state.proofs:
        widgets.safe_addstr(window, top + 2, 2, "no proofs recorded", widgets.attr(colors["dim"]), width=width - 4)
        return
    rows = []
    for proof in state.proofs:
        rows.append([
            str(proof.get("technique") or "proof"),
            str(proof.get("title") or "")[:40],
            str(proof.get("url") or proof.get("endpoint") or "")[:48],
        ])
    widgets.draw_table(window, top + 1, 2, width - 4, ["technique", "title", "target"], rows,
                       column_widths=[16, 34, max(20, width - 56)], max_rows=height - 3)


def draw_stats(window: Any, state: DashboardState, *, top: int, height: int, width: int) -> None:
    colors = _colors()
    widgets.draw_box(window, top, 0, height, width, "statistics", colors["accent"])
    summary = state.snapshot()
    rows = [
        ("scan id", summary["scan_id"] or "pending"),
        ("status", summary["status"]),
        ("elapsed", humanize_duration(summary["elapsed"])),
        ("findings", summary["findings"]),
        ("proofs", summary["proofs"]),
        ("requests", state.requests),
        ("errors", state.errors),
        ("filter", state.filter),
        ("sort", state.sort),
    ]
    row = top + 1
    for key, value in rows:
        widgets.safe_addstr(window, row, 2, f"{key.ljust(12)} {value}", 0, width=width - 4)
        row += 1
    row += 1
    widgets.safe_addstr(window, row, 2, widgets.progress_line(state, max(10, width - 20)), widgets.attr(colors["ok"]), width=width - 4)


def draw_help(window: Any, state: DashboardState, *, top: int, height: int, width: int) -> None:
    colors = _colors()
    widgets.draw_box(window, top, 0, height, width, "keyboard shortcuts", colors["accent"])
    row = top + 1
    for line in help_lines():
        if row >= top + height - 1:
            break
        widgets.safe_addstr(window, row, 2, widgets.truncate(line, width - 4), 0, width=width - 4)
        row += 1
    widgets.safe_addstr(window, top + height - 2, 2, "press any key to return", widgets.attr(colors["dim"]), width=width - 4)


def draw_detail(window: Any, state: DashboardState, *, top: int, height: int, width: int) -> None:
    colors = _colors()
    finding = state.current_finding()
    widgets.draw_box(window, top, 0, height, width, "finding detail", colors["accent"])
    if finding is None:
        widgets.safe_addstr(window, top + 2, 2, "no finding selected", widgets.attr(colors["dim"]), width=width - 4)
        return
    _finding_detail(window, finding, top + 1, 2, height - 2, width - 4)


VIEW_RENDERERS = {
    "dashboard": draw_dashboard,
    "findings": draw_findings,
    "detail": draw_detail,
    "proofs": draw_proofs,
    "stats": draw_stats,
    "help": draw_help,
}


def _colors() -> dict[str, int]:
    from candix.tui import app

    return getattr(app, "COLORS", {name: 0 for name in widgets.PAIRS})


def render(window: Any, state: DashboardState) -> None:
    height, width = window.getmaxyx()
    window.erase()
    colors = _colors()
    top = draw_header(window, state, width=width, colors=colors)
    body_height = max(3, height - top - FOOTER_HEIGHT)
    renderer = VIEW_RENDERERS.get(state.view, draw_dashboard)
    try:
        renderer(window, state, top=top, height=body_height, width=width)
    except Exception as exc:  # pragma: no cover - never let drawing kill the scan
        widgets.safe_addstr(window, top + 1, 2, f"render error: {exc}", widgets.attr(colors["error"]), width=width - 4)
    draw_footer(window, state, width=width, colors=colors)
    window.noutrefresh()
