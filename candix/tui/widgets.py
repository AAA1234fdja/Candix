"""Drawing primitives for the curses dashboard."""

from __future__ import annotations

import curses
from typing import Any, Iterable, Sequence

PAIRS = {
    "default": 0,
    "title": 1,
    "dim": 2,
    "ok": 3,
    "warn": 4,
    "error": 5,
    "critical": 6,
    "high": 7,
    "medium": 8,
    "low": 9,
    "accent": 10,
}

SEVERITY_PAIR = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "dim",
}

BAR_CHARS = " ▏▎▍▌▋▊▉█"


def init_colors() -> dict[str, int]:
    """Initialise colour pairs; falls back to a monochrome theme when unavailable."""

    mapping = dict(PAIRS)
    if not curses.has_colors():
        return {name: 0 for name in mapping}
    curses.start_color()
    try:
        curses.use_default_colors()
        background = -1
    except curses.error:
        background = curses.COLOR_BLACK
    definitions = {
        "title": (curses.COLOR_CYAN, background),
        "dim": (curses.COLOR_WHITE, background),
        "ok": (curses.COLOR_GREEN, background),
        "warn": (curses.COLOR_YELLOW, background),
        "error": (curses.COLOR_RED, background),
        "critical": (curses.COLOR_MAGENTA, background),
        "high": (curses.COLOR_RED, background),
        "medium": (curses.COLOR_YELLOW, background),
        "low": (curses.COLOR_CYAN, background),
        "accent": (curses.COLOR_BLUE, background),
    }
    for name, (foreground, bg) in definitions.items():
        try:
            curses.init_pair(mapping[name], foreground, bg)
        except curses.error:  # pragma: no cover - terminal limits
            mapping[name] = 0
    return mapping


def attr(pair: int, *, bold: bool = False) -> int:
    value = curses.color_pair(pair) if pair else 0
    if bold:
        value |= curses.A_BOLD
    return value


def safe_addstr(window: Any, y: int, x: int, text: str, attrs: int = 0, *, width: int | None = None) -> None:
    height, columns = window.getmaxyx()
    if y < 0 or y >= height or x >= columns:
        return
    limit = (width if width is not None else columns - x) - 1
    if limit <= 0:
        return
    try:
        window.addnstr(y, x, text, max(0, min(limit, columns - x - 1)), attrs)
    except curses.error:  # pragma: no cover - writing the last cell raises
        pass


def draw_box(window: Any, y: int, x: int, height: int, width: int, title: str = "", pair: int = 0) -> None:
    screen_h, screen_w = window.getmaxyx()
    if height < 3 or width < 4 or y + height > screen_h or x + width > screen_w:
        return
    style = attr(pair)
    try:
        window.attron(style)
        window.hline(y, x + 1, curses.ACS_HLINE, width - 2)
        window.hline(y + height - 1, x + 1, curses.ACS_HLINE, width - 2)
        window.vline(y + 1, x, curses.ACS_VLINE, height - 2)
        window.vline(y + 1, x + width - 1, curses.ACS_VLINE, height - 2)
        window.addch(y, x, curses.ACS_ULCORNER)
        window.addch(y, x + width - 1, curses.ACS_URCORNER)
        window.addch(y + height - 1, x, curses.ACS_LLCORNER)
        window.addch(y + height - 1, x + width - 1, curses.ACS_LRCORNER)
        window.attroff(style)
    except curses.error:  # pragma: no cover
        pass
    if title:
        label = f" {title[: max(0, width - 6)]} "
        safe_addstr(window, y, x + 2, label, attr(pair, bold=True), width=width - 4)


def draw_bar(window: Any, y: int, x: int, width: int, ratio: float, pair: int) -> None:
    ratio = max(0.0, min(1.0, ratio))
    filled = int(round(width * ratio))
    style = attr(pair)
    try:
        window.addstr(y, x, "█" * filled, style)
        window.addstr(y, x + filled, "░" * max(0, width - filled), attr(0))
    except curses.error:  # pragma: no cover
        pass


def draw_table(
    window: Any,
    y: int,
    x: int,
    width: int,
    headers: Sequence[str],
    rows: Iterable[Sequence[Any]],
    *,
    column_widths: Sequence[int] | None = None,
    highlight: int = -1,
    max_rows: int | None = None,
) -> int:
    """Draw a simple aligned table; returns the next free line."""

    widths = list(column_widths or _fit_columns(headers, width))
    safe_addstr(window, y, x, _join(headers, widths), attr(PAIRS["title"], bold=True), width=width)
    y += 1
    safe_addstr(window, y, x, "─" * min(width - 1, sum(widths) + 2 * (len(widths) - 1)), attr(PAIRS["dim"]), width=width)
    y += 1
    for index, row in enumerate(rows):
        if max_rows is not None and index >= max_rows:
            break
        style = attr(PAIRS["accent"], bold=True) if index == highlight else 0
        safe_addstr(window, y, x, _join([str(cell) for cell in row], widths), style, width=width)
        y += 1
    return y


def _fit_columns(headers: Sequence[str], width: int) -> list[int]:
    count = max(1, len(headers))
    base = max(8, (width - 2 * (count - 1)) // count)
    return [base for _ in headers]


def _join(cells: Sequence[str], widths: Sequence[int]) -> str:
    parts = []
    for index, width in enumerate(widths):
        cell = cells[index] if index < len(cells) else ""
        if len(cell) > width:
            cell = cell[: max(0, width - 1)] + "…"
        parts.append(cell.ljust(width))
    return "  ".join(parts).rstrip()


def severity_chip(counts: dict[str, int], width: int) -> str:
    order = ("critical", "high", "medium", "low", "info")
    chunks = [f"{severity[0].upper()}{counts.get(severity, 0)}" for severity in order if counts.get(severity, 0)]
    text = " ".join(chunks) if chunks else "clean"
    return text[:width]


def sparkline(values: Sequence[float], width: int) -> str:
    if not values:
        return ""
    sampled = list(values)[-width:]
    peak = max(sampled) or 1.0
    chars = " ▁▂▃▄▅▆▇█"
    return "".join(chars[min(len(chars) - 1, int(value / peak * (len(chars) - 1)))] for value in sampled)


def wrap_text(text: str, width: int) -> list[str]:
    words = str(text).split()
    lines: list[str] = []
    current = ""
    for word in words:
        if not current:
            current = word
            continue
        if len(current) + 1 + len(word) <= width:
            current += " " + word
        else:
            lines.append(current)
            current = word
    if current:
        lines.append(current)
    return lines or [""]


def truncate(text: str, width: int) -> str:
    text = str(text)
    return text if len(text) <= width else text[: max(0, width - 1)] + "…"


def center(text: str, width: int) -> str:
    text = truncate(text, width)
    padding = max(0, (width - len(text)) // 2)
    return " " * padding + text


def footer(items: Sequence[tuple[str, str]], width: int) -> str:
    chunks = [f"[{key}] {label}" for key, label in items]
    text = "  ".join(chunks)
    return truncate(text, width)


def progress_line(state: Any, width: int) -> str:
    ratio = state.progress()
    filled = int(width * ratio)
    bar = "█" * filled + "░" * max(0, width - filled)
    return f"{bar} {ratio * 100:3.0f}%"


def severities() -> list[str]:
    return ["critical", "high", "medium", "low", "info"]


def divider(width: int) -> str:
    return "─" * max(0, width - 1)
