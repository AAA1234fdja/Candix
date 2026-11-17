"""Terminal rendering helpers: colour, tables, boxes and finding summaries."""

from __future__ import annotations

import json
import os
import shutil
import sys
import textwrap
from datetime import datetime
from typing import Any, Iterable, Sequence

_COLORS = {
    "reset": "\033[0m",
    "bold": "\033[1m",
    "dim": "\033[2m",
    "red": "\033[31m",
    "green": "\033[32m",
    "yellow": "\033[33m",
    "blue": "\033[34m",
    "magenta": "\033[35m",
    "cyan": "\033[36m",
    "grey": "\033[90m",
    "white": "\033[97m",
}

SEVERITY_COLOR = {
    "critical": "magenta",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "info": "grey",
    "ok": "green",
    "warn": "yellow",
    "error": "red",
}

SEVERITY_GLYPH = {
    "critical": "!!",
    "high": "! ",
    "medium": "~ ",
    "low": "- ",
    "info": ". ",
}

ANSI_RESET = _COLORS["reset"]


def color_enabled(stream: Any = None) -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    target = stream or sys.stdout
    try:
        return bool(target.isatty())
    except Exception:
        return False


def paint(text: str, color: str = "", *, bold: bool = False, stream: Any = None) -> str:
    if not color_enabled(stream) or (not color and not bold):
        return text
    prefix = ""
    if color:
        prefix += _COLORS.get(color, "")
    if bold:
        prefix += _COLORS["bold"]
    if not prefix:
        return text
    return f"{prefix}{text}{ANSI_RESET}"


def severity_text(severity: str, *, width: int = 0) -> str:
    label = severity.upper() if width and len(severity) <= width else severity.upper()
    padded = label.ljust(width) if width else label
    return paint(padded, SEVERITY_COLOR.get(severity.lower(), "grey"), bold=severity.lower() in {"critical", "high"})


def term_width(default: int = 100) -> int:
    try:
        return max(60, shutil.get_terminal_size((default, 24)).columns)
    except Exception:
        return default


def rule(title: str = "", *, width: int | None = None, char: str = "─") -> str:
    span = width or term_width()
    if not title:
        return paint(char * span, "grey")
    label = f" {title} "
    remaining = max(0, span - len(label) - 2)
    left = remaining // 2
    right = remaining - left
    return paint(char * left, "grey") + paint(label, "bold") + paint(char * right, "grey")


def banner(version: str, *, subtitle: str = "") -> str:
    art = [
        "  ██████╗ █████╗ ███╗   ██╗██████╗ ██╗██╗  ██╗",
        " ██╔════╝██╔══██╗████╗  ██║██╔══██╗██║╚██╗██╔╝",
        " ██║     ███████║██╔██╗ ██║██║  ██║██║ ╚███╔╝ ",
        " ██║     ██╔══██║██║╚██╗██║██║  ██║██║ ██╔██╗ ",
        " ╚██████╗██║  ██║██║ ╚████║██████╔╝██║██╔╝ ██╗",
        "  ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═════╝ ╚═╝╚═╝  ╚═╝",
    ]
    lines = [paint(line, "cyan") for line in art]
    lines.append(paint(f"  offensive security harness · v{version}", "grey"))
    if subtitle:
        lines.append(paint(f"  {subtitle}", "grey"))
    return "\n".join(lines)


def kv_table(rows: Sequence[tuple[str, Any]], *, indent: int = 0) -> str:
    if not rows:
        return ""
    width = max(len(str(key)) for key, _ in rows)
    pad = " " * indent
    out = []
    for key, value in rows:
        out.append(f"{pad}{paint(str(key).ljust(width), 'grey')}  {value}")
    return "\n".join(out)


def table(
    headers: Sequence[str],
    rows: Iterable[Sequence[Any]],
    *,
    max_width: int | None = None,
    align: Sequence[str] | None = None,
) -> str:
    materialized = [[("" if cell is None else str(cell)) for cell in row] for row in rows]
    widths = [len(header) for header in headers]
    for row in materialized:
        for index, cell in enumerate(row):
            if index < len(widths):
                widths[index] = min(max(widths[index], len(cell)), 60)
    limit = max_width or term_width()
    while sum(widths) + 2 * (len(widths) - 1) > limit and len(widths) > 1:
        index = widths.index(max(widths))
        widths[index] = max(8, widths[index] - 2)
    out = []
    header_cells = []
    for index, header in enumerate(headers):
        text = header[: widths[index]].ljust(widths[index])
        header_cells.append(paint(text, "bold"))
    out.append("  ".join(header_cells))
    out.append(paint("  ".join("─" * width for width in widths), "grey"))
    for row in materialized:
        cells = []
        for index, width in enumerate(widths):
            cell = row[index] if index < len(row) else ""
            if len(cell) > width:
                cell = cell[: max(1, width - 1)] + "…"
            mode = (align[index] if align and index < len(align) else "l")
            cells.append(cell.rjust(width) if mode == "r" else cell.ljust(width))
        out.append("  ".join(cells))
    return "\n".join(out)


def box(lines: Sequence[str], *, title: str = "", color: str = "grey", width: int | None = None) -> str:
    content = [line for line in lines if line is not None]
    inner = max([len(_strip_ansi(line)) for line in content] + [len(title) + 2, 10])
    total = min(width or term_width(), inner + 4)
    top = "┌" + ("─" * (total - 2)) + "┐"
    bottom = "└" + ("─" * (total - 2)) + "┘"
    out = [paint(top, color)]
    if title:
        label = f" {title} "
        out.append(paint("│", color) + paint(label, "bold") + " " * max(0, total - len(label) - 2) + paint("│", color))
        out.append(paint("├" + "─" * (total - 2) + "┤", color))
    for line in content:
        visible = _strip_ansi(line)
        padding = max(0, total - 2 - len(visible))
        out.append(paint("│", color) + " " + line + " " * (padding - 1) + paint("│", color))
    out.append(paint(bottom, color))
    return "\n".join(out)


def _strip_ansi(text: str) -> str:
    import re

    return re.sub(r"\033\[[0-9;]*m", "", text)


def wrap(text: str, *, width: int | None = None, indent: str = "") -> str:
    return "\n".join(
        textwrap.fill(paragraph, width=width or term_width(), initial_indent=indent, subsequent_indent=indent)
        for paragraph in str(text).splitlines() or [""]
    )


def bullet_list(items: Iterable[str], *, marker: str = "•", color: str = "cyan") -> str:
    return "\n".join(f"  {paint(marker, color)} {item}" for item in items)


def format_bytes(value: int | float) -> str:
    units = ("B", "KiB", "MiB", "GiB", "TiB")
    size = float(value)
    for unit in units:
        if size < 1024 or unit == units[-1]:
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TiB"


def format_duration(seconds: float) -> str:
    from candix.core.clock import humanize_duration

    return humanize_duration(seconds)


def timestamp() -> str:
    return datetime.now().strftime("%H:%M:%S")


def print_json(payload: Any, *, stream: Any = None) -> None:
    target = stream or sys.stdout
    target.write(json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n")


def finding_line(finding: Any, *, show_url: bool = True) -> str:
    severity = finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity)
    glyph = SEVERITY_GLYPH.get(severity.lower(), "? ")
    head = f"{severity_text(severity.lower(), width=8)} {glyph} {finding.title}"
    if show_url:
        head += paint(f"  [{finding.method} {finding.url}]", "grey")
    return head


def finding_block(finding: Any, *, indent: str = "  ") -> str:
    severity = finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity)
    lines = [
        f"{indent}{severity_text(severity.lower(), width=8)} {paint(finding.title, 'bold')}",
        f"{indent}{paint('endpoint', 'grey')}   {finding.method} {finding.url}",
    ]
    if finding.parameter:
        lines.append(f"{indent}{paint('parameter', 'grey')}  {finding.parameter} ({finding.location})")
    if finding.vector:
        lines.append(f"{indent}{paint('cvss', 'grey')}       {finding.vector} → {finding.effective_score:.1f}")
    lines.append(f"{indent}{paint('confidence', 'grey')} {finding.confidence.value} · verified={finding.verified} · exploited={finding.exploited}")
    if finding.description:
        lines.append(wrap(finding.description, indent=indent + "  "))
    if finding.remediation.summary:
        lines.append(f"{indent}{paint('fix', 'green')}        {finding.remediation.summary}")
    return "\n".join(lines)


def counts_bar(counts: dict[str, int]) -> str:
    order = ("critical", "high", "medium", "low", "info")
    chunks = []
    for severity in order:
        count = counts.get(severity, 0)
        if not count:
            continue
        chunks.append(paint(f"{severity} {count}", SEVERITY_COLOR[severity], bold=severity in {"critical", "high"}))
    return " · ".join(chunks) if chunks else paint("no findings", "green")


def exit_hint() -> str:
    return paint("Run 'candix --help' for usage.", "grey")
