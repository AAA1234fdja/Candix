"""Key handling for the dashboard."""

from __future__ import annotations

try:
    import curses  # type: ignore  # noqa: F401 - only needed for HAS_CURSES detection; actual use is via chr codes
    HAS_CURSES = True
except ImportError:
    curses = None  # type: ignore
    HAS_CURSES = False

from dataclasses import dataclass
from typing import Callable

from candix.tui.state import DashboardState

ACTION_QUIT = "quit"
ACTION_HELP = "help"
ACTION_DASHBOARD = "dashboard"
ACTION_FINDINGS = "findings"
ACTION_DETAIL = "detail"
ACTION_PROOFS = "proofs"
ACTION_STATS = "stats"
ACTION_SCROLL_UP = "scroll-up"
ACTION_SCROLL_DOWN = "scroll-down"
ACTION_PAGE_UP = "page-up"
ACTION_PAGE_DOWN = "page-down"
ACTION_NEXT = "next"
ACTION_PREVIOUS = "previous"
ACTION_FILTER = "filter"
ACTION_EXPORT = "export"
ACTION_TOGGLE_EXPLOIT = "toggle-exploit"
ACTION_PAUSE = "pause"
ACTION_TOP = "top"
ACTION_BOTTOM = "bottom"
ACTION_SORT = "sort"

BINDINGS: dict[str, str] = {
    "q": ACTION_QUIT,
    "\x1b": ACTION_QUIT,
    "?": ACTION_HELP,
    "h": ACTION_HELP,
    "d": ACTION_DASHBOARD,
    "f": ACTION_FINDINGS,
    "\r": ACTION_DETAIL,
    "\n": ACTION_DETAIL,
    "p": ACTION_PROOFS,
    "s": ACTION_STATS,
    "k": ACTION_SCROLL_UP,
    "\x1b[A": ACTION_SCROLL_UP,
    "j": ACTION_SCROLL_DOWN,
    "\x1b[B": ACTION_SCROLL_DOWN,
    "\x1b[5~": ACTION_PAGE_UP,
    "\x1b[6~": ACTION_PAGE_DOWN,
    "\x1b[C": ACTION_NEXT,
    "\x1b[D": ACTION_PREVIOUS,
    "n": ACTION_NEXT,
    "b": ACTION_PREVIOUS,
    "/": ACTION_FILTER,
    "e": ACTION_EXPORT,
    "x": ACTION_TOGGLE_EXPLOIT,
    " ": ACTION_PAUSE,
    "g": ACTION_TOP,
    "G": ACTION_BOTTOM,
    "o": ACTION_SORT,
}

ACTION_HELP_TEXT = {
    ACTION_QUIT: "quit the dashboard",
    ACTION_HELP: "show this help",
    ACTION_DASHBOARD: "dashboard view",
    ACTION_FINDINGS: "findings list",
    ACTION_DETAIL: "open the selected finding",
    ACTION_PROOFS: "proofs view",
    ACTION_STATS: "statistics view",
    ACTION_SCROLL_UP: "scroll up",
    ACTION_SCROLL_DOWN: "scroll down",
    ACTION_PAGE_UP: "page up",
    ACTION_PAGE_DOWN: "page down",
    ACTION_NEXT: "next item",
    ACTION_PREVIOUS: "previous item",
    ACTION_FILTER: "filter findings by severity",
    ACTION_EXPORT: "write the current report",
    ACTION_TOGGLE_EXPLOIT: "enable exploitation for the next run",
    ACTION_PAUSE: "pause or resume drawing",
    ACTION_TOP: "jump to the first item",
    ACTION_BOTTOM: "jump to the last item",
    ACTION_SORT: "cycle the sort order",
}


@dataclass
class KeyEvent:
    action: str
    key: str = ""
    text: str = ""


def key_to_action(ch: int, *, screen: "curses.window | None" = None) -> str | None:
    if ch == -1:
        return None
    try:
        text = chr(ch)
    except (ValueError, OverflowError):
        return None
    return BINDINGS.get(text)


def handle_action(state: DashboardState, action: str) -> str:
    """Apply non-navigational actions to the state; returns an instruction."""

    if action == ACTION_FILTER:
        state.cycle_filter()
    elif action == ACTION_SORT:
        state.cycle_sort()
    elif action == ACTION_TOGGLE_EXPLOIT:
        state.exploit_enabled = not state.exploit_enabled
        state.push_event(f"exploitation {'enabled' if state.exploit_enabled else 'disabled'} for the next run")
    elif action == ACTION_PAUSE:
        state.paused = not state.paused
    elif action == ACTION_SCROLL_UP:
        state.scroll = max(0, state.scroll - 1)
    elif action == ACTION_SCROLL_DOWN:
        state.scroll += 1
    elif action == ACTION_PAGE_UP:
        state.scroll = max(0, state.scroll - 10)
    elif action == ACTION_PAGE_DOWN:
        state.scroll += 10
    elif action == ACTION_TOP:
        state.scroll = 0
    elif action == ACTION_NEXT:
        state.select_next()
    elif action == ACTION_PREVIOUS:
        state.select_previous()
    return action


def help_lines() -> list[str]:
    return [f"  {key:<8} {description}" for key, description in sorted(
        ((key, ACTION_HELP_TEXT.get(action, action)) for key, action in BINDINGS.items() if key.isprintable()),
        key=lambda pair: pair[1],
    )]
