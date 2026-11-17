"""Terminal user interface.

On platforms where ``curses`` is unavailable (e.g. Windows) the import is
deferred and a stub ``run_tui`` explains how to proceed instead of raising
``ModuleNotFoundError`` at import time.
"""

from __future__ import annotations

try:
    from candix.tui.app import run_tui  # type: ignore
except ImportError as _exc:  # pragma: no cover - Windows without curses
    import sys as _sys

    def run_tui(*_args, **_kwargs):  # type: ignore
        _sys.stderr.write(
            "TUI requires the 'curses' module which is unavailable on this platform (Windows). "
            "Install 'windows-curses' (pip install windows-curses) or run with --json for headless mode.\n"
        )
        return 2

__all__ = ["run_tui"]
