"""``python -m candix`` entry point."""

from __future__ import annotations

from candix.cli.main import main

if __name__ == "__main__":  # pragma: no cover - process entry point
    raise SystemExit(main())
