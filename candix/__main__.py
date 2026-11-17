"""``python -m candix`` entry point."""

from __future__ import annotations

import sys

if sys.version_info < (3, 11):
    sys.stderr.write(
        f"error: Candix requires Python 3.11+ (detected {sys.version.split()[0]}). "
        "Upgrade Python or use pyenv/conda with 3.11+.\n"
    )
    sys.exit(2)

from candix.cli.main import main

if __name__ == "__main__":  # pragma: no cover - process entry point
    raise SystemExit(main())
