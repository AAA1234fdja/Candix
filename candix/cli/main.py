"""Console entry point."""

from __future__ import annotations

import os
import signal
import sys
import traceback

if sys.version_info < (3, 11):
    sys.stderr.write(
        f"error: Candix requires Python 3.11+ (detected {sys.version.split()[0]}). "
        "Upgrade Python or use pyenv/conda with 3.11+.\n"
    )
    sys.exit(2)
from typing import Any, Sequence

from candix.cli import output as out
from candix.cli.args import build_parser
from candix.cli.commands import COMMANDS, EXIT_ERROR, EXIT_USAGE
from candix.core.errors import CandixError


class Interrupted(Exception):
    pass


def _install_signals() -> None:
    def handler(signum: int, frame: Any) -> None:
        raise Interrupted(f"received signal {signum}")

    for name in ("SIGINT", "SIGTERM"):
        number = getattr(signal, name, None)
        if number is None:
            continue
        try:
            signal.signal(number, handler)
        except (ValueError, OSError):
            pass


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()
    if not arguments:
        parser.print_help()
        return 0
    try:
        args = parser.parse_args(arguments)
        for attribute, default in (("json_output", False), ("quiet", False), ("verbose", False), ("overrides", [])):
            if not hasattr(args, attribute):
                setattr(args, attribute, default)
    except SystemExit as exc:
        code = exc.code
        if isinstance(code, int):
            return code
        sys.stderr.write(f"{code}\n")
        return EXIT_USAGE
    command = getattr(args, "command", None)
    if not command:
        parser.print_help()
        return 0
    handler = COMMANDS.get(command)
    if handler is None:  # pragma: no cover - argparse guards this
        sys.stderr.write(f"unknown command: {command}\n")
        return EXIT_USAGE
    _install_signals()
    try:
        return int(handler(args) or 0)
    except Interrupted as exc:
        sys.stderr.write(f"\ninterrupted: {exc}\n")
        return 130
    except KeyboardInterrupt:
        sys.stderr.write("\ninterrupted\n")
        return 130
    except CandixError as exc:
        _report_error(exc, debug=bool(getattr(args, "verbose", False) or os.environ.get("CANDIX_DEBUG")))
        return exc.exit_code
    except BrokenPipeError:  # pragma: no cover - output truncated by a pager
        return 0
    except SystemExit as exc:
        code = exc.code
        return code if isinstance(code, int) else EXIT_ERROR
    except Exception as exc:  # pragma: no cover - unexpected failure
        if getattr(args, "verbose", False) or os.environ.get("CANDIX_DEBUG"):
            traceback.print_exc()
        sys.stderr.write(f"{out.paint('error', 'red', bold=True)} {exc}\n")
        sys.stderr.write(out.paint("  re-run with --verbose for a traceback\n", "grey"))
        return EXIT_ERROR


def _report_error(exc: CandixError, *, debug: bool) -> None:
    sys.stderr.write(f"{out.paint('error', 'red', bold=True)} {exc.message}\n")
    if exc.context:
        rows = []
        for key, value in sorted(exc.context.items()):
            if isinstance(value, (list, tuple)):
                value = ", ".join(str(item) for item in value)
            rows.append((key, str(value)))
        sys.stderr.write(out.kv_table(rows, indent=2) + "\n")
    sys.stderr.write(out.paint(f"  code: {exc.code}\n", "grey"))
    if debug:
        traceback.print_exc()


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
