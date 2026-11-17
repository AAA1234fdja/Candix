"""Time helpers.

The harness distinguishes wall-clock time (used in reports) from the monotonic
clock (used for budgets and latency measurements) because operators frequently
run scans on virtual machines whose wall clock drifts.
"""

from __future__ import annotations

import datetime as _dt
import re
import time
from dataclasses import dataclass, field
from typing import Final

UTC: Final[_dt.timezone] = _dt.timezone.utc

_DURATION_RE = re.compile(
    r"^\s*(?P<value>\d+(?:\.\d+)?)\s*(?P<unit>ms|s|m|h|d)?\s*$",
    re.IGNORECASE,
)

_UNIT_SECONDS: Final[dict[str, float]] = {
    "ms": 0.001,
    "s": 1.0,
    "m": 60.0,
    "h": 3600.0,
    "d": 86400.0,
}


def utcnow() -> _dt.datetime:
    return _dt.datetime.now(tz=UTC)


def isoformat(moment: _dt.datetime | None = None, *, timespec: str = "seconds") -> str:
    moment = moment or utcnow()
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    return moment.astimezone(UTC).isoformat(timespec=timespec).replace("+00:00", "Z")


def parse_time(value: str) -> _dt.datetime:
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    moment = _dt.datetime.fromisoformat(text)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    return moment.astimezone(UTC)


def parse_duration(value: str | int | float, *, default_unit: str = "s") -> float:
    """Parse ``"30"``, ``"250ms"``, ``"5m"`` or ``"2h"`` into seconds."""

    if isinstance(value, (int, float)):
        return float(value)
    match = _DURATION_RE.match(value)
    if not match:
        from candix.core.errors import ConfigError

        raise ConfigError(f"invalid duration: {value!r}")
    number = float(match.group("value"))
    unit = (match.group("unit") or default_unit).lower()
    return number * _UNIT_SECONDS[unit]


def humanize_duration(seconds: float) -> str:
    if seconds < 0.001:
        return f"{seconds * 1_000_000:.0f}us"
    if seconds < 1.0:
        return f"{seconds * 1000:.0f}ms"
    if seconds < 60.0:
        return f"{seconds:.2f}s"
    minutes, secs = divmod(seconds, 60.0)
    if minutes < 60:
        return f"{int(minutes)}m{secs:04.1f}s"
    hours, minutes = divmod(int(minutes), 60)
    return f"{hours}h{minutes:02d}m"


def humanize_bytes(count: float) -> str:
    units = ["B", "KiB", "MiB", "GiB", "TiB"]
    index = 0
    value = float(count)
    while value >= 1024.0 and index < len(units) - 1:
        value /= 1024.0
        index += 1
    return f"{value:.1f} {units[index]}" if index else f"{int(value)} B"


@dataclass
class Stopwatch:
    """Monotonic stopwatch with lap support."""

    started: float = field(default_factory=time.monotonic)
    laps: list[float] = field(default_factory=list)

    def reset(self) -> None:
        self.started = time.monotonic()
        self.laps.clear()

    def elapsed(self) -> float:
        return time.monotonic() - self.started

    def lap(self) -> float:
        now = time.monotonic()
        previous = self.started + sum(self.laps)
        delta = now - previous
        self.laps.append(delta)
        return delta

    def __enter__(self) -> "Stopwatch":
        self.reset()
        return self

    def __exit__(self, *exc: object) -> None:
        return None


class Deadline:
    """Cooperative deadline used by long running phases."""

    __slots__ = ("_seconds", "_started")

    def __init__(self, seconds: float) -> None:
        self._seconds = max(0.0, float(seconds))
        self._started = time.monotonic()

    @property
    def expired(self) -> bool:
        return self.remaining <= 0.0

    @property
    def remaining(self) -> float:
        return self._seconds - (time.monotonic() - self._started)

    def check(self) -> None:
        if self.expired:
            from candix.core.errors import BudgetExceeded

            raise BudgetExceeded("deadline exceeded", limit_seconds=self._seconds)
