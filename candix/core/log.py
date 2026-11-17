"""Structured logging and operator-facing progress output.

Two audiences exist: the operator watching a terminal, who wants readable
progress, and the report/audit trail, which needs machine-parseable events.
Both sink through the same logger so a redacted JSONL file can be shipped with
the deliverable.
"""

from __future__ import annotations

import json
import os
import sys
import threading
import time
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import Any, IO

from candix.core.clock import isoformat
from candix.core.redact import RedactionPolicy, SecretRegistry, redact_text

_LOCK = threading.Lock()


class Level(IntEnum):
    DEBUG = 10
    INFO = 20
    WARNING = 30
    ERROR = 40
    CRITICAL = 50

    @classmethod
    def parse(cls, value: str | int | "Level") -> "Level":
        if isinstance(value, Level):
            return value
        if isinstance(value, int):
            return cls(value)
        text = str(value).strip().upper()
        aliases = {"WARN": "WARNING", "FATAL": "CRITICAL", "TRACE": "DEBUG"}
        text = aliases.get(text, text)
        return cls[text]


_COLORS = {
    Level.DEBUG: "\033[38;5;244m",
    Level.INFO: "\033[38;5;39m",
    Level.WARNING: "\033[38;5;214m",
    Level.ERROR: "\033[38;5;196m",
    Level.CRITICAL: "\033[1;38;5;196m",
}
_RESET = "\033[0m"
_DIM = "\033[2m"


@dataclass
class LogRecord:
    level: Level
    message: str
    logger: str = "candix"
    event: str = ""
    fields: dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=isoformat)
    elapsed: float = 0.0


class Handler:
    """Base handler interface."""

    def emit(self, record: LogRecord) -> None:  # pragma: no cover - interface
        raise NotImplementedError

    def close(self) -> None:
        return None


class ConsoleHandler(Handler):
    def __init__(self, *, color: bool = True, stream: IO[str] | None = None, show_fields: bool = True) -> None:
        self.color = color and _supports_color()
        self.stream = stream or sys.stderr
        self.show_fields = show_fields

    def emit(self, record: LogRecord) -> None:
        prefix = f"[{record.timestamp[11:19]}]"
        level = record.level.name.lower().ljust(7)
        if self.color:
            color = _COLORS.get(record.level, "")
            level = f"{color}{level}{_RESET}"
            prefix = f"{_DIM}{prefix}{_RESET}"
        fields = ""
        if self.show_fields and record.fields:
            rendered = " ".join(f"{key}={_short(value)}" for key, value in record.fields.items())
            fields = " " + (f"{_DIM}{rendered}{_RESET}" if self.color else rendered)
        with _LOCK:
            self.stream.write(f"{prefix} {level} {record.message}{fields}\n")
            self.stream.flush()


class JsonlHandler(Handler):
    def __init__(self, path: str | Path, *, policy: RedactionPolicy | None = None, registry: SecretRegistry | None = None) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.policy = policy or RedactionPolicy()
        self.registry = registry
        self._handle = self.path.open("a", encoding="utf-8")

    def emit(self, record: LogRecord) -> None:
        payload = {
            "ts": record.timestamp,
            "level": record.level.name,
            "logger": record.logger,
            "event": record.event,
            "message": record.message,
            "fields": record.fields,
            "elapsed": round(record.elapsed, 3),
        }
        text = json.dumps(payload, ensure_ascii=False, default=str)
        if self.registry is not None:
            text = self.registry.apply(text)
        text = redact_text(text, self.policy)
        with _LOCK:
            self._handle.write(text + "\n")
            self._handle.flush()

    def close(self) -> None:
        self._handle.close()


class MemoryHandler(Handler):
    def __init__(self, capacity: int = 2000) -> None:
        self.capacity = capacity
        self.records: list[LogRecord] = []

    def emit(self, record: LogRecord) -> None:
        self.records.append(record)
        if len(self.records) > self.capacity:
            del self.records[: max(1, self.capacity // 10)]

    def by_level(self, level: Level) -> list[LogRecord]:
        return [record for record in self.records if record.level >= level]


def _short(value: Any, limit: int = 80) -> str:
    text = str(value)
    if len(text) > limit:
        text = text[: limit - 1] + "\u2026"
    return text.replace("\n", " ")


def _supports_color() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("TERM") == "dumb":
        return False
    return sys.stderr.isatty()


class Logger:
    """Small structured logger with bound context."""

    def __init__(
        self,
        name: str = "candix",
        *,
        level: Level = Level.INFO,
        handlers: list[Handler] | None = None,
        context: dict[str, Any] | None = None,
    ) -> None:
        self.name = name
        self.level = level
        self.handlers = handlers if handlers is not None else [ConsoleHandler()]
        self.context = context or {}
        self._started = time.monotonic()

    def bind(self, **context: Any) -> "Logger":
        merged = {**self.context, **context}
        return Logger(self.name, level=self.level, handlers=self.handlers, context=merged)

    def child(self, name: str) -> "Logger":
        return Logger(f"{self.name}.{name}", level=self.level, handlers=self.handlers, context=self.context)

    def log(self, level: Level, message: str, event: str = "", **fields: Any) -> None:
        if level < self.level:
            return
        record = LogRecord(
            level=level,
            message=message,
            logger=self.name,
            event=event,
            fields={**self.context, **fields},
            elapsed=time.monotonic() - self._started,
        )
        for handler in self.handlers:
            try:
                handler.emit(record)
            except Exception:  # pragma: no cover - logging must never break a scan
                continue

    def debug(self, message: str, **fields: Any) -> None:
        self.log(Level.DEBUG, message, **fields)

    def info(self, message: str, **fields: Any) -> None:
        self.log(Level.INFO, message, **fields)

    def warning(self, message: str, **fields: Any) -> None:
        self.log(Level.WARNING, message, **fields)

    def error(self, message: str, **fields: Any) -> None:
        self.log(Level.ERROR, message, **fields)

    def critical(self, message: str, **fields: Any) -> None:
        self.log(Level.CRITICAL, message, **fields)

    def event(self, name: str, message: str = "", **fields: Any) -> None:
        self.log(Level.INFO, message or name, event=name, **fields)

    def exception(self, message: str, **fields: Any) -> None:
        import traceback

        fields.setdefault("traceback", traceback.format_exc())
        self.log(Level.ERROR, message, **fields)

    def close(self) -> None:
        for handler in self.handlers:
            handler.close()


_DEFAULT_LOGGER = Logger()
_loggers: dict[str, Logger] = {}


def configure(
    *,
    level: str | Level = "info",
    log_file: str | Path | None = None,
    jsonl: bool = False,
    color: bool = True,
    quiet: bool = False,
    registry: SecretRegistry | None = None,
    policy: RedactionPolicy | None = None,
) -> Logger:
    global _DEFAULT_LOGGER
    handlers: list[Handler] = []
    if not quiet:
        handlers.append(ConsoleHandler(color=color))
    if log_file:
        if jsonl:
            handlers.append(JsonlHandler(log_file, policy=policy, registry=registry))
        else:
            handlers.append(PlainFileHandler(log_file, policy=policy, registry=registry))
    _DEFAULT_LOGGER = Logger(level=Level.parse(level), handlers=handlers or [MemoryHandler()])
    _loggers.clear()
    return _DEFAULT_LOGGER


def get_logger(name: str = "candix") -> Logger:
    if name not in _loggers:
        _loggers[name] = _DEFAULT_LOGGER.child(name) if name != "candix" else _DEFAULT_LOGGER
    return _loggers[name]


class PlainFileHandler(Handler):
    def __init__(self, path: str | Path, *, policy: RedactionPolicy | None = None, registry: SecretRegistry | None = None) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.policy = policy or RedactionPolicy()
        self.registry = registry
        self._handle = self.path.open("a", encoding="utf-8")

    def emit(self, record: LogRecord) -> None:
        fields = " ".join(f"{key}={value!r}" for key, value in record.fields.items())
        line = f"{record.timestamp} {record.level.name:<8} {record.logger} {record.message}"
        if fields:
            line += f" | {fields}"
        if self.registry is not None:
            line = self.registry.apply(line)
        with _LOCK:
            self._handle.write(redact_text(line, self.policy) + "\n")
            self._handle.flush()

    def close(self) -> None:
        self._handle.close()


class Progress:
    """Throttled progress reporting for long phases."""

    def __init__(self, logger: Logger, total: int, *, label: str = "progress", every: float = 1.0) -> None:
        self.logger = logger
        self.total = max(1, total)
        self.label = label
        self.every = every
        self.current = 0
        self._last = 0.0
        self._started = time.monotonic()

    def advance(self, count: int = 1, **fields: Any) -> None:
        self.current += count
        now = time.monotonic()
        if now - self._last < self.every and self.current < self.total:
            return
        self._last = now
        percent = min(100.0, 100.0 * self.current / self.total)
        elapsed = now - self._started
        rate = self.current / elapsed if elapsed > 0 else 0.0
        self.logger.info(
            f"{self.label}: {self.current}/{self.total} ({percent:.0f}%)",
            rate=f"{rate:.1f}/s",
            **fields,
        )

    def done(self, **fields: Any) -> None:
        elapsed = time.monotonic() - self._started
        self.logger.info(f"{self.label}: complete", items=self.current, elapsed=f"{elapsed:.1f}s", **fields)
