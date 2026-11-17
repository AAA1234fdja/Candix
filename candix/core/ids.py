"""Identifier generation.

Identifiers are short, sortable and collision resistant. Findings use a prefix
(``CDX-F``) so that operators can quote them in tickets without ambiguity, and
the embedded timestamp lets analysts sort evidence chronologically even when
the report is filtered.
"""

from __future__ import annotations

import hashlib
import secrets
import threading
import time
from typing import Final

_ALPHABET: Final[str] = "0123456789abcdefghijklmnopqrstuvwxyz"

_counter_lock = threading.Lock()
_counter = 0


def _base36(value: int, width: int = 4) -> str:
    if value == 0:
        return "0".rjust(width, "0")
    digits: list[str] = []
    while value:
        value, remainder = divmod(value, 36)
        digits.append(_ALPHABET[remainder])
    text = "".join(reversed(digits))
    return text.rjust(width, "0")


def _next_sequence() -> int:
    global _counter
    with _counter_lock:
        _counter += 1
        return _counter


def new_id(prefix: str = "cdx", *, width: int = 4) -> str:
    """Return a new identifier such as ``cdx-1lz9k2-0007``."""

    stamp = _base36(int(time.time() * 1000), width=8)
    sequence = _base36(_next_sequence(), width=width)
    return f"{prefix}-{stamp}-{sequence}"


def scan_id() -> str:
    return new_id("scan")


def finding_id() -> str:
    return new_id("CDX-F")


def evidence_id() -> str:
    return new_id("CDX-E", width=3)


def endpoint_id() -> str:
    return new_id("ep", width=5)


def task_id() -> str:
    return new_id("task", width=5)


def token(nbytes: int = 16) -> str:
    """Return a URL-safe random token suitable for markers and nonces."""

    return secrets.token_urlsafe(nbytes).replace("-", "a").replace("_", "b")


def marker(prefix: str = "cdx") -> str:
    """Return an alphanumeric marker that survives most shell and SQL contexts."""

    return f"{prefix}{secrets.token_hex(6)}"


def digest(data: bytes | str, *, length: int = 16) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8", "replace")
    return hashlib.sha256(data).hexdigest()[:length]


def sha256(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8", "replace")
    return hashlib.sha256(data).hexdigest()


def short_hash(*parts: object, length: int = 12) -> str:
    joined = "\x1f".join(str(part) for part in parts)
    return hashlib.blake2s(joined.encode("utf-8", "replace"), digest_size=16).hexdigest()[:length]
