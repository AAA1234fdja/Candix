"""Response comparison.

Detectors reason about *change*, not absolute responses: a payload is
interesting when it changes the status code, the length, the structure or the
timing relative to a control request. The comparison here is intentionally
conservative - volatile tokens, CSRF nonces and timestamps are normalised first
so that ordinary page churn does not look like an injection.
"""

from __future__ import annotations

import difflib
import re
from dataclasses import dataclass, field
from typing import Any, Iterable

from candix.net.http import Response

_VOLATILE_PATTERNS = (
    re.compile(r"\b[0-9a-f]{32,}\b", re.IGNORECASE),
    re.compile(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?\b"),
    re.compile(r"\bcsrf[_-]?token[=:\"'\s]+[A-Za-z0-9_-]{8,}", re.IGNORECASE),
    re.compile(r"\bnonce[=:\"'\s]+[A-Za-z0-9_-]{8,}", re.IGNORECASE),
    re.compile(r"\b\d{10,13}\b"),
)


def normalize(text: str, *, max_chars: int = 200_000) -> str:
    value = (text or "")[:max_chars]
    for pattern in _VOLATILE_PATTERNS:
        value = pattern.sub("<volatile>", value)
    return value


def similarity(a: str, b: str) -> float:
    left = normalize(a)
    right = normalize(b)
    if not left and not right:
        return 1.0
    if not left or not right:
        return 0.0
    matcher = difflib.SequenceMatcher(None, left[:50_000], right[:50_000], autojunk=False)
    return matcher.quick_ratio() * 0.5 + matcher.ratio() * 0.5


@dataclass
class ResponseDiff:
    baseline_status: int = 0
    attack_status: int = 0
    status_changed: bool = False
    baseline_length: int = 0
    attack_length: int = 0
    length_delta: int = 0
    relative_length_change: float = 0.0
    similarity: float = 1.0
    body_changed: bool = False
    headers_added: dict[str, str] = field(default_factory=dict)
    headers_removed: list[str] = field(default_factory=list)
    time_delta: float = 0.0
    time_ratio: float = 1.0
    identical: bool = False
    added_tokens: list[str] = field(default_factory=list)
    removed_tokens: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "baseline_status": self.baseline_status,
            "attack_status": self.attack_status,
            "status_changed": self.status_changed,
            "baseline_length": self.baseline_length,
            "attack_length": self.attack_length,
            "length_delta": self.length_delta,
            "similarity": round(self.similarity, 4),
            "body_changed": self.body_changed,
            "time_delta": round(self.time_delta, 4),
            "time_ratio": round(self.time_ratio, 3),
            "headers_added": self.headers_added,
            "headers_removed": self.headers_removed,
            "identical": self.identical,
        }

    @property
    def significant(self) -> bool:
        """Whether the change is large enough to warrant a closer look."""

        if self.status_changed and self.attack_status >= 500:
            return True
        if self.attack_status in {401, 403} and self.baseline_status not in {401, 403}:
            return True
        if abs(self.length_delta) > max(32, self.baseline_length * 0.05):
            return True
        return self.similarity < 0.92

    def summary(self) -> str:
        pieces = [f"{self.baseline_status}->{self.attack_status}"]
        if self.length_delta:
            pieces.append(f"{self.length_delta:+d}B")
        pieces.append(f"sim={self.similarity:.2f}")
        if abs(self.time_delta) > 0.5:
            pieces.append(f"dt={self.time_delta:+.2f}s")
        return " ".join(pieces)


def compare_responses(baseline: Response, attack: Response, *, include_tokens: bool = False) -> ResponseDiff:
    baseline_body = normalize(baseline.text)
    attack_body = normalize(attack.text)
    diff = ResponseDiff(
        baseline_status=baseline.status,
        attack_status=attack.status,
        status_changed=baseline.status != attack.status,
        baseline_length=len(baseline.content),
        attack_length=len(attack.content),
        length_delta=len(attack.content) - len(baseline.content),
        similarity=similarity(baseline_body, attack_body),
        time_delta=attack.elapsed - baseline.elapsed,
        time_ratio=(attack.elapsed / baseline.elapsed) if baseline.elapsed > 0 else 1.0,
    )
    if diff.baseline_length:
        diff.relative_length_change = diff.length_delta / diff.baseline_length
    diff.body_changed = baseline_body != attack_body
    diff.identical = (
        baseline.status == attack.status
        and baseline.content == attack.content
        and baseline_body == attack_body
    )
    baseline_headers = {name.lower(): value for name, value in baseline.headers.items()}
    attack_headers = {name.lower(): value for name, value in attack.headers.items()}
    for name, value in attack_headers.items():
        if name not in baseline_headers:
            diff.headers_added[name] = value
        elif baseline_headers[name] != value and name in {"location", "content-type", "allow", "x-powered-by"}:
            diff.headers_added[name] = value
    diff.headers_removed = [name for name in baseline_headers if name not in attack_headers]
    if include_tokens:
        diff.added_tokens, diff.removed_tokens = token_delta(baseline_body, attack_body)
    return diff


def token_delta(before: str, after: str, *, limit: int = 40) -> tuple[list[str], list[str]]:
    before_tokens = re.findall(r"[A-Za-z0-9_./:-]{4,}", before)
    after_tokens = re.findall(r"[A-Za-z0-9_./:-]{4,}", after)
    before_counts: dict[str, int] = {}
    for token in before_tokens:
        before_counts[token] = before_counts.get(token, 0) + 1
    after_counts: dict[str, int] = {}
    for token in after_tokens:
        after_counts[token] = after_counts.get(token, 0) + 1
    added = [token for token in after_counts if token not in before_counts][:limit]
    removed = [token for token in before_counts if token not in after_counts][:limit]
    return added, removed


def diff_lines(before: str, after: str, *, context: int = 2, limit: int = 200) -> list[str]:
    left = normalize(before).splitlines()
    right = normalize(after).splitlines()
    diff = difflib.unified_diff(left, right, fromfile="baseline", tofile="probe", n=context, lineterm="")
    result: list[str] = []
    for index, line in enumerate(diff):
        if index >= limit:
            result.append("... diff truncated ...")
            break
        result.append(line)
    return result


def stable_hash(response: Response, *, ignore_volatile: bool = True) -> str:
    import hashlib

    body = normalize(response.text) if ignore_volatile else response.text
    digest = hashlib.sha256()
    digest.update(str(response.status).encode())
    digest.update(b"\x00")
    digest.update(body.encode("utf-8", "replace"))
    return digest.hexdigest()


def looks_like_error_page(text: str) -> bool:
    lowered = (text or "")[:5000].lower()
    markers = (
        "sql syntax",
        "mysql_fetch",
        "ora-0",
        "postgresql",
        "odbc sql server driver",
        "unclosed quotation mark",
        "stack trace",
        "traceback (most recent call last)",
        "warning: include(",
        "warning: require(",
        "fatal error",
        "javax.servlet",
        "org.springframework",
        "internal server error",
        "whitelabel error page",
        "template syntax error",
        "unexpected token",
        "you have an error in your sql",
    )
    return any(marker in lowered for marker in markers)


def extract_error_signatures(text: str) -> list[str]:
    lowered = (text or "")[:20000].lower()
    signatures = {
        "mysql": ("you have an error in your sql", "mysql_fetch", "mysqli", "sql syntax"),
        "postgres": ("postgresql", "pg_query", "psql:", "unterminated quoted string"),
        "mssql": ("microsoft ole db", "odbc sql server", "unclosed quotation mark", "sqlserver"),
        "oracle": ("ora-", "oracle error", "pls-"),
        "sqlite": ("sqlite", "sqlite3", "no such table"),
        "php": ("fatal error", "parse error", "warning: ", "notice: "),
        "python": ("traceback (most recent call last)", "django", "werkzeug", "jinja2"),
        "java": ("java.lang.", "org.springframework", "javax.servlet", "stacktrace"),
        "node": ("node.js", "express", "typeerror:", "referenceerror:"),
        "ruby": ("actioncontroller", "activerecord", "ruby on rails"),
    }
    found: list[str] = []
    for name, markers in signatures.items():
        if any(marker in lowered for marker in markers):
            found.append(name)
    return found


def compare_bodies(baseline: str, attack: str) -> dict[str, Any]:
    diff = ResponseDiff(
        baseline_length=len(baseline),
        attack_length=len(attack),
        length_delta=len(attack) - len(baseline),
        similarity=similarity(baseline, attack),
    )
    diff.body_changed = normalize(baseline) != normalize(attack)
    diff.identical = baseline == attack
    return diff.to_dict()


def detect_reflection_delta(baseline: Response, attack: Response, marker: str) -> int:
    before = baseline.text.count(marker)
    after = attack.text.count(marker)
    return after - before


def find_header_differences(responses: Iterable[Response]) -> dict[str, set[str]]:
    result: dict[str, set[str]] = {}
    for response in responses:
        for name, value in response.headers.items():
            result.setdefault(name.lower(), set()).add(value)
    return {name: values for name, values in result.items() if len(values) > 1}
