"""Session and cookie analysis."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import math
import re
import time
from dataclasses import dataclass, field
from typing import Any, Iterable

SESSION_COOKIE_HINTS = ("session", "sess", "sid", "auth", "token", "jwt", "remember", "logged")
WEAK_VALUES = ("admin", "test", "guest", "user", "1", "true", "yes", "dev", "debug")
_FLAG_ATTRS = ("httponly", "secure", "samesite", "path", "domain", "expires", "max-age", "priority", "partitioned")


@dataclass
class SessionCookie:
    name: str
    value: str
    attributes: dict[str, str] = field(default_factory=dict)
    host: str = ""

    @property
    def flags(self) -> set[str]:
        return {key.lower() for key in self.attributes}

    @property
    def secure(self) -> bool:
        return "secure" in self.flags

    @property
    def httponly(self) -> bool:
        return "httponly" in self.flags

    @property
    def samesite(self) -> str:
        return self.attributes.get("SameSite", self.attributes.get("samesite", "")).lower()

    @property
    def entropy(self) -> float:
        return shannon_entropy(self.value)

    @property
    def looks_like_session(self) -> bool:
        name = self.name.lower()
        return any(hint in name for hint in SESSION_COOKIE_HINTS) or len(self.value) >= 24

    def issues(self) -> list[str]:
        problems: list[str] = []
        if not self.httponly:
            problems.append("cookie is readable from JavaScript (no HttpOnly)")
        if not self.secure:
            problems.append("cookie is sent over plain HTTP (no Secure)")
        if self.samesite not in {"lax", "strict"}:
            problems.append("SameSite is missing or None")
        if self.value.lower() in WEAK_VALUES:
            problems.append("cookie value is a well-known weak value")
        if 0 < self.entropy < 3.0 and len(self.value) < 32:
            problems.append("cookie value has low entropy")
        if re.fullmatch(r"\d+", self.value or ""):
            problems.append("cookie value is a sequential identifier")
        return problems

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "value_length": len(self.value),
            "attributes": dict(self.attributes),
            "entropy": round(self.entropy, 2),
            "issues": self.issues(),
            "host": self.host,
        }


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    entropy = 0.0
    for count in counts.values():
        p = count / len(value)
        entropy -= p * math.log2(p)
    return entropy


def parse_set_cookie(header: str, *, host: str = "") -> SessionCookie:
    parts = [item.strip() for item in header.split(";") if item.strip()]
    name, _, value = parts[0].partition("=") if parts else ("", "", "")
    attributes: dict[str, str] = {}
    for item in parts[1:]:
        key, _, attr_value = item.partition("=")
        attributes[key.strip()] = attr_value.strip()
    return SessionCookie(name=name.strip(), value=value.strip(), attributes=attributes, host=host)


def classify_value(value: str) -> str:
    if re.fullmatch(r"\d{4,}", value or ""):
        return "numeric"
    if value and value.isalnum() and len(value) in {16, 32, 40, 64}:
        return "hex-or-hash"
    if _looks_like_jwt(value):
        return "jwt"
    if _looks_like_base64(value):
        try:
            decoded = base64.b64decode(value + "=" * (-len(value) % 4))
            if decoded and all(32 <= byte < 127 for byte in decoded[:32]):
                return "base64-text"
        except (binascii.Error, ValueError):
            return "base64-binary"
        return "base64-binary"
    if value.count(":") >= 1 and value.count(":") <= 3:
        return "delimited"
    return "opaque"


def _looks_like_jwt(value: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*", value or ""))


def _looks_like_base64(value: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z0-9+/=_-]{12,}", value or ""))


def cookie_fingerprint(cookies: Iterable[SessionCookie]) -> str:
    payload = "|".join(sorted(f"{cookie.name}={cookie.value}" for cookie in cookies))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


@dataclass
class SessionReport:
    cookies: list[SessionCookie] = field(default_factory=list)
    rotated: bool | None = None
    fixation_suspected: bool = False
    issues: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "cookies": [cookie.to_dict() for cookie in self.cookies],
            "rotated": self.rotated,
            "fixation_suspected": self.fixation_suspected,
            "issues": list(self.issues),
            "notes": list(self.notes),
        }

    def summary(self) -> str:
        risky = sum(1 for cookie in self.cookies if cookie.issues())
        return f"{len(self.cookies)} cookies, {risky} with issues, fixation={self.fixation_suspected}"


def analyse_cookies(cookies: Iterable[SessionCookie]) -> SessionReport:
    report = SessionReport(cookies=list(cookies))
    seen_issues: set[str] = set()
    for cookie in report.cookies:
        for issue in cookie.issues():
            if issue in seen_issues:
                continue
            seen_issues.add(issue)
            report.issues.append(f"{cookie.name}: {issue}")
    return report


def compare_sessions(before: Iterable[SessionCookie], after: Iterable[SessionCookie]) -> SessionReport:
    old = {cookie.name: cookie for cookie in before}
    new = {cookie.name: cookie for cookie in after}
    report = analyse_cookies(new.values())
    session_names = [name for name, cookie in new.items() if cookie.looks_like_session]
    if not session_names:
        report.notes.append("no session-like cookie was observed after authentication")
        return report
    rotated = all(name in old and old[name].value != new[name].value for name in session_names if name in old)
    report.rotated = rotated
    if not rotated and any(name in old for name in session_names):
        report.fixation_suspected = True
        report.issues.append("session identifier did not change after authentication (possible fixation)")
    return report


def predictable_sequence(values: Iterable[str]) -> bool:
    numbers = []
    for value in values:
        if value.isdigit():
            numbers.append(int(value))
        else:
            return False
    if len(numbers) < 3:
        return False
    steps = [b - a for a, b in zip(numbers, numbers[1:])]
    return len(set(steps)) == 1


def sign_cookie(name: str, value: str, secret: str) -> str:
    signature = hmac.new(secret.encode("utf-8"), f"{name}={value}".encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{value}.{signature[:16]}"


def verify_cookie(name: str, signed: str, secret: str) -> bool:
    value, _, signature = signed.rpartition(".")
    if not signature:
        return False
    return hmac.compare_digest(sign_cookie(name, value, secret).rpartition(".")[2], signature)


def session_age(cookie: SessionCookie, *, now: float | None = None) -> float | None:
    expires = cookie.attributes.get("Expires") or cookie.attributes.get("expires")
    if not expires:
        return None
    from email.utils import parsedate_to_datetime

    try:
        parsed = parsedate_to_datetime(expires)
    except (TypeError, ValueError):
        return None
    return parsed.timestamp() - (now or time.time())


def dump_report(report: SessionReport) -> str:
    return json.dumps(report.to_dict(), indent=2, sort_keys=True)
