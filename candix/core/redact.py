"""Secret redaction for evidence, logs and reports.

Evidence frequently contains bearer tokens, session cookies and credentials
harvested during a test. Those values are useful for the operator while the
engagement is running but must never reach the deliverable, so every rendering
path funnels through this module.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Final, Iterable

REDACTED: Final[str] = "[REDACTED]"

_SENSITIVE_HEADERS: Final[frozenset[str]] = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "x-auth-token",
        "x-csrf-token",
        "x-xsrf-token",
        "x-amz-security-token",
        "x-goog-api-key",
        "api-key",
        "apikey",
        "authentication",
        "www-authenticate",
        "proxy-authenticate",
    }
)

_SENSITIVE_PARAMS: Final[frozenset[str]] = frozenset(
    {
        "password",
        "passwd",
        "pass",
        "pwd",
        "secret",
        "client_secret",
        "token",
        "access_token",
        "refresh_token",
        "id_token",
        "api_key",
        "apikey",
        "private_key",
        "session",
        "sessionid",
        "sid",
        "auth",
        "authorization",
        "otp",
        "mfa",
        "credit_card",
        "card_number",
        "cvv",
        "ssn",
    }
)

_PATTERNS: Final[tuple[tuple[str, re.Pattern[str]], ...]] = (
    (
        "jwt",
        re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\b"),
    ),
    (
        "aws_access_key",
        re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA)[A-Z0-9]{16}\b"),
    ),
    (
        "aws_secret",
        re.compile(r"(?i)aws_secret_access_key\s*[:=]\s*[A-Za-z0-9/+=]{32,}"),
    ),
    (
        "github_token",
        re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    ),
    (
        "gitlab_token",
        re.compile(r"\bglpat-[A-Za-z0-9_-]{16,}\b"),
    ),
    (
        "slack_token",
        re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}\b"),
    ),
    (
        "private_key",
        re.compile(
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----.*?-----END (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----",
            re.DOTALL,
        ),
    ),
    (
        "google_api_key",
        re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b"),
    ),
    (
        "stripe_key",
        re.compile(r"\b(?:sk|pk|rk)_(?:live|test)_[0-9A-Za-z]{16,}\b"),
    ),
    (
        "basic_auth",
        re.compile(r"(?i)authorization\s*:\s*basic\s+[A-Za-z0-9+/=]{8,}"),
    ),
    (
        "bearer",
        re.compile(r"(?i)bearer\s+[A-Za-z0-9._~+/=-]{12,}"),
    ),
    (
        "password_field",
        re.compile(r"(?i)(password|passwd|pwd|secret|token)\s*[=:]\s*([\"']?)([^\s&\"',;]{4,})\2"),
    ),
    (
        "email",
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    ),
    (
        "credit_card",
        re.compile(r"\b(?:\d[ -]*?){13,19}\b"),
    ),
)


@dataclass(frozen=True)
class RedactionPolicy:
    """Controls how aggressively evidence is scrubbed."""

    level: str = "standard"  # none | standard | strict
    mask_emails: bool = False
    mask_cards: bool = True
    keep_length: bool = False
    extra_terms: tuple[str, ...] = ()

    @classmethod
    def parse(cls, value: str | "RedactionPolicy" | None) -> "RedactionPolicy":
        if isinstance(value, RedactionPolicy):
            return value
        text = (value or "standard").strip().lower()
        if text == "none":
            return cls(level="none")
        if text == "strict":
            return cls(level="strict", mask_emails=True, mask_cards=True)
        return cls(level="standard")

    def _mask(self, value: str) -> str:
        if self.keep_length and len(value) > 8:
            return value[:2] + "*" * (len(value) - 4) + value[-2:]
        return REDACTED


def redact_text(text: str, policy: RedactionPolicy | None = None) -> str:
    """Redact well-known secret formats from free-form text."""

    policy = policy or RedactionPolicy()
    if policy.level == "none" or not text:
        return text
    result = text
    for name, pattern in _PATTERNS:
        if name == "email" and not policy.mask_emails:
            continue
        if name == "credit_card":
            if not policy.mask_cards:
                continue
            result = pattern.sub(lambda m: _mask_card(m.group(0)), result)
            continue
        if name == "password_field":
            def _replace(match: re.Match[str]) -> str:
                return f"{match.group(1)}{'=' if '=' in match.group(0) else ':'}{policy._mask(match.group(3))}"

            result = pattern.sub(_replace, result)
            continue
        result = pattern.sub(policy._mask, result)
    for term in policy.extra_terms:
        if term:
            result = result.replace(term, REDACTED)
    return result


def _mask_card(value: str) -> str:
    digits = re.sub(r"\D", "", value)
    if not (13 <= len(digits) <= 19):
        return value
    if not _luhn(digits):
        return value
    return f"{digits[:4]}{'*' * (len(digits) - 8)}{digits[-4:]}"


def _luhn(number: str) -> bool:
    total = 0
    reverse = number[::-1]
    for index, char in enumerate(reverse):
        digit = int(char)
        if index % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def redact_headers(
    headers: dict[str, str] | Iterable[tuple[str, str]],
    policy: RedactionPolicy | None = None,
) -> dict[str, str]:
    policy = policy or RedactionPolicy()
    items = headers.items() if isinstance(headers, dict) else headers
    result: dict[str, str] = {}
    for name, value in items:
        if policy.level != "none" and name.lower() in _SENSITIVE_HEADERS:
            if name.lower() == "set-cookie":
                result[name] = _redact_set_cookie(value, policy)
            else:
                result[name] = policy._mask(value)
        else:
            result[name] = redact_text(value, policy) if policy.level != "none" else value
    return result


def _redact_set_cookie(value: str, policy: RedactionPolicy) -> str:
    parts = [segment.strip() for segment in value.split(";")]
    if not parts:
        return policy._mask(value)
    name, _, _ = parts[0].partition("=")
    flags = [segment for segment in parts[1:] if "=" not in segment]
    rendered = f"{name or 'session'}={policy._mask('x' * 24)}"
    if flags:
        rendered += "; " + "; ".join(flags)
    return rendered


def redact_url(url: str, policy: RedactionPolicy | None = None) -> str:
    policy = policy or RedactionPolicy()
    if policy.level == "none":
        return url
    from candix.net.url import URL

    try:
        parsed = URL.parse(url)
    except Exception:
        return redact_text(url, policy)
    changed = False
    for name in list(parsed.query.keys()):
        if name.lower() in _SENSITIVE_PARAMS:
            parsed.query = parsed.query.set(name, policy._mask("x" * 12))
            changed = True
    for name in list(parsed.fragment_params.keys()):
        if name.lower() in _SENSITIVE_PARAMS:
            parsed.fragment_params = parsed.fragment_params.set(name, policy._mask("x" * 12))
            changed = True
    if changed:
        return parsed.render()
    return redact_text(url, policy)


def redact_pairs(pairs: dict[str, Any], policy: RedactionPolicy | None = None) -> dict[str, Any]:
    policy = policy or RedactionPolicy()
    return {
        key: (policy._mask(str(value)) if policy.level != "none" and key.lower() in _SENSITIVE_PARAMS else value)
        for key, value in pairs.items()
    }


def redact_json(value: Any, policy: RedactionPolicy | None = None, _depth: int = 0) -> Any:
    """Recursively redact a decoded JSON document."""

    policy = policy or RedactionPolicy()
    if policy.level == "none" or _depth > 12:
        return value
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, item in value.items():
            if key.lower() in _SENSITIVE_PARAMS:
                result[key] = policy._mask(str(item))
            else:
                result[key] = redact_json(item, policy, _depth + 1)
        return result
    if isinstance(value, list):
        return [redact_json(item, policy, _depth + 1) for item in value[:200]]
    if isinstance(value, str):
        return redact_text(value, policy)
    return value


class SecretRegistry:
    """Runtime registry of exact secret values seen during a scan.

    Pattern based redaction cannot catch opaque session identifiers, so the
    HTTP client registers every credential it uses or observes and the report
    layer masks exact matches as well.
    """

    def __init__(self, policy: RedactionPolicy | None = None) -> None:
        self.policy = policy or RedactionPolicy()
        self._secrets: set[str] = set()

    def add(self, value: str | None) -> None:
        if value and len(value) >= 6 and value not in {REDACTED}:
            self._secrets.add(value)

    def add_cookie(self, cookie: str | None) -> None:
        if not cookie:
            return
        for segment in cookie.split(";"):
            _, _, value = segment.strip().partition("=")
            self.add(value.strip())

    def extend(self, values: Iterable[str | None]) -> None:
        for value in values:
            self.add(value)

    def apply(self, text: str) -> str:
        result = redact_text(text, self.policy)
        for secret in sorted(self._secrets, key=len, reverse=True):
            result = result.replace(secret, REDACTED)
        return result

    @property
    def secrets(self) -> tuple[str, ...]:
        return tuple(sorted(self._secrets))
