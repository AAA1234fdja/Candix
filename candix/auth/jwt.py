"""JSON Web Token inspection.

Only the algorithms that matter for the common misconfigurations are
implemented (HS256 and ``none``). That is intentional: the harness needs to
prove whether a token can be forged, not to be a general-purpose JWT library.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
from dataclasses import dataclass, field
from typing import Any, Iterable

_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*")


@dataclass
class JwtIssue:
    kind: str
    severity: str
    detail: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "severity": self.severity,
            "detail": self.detail,
            "metadata": self.metadata,
        }


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    try:
        return base64.urlsafe_b64decode(value + padding)
    except (ValueError, base64.binascii.Error):  # type: ignore[attr-defined]
        return b""


def find_tokens(text: str) -> list[str]:
    return list(dict.fromkeys(_JWT_RE.findall(text or "")))


def decode_unverified(token: str) -> tuple[dict[str, Any], dict[str, Any], str]:
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("not a JWT: expected three segments")
    header_raw = b64url_decode(parts[0])
    payload_raw = b64url_decode(parts[1])
    try:
        header = json.loads(header_raw or "{}")
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JWT header: {exc}") from exc
    try:
        payload = json.loads(payload_raw or "{}")
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JWT payload: {exc}") from exc
    return header, payload, parts[2]


def sign_hs256(header: dict[str, Any], payload: dict[str, Any], secret: str | bytes) -> str:
    encoded_header = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    encoded_payload = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    key = secret.encode() if isinstance(secret, str) else secret
    signature = hmac.new(key, f"{encoded_header}.{encoded_payload}".encode(), hashlib.sha256).digest()
    return f"{encoded_header}.{encoded_payload}.{b64url_encode(signature)}"


def verify_hs256(token: str, secret: str | bytes) -> bool:
    parts = token.split(".")
    if len(parts) != 3:
        return False
    key = secret.encode() if isinstance(secret, str) else secret
    expected = hmac.new(key, f"{parts[0]}.{parts[1]}".encode(), hashlib.sha256).digest()
    try:
        provided = b64url_decode(parts[2])
    except Exception:
        return False
    return hmac.compare_digest(expected, provided)


def forge_none(payload: dict[str, Any], *, header: dict[str, Any] | None = None) -> str:
    header = header or {"alg": "none", "typ": "JWT"}
    encoded_header = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    encoded_payload = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    return f"{encoded_header}.{encoded_payload}."


def forge_alg_confusion(token: str, public_key: str) -> str:
    """Sign with HS256 using the server's public key as the HMAC secret."""

    header, payload, _ = decode_unverified(token)
    header = dict(header)
    header["alg"] = "HS256"
    return sign_hs256(header, payload, public_key)


def crack_hs256(token: str, secrets: Iterable[str], *, max_attempts: int = 5000) -> str | None:
    for index, secret in enumerate(secrets):
        if index >= max_attempts:
            return None
        if verify_hs256(token, secret):
            return secret
    return None


def inspect_token(token: str, *, now: int | None = None) -> list[JwtIssue]:
    import time

    issues: list[JwtIssue] = []
    try:
        header, payload, signature = decode_unverified(token)
    except ValueError as exc:
        return [JwtIssue("malformed", "low", str(exc))]
    algorithm = str(header.get("alg", "")).lower()
    if not algorithm:
        issues.append(JwtIssue("missing_alg", "high", "The JWT header has no algorithm."))
    if algorithm == "none":
        issues.append(JwtIssue("alg_none", "critical", "The token is unsigned (alg=none)."))
    if algorithm.startswith("hs") and header.get("kid"):
        kid = str(header.get("kid"))
        if any(token in kid for token in ("../", "..\\", "/", "\\")):
            issues.append(JwtIssue("kid_path_traversal", "high", f"kid looks like a path: {kid}"))
    if header.get("jku") or header.get("x5u"):
        issues.append(
            JwtIssue(
                "untrusted_key_url",
                "high",
                "The token references a remote key URL (jku/x5u) that must be validated against an allow-list.",
            )
        )
    current = now if now is not None else int(time.time())
    exp = payload.get("exp")
    if exp is None:
        issues.append(JwtIssue("no_expiry", "medium", "The token has no exp claim and never expires."))
    elif isinstance(exp, (int, float)):
        if exp < current:
            issues.append(JwtIssue("expired", "info", "The token is already expired."))
        elif exp - current > 60 * 60 * 24 * 30:
            issues.append(
                JwtIssue(
                    "long_lived",
                    "low",
                    f"The token remains valid for {(exp - current) // 86400} days, well beyond a sensible session lifetime.",
                )
            )
    if not payload.get("iss"):
        issues.append(JwtIssue("no_issuer", "low", "The token has no iss claim, so issuer validation is impossible."))
    if not payload.get("aud"):
        issues.append(JwtIssue("no_audience", "low", "The token has no aud claim and may be replayable across services."))
    if not signature:
        issues.append(JwtIssue("missing_signature", "critical", "The token has an empty signature segment."))
    return issues


def extract_tokens_from_cookies(cookies: dict[str, str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for name, value in (cookies or {}).items():
        for token in find_tokens(value):
            result[name] = token
    return result


def extract_tokens_from_headers(headers: dict[str, str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for name, value in (headers or {}).items():
        for token in find_tokens(value):
            result[name] = token
    return result


def token_summary(token: str) -> dict[str, Any]:
    header, payload, signature = decode_unverified(token)
    return {
        "header": header,
        "claims": sorted(payload),
        "alg": header.get("alg"),
        "has_signature": bool(signature),
        "subject": payload.get("sub") or payload.get("user") or payload.get("username"),
        "role": payload.get("role") or payload.get("scope"),
    }
