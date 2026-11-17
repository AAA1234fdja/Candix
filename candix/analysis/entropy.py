"""Shannon entropy and secret-shape heuristics.

Used to spot high-entropy blobs in responses (potential secrets), to judge
whether a session identifier is predictable, and to detect encoded payloads in
JavaScript bundles.
"""

from __future__ import annotations

import base64
import binascii
import math
import re
from dataclasses import dataclass
from typing import Any, Iterable

_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str], str], ...] = (
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"), "critical"),
    ("github_pat", re.compile(r"\bghp_[A-Za-z0-9]{36}\b"), "critical"),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "critical"),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"), "high"),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"), "critical"),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), "high"),
    ("stripe_live", re.compile(r"\bsk_live_[0-9A-Za-z]{20,}\b"), "critical"),
    ("sendgrid", re.compile(r"\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b"), "high"),
    ("basic_auth_pair", re.compile(r"\b[A-Za-z0-9._%+-]+:[^\s:@]{6,}@[a-z0-9.-]+\b", re.IGNORECASE), "high"),
)


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    total = len(value)
    entropy = 0.0
    for count in counts.values():
        probability = count / total
        entropy -= probability * math.log2(probability)
    return entropy


def looks_random(value: str, *, minimum_length: int = 16) -> bool:
    if len(value) < minimum_length:
        return False
    if shannon_entropy(value) < 3.6:
        return False
    classes = sum(
        [
            any(char.islower() for char in value),
            any(char.isupper() for char in value),
            any(char.isdigit() for char in value),
            any(not char.isalnum() for char in value),
        ]
    )
    return classes >= 3


def is_base64(value: str) -> bool:
    candidate = value.strip()
    if len(candidate) < 8 or len(candidate) % 4 != 0:
        return False
    if not re.fullmatch(r"[A-Za-z0-9+/=_-]+", candidate):
        return False
    try:
        normalized = candidate.replace("-", "+").replace("_", "/")
        base64.b64decode(normalized + "=" * (-len(normalized) % 4), validate=True)
        return True
    except (binascii.Error, ValueError):
        return False


def try_decode(value: str) -> tuple[str, str] | None:
    """Attempt common encodings; return ``(scheme, decoded)``."""

    if is_base64(value):
        try:
            decoded = base64.b64decode(value + "=" * (-len(value) % 4)).decode("utf-8")
            if decoded.isprintable():
                return ("base64", decoded)
        except (binascii.Error, UnicodeDecodeError):
            pass
    hex_candidate = value.strip()
    if len(hex_candidate) >= 8 and len(hex_candidate) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", hex_candidate):
        try:
            decoded = bytes.fromhex(hex_candidate).decode("utf-8")
            if decoded.isprintable():
                return ("hex", decoded)
        except (ValueError, UnicodeDecodeError):
            pass
    return None


@dataclass
class SecretMatch:
    kind: str
    value: str
    severity: str
    offset: int

    def masked(self) -> str:
        if len(self.value) <= 8:
            return "[REDACTED]"
        return f"{self.value[:4]}...{self.value[-4:]}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "preview": self.masked(),
            "severity": self.severity,
            "offset": self.offset,
        }


def scan_for_secrets(text: str, *, limit: int = 20) -> list[SecretMatch]:
    matches: list[SecretMatch] = []
    seen: set[str] = set()
    for kind, pattern, severity in _SECRET_PATTERNS:
        for match in pattern.finditer(text or ""):
            value = match.group(0)
            if value in seen:
                continue
            seen.add(value)
            matches.append(SecretMatch(kind=kind, value=value, severity=severity, offset=match.start()))
            if len(matches) >= limit:
                return matches
    return matches


def entropy_profile(text: str, *, window: int = 32) -> list[float]:
    if len(text) < window:
        return []
    return [shannon_entropy(text[index : index + window]) for index in range(0, len(text) - window, window)]


def high_entropy_segments(text: str, *, threshold: float = 4.5, window: int = 32, limit: int = 10) -> list[str]:
    segments: list[str] = []
    for index in range(0, max(0, len(text) - window), window):
        chunk = text[index : index + window]
        if shannon_entropy(chunk) >= threshold:
            segments.append(chunk)
        if len(segments) >= limit:
            break
    return segments


def session_id_quality(value: str) -> dict[str, Any]:
    return {
        "length": len(value),
        "entropy": round(shannon_entropy(value), 2),
        "random_looking": looks_random(value),
        "base64": is_base64(value),
        "hex": bool(re.fullmatch(r"[0-9a-fA-F]+", value or "")),
        "sequential_hint": bool(re.fullmatch(r"\d+", value or "")),
        "verdict": "strong" if looks_random(value) and len(value) >= 24 else "weak",
    }


def encoded_payload_depth(value: str, *, max_depth: int = 4) -> int:
    depth = 0
    current = value
    for _ in range(max_depth):
        decoded = try_decode(current)
        if decoded is None:
            break
        depth += 1
        current = decoded[1]
    return depth


def text_complexity(text: str) -> dict[str, float]:
    words = re.findall(r"\w+", text or "")
    unique = len(set(words))
    return {
        "characters": float(len(text or "")),
        "words": float(len(words)),
        "unique_words": float(unique),
        "entropy": round(shannon_entropy(text or ""), 3),
        "vocabulary_ratio": round(unique / len(words), 3) if words else 0.0,
    }
