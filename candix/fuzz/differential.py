"""Response clustering used to spot differential behaviour."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any, Iterable

_DYNAMIC = (
    (re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I), "<uuid>"),
    (re.compile(r"\b\d{10,13}\b"), "<ts>"),
    (re.compile(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?\b"), "<datetime>"),
    (re.compile(r"\b[0-9a-f]{32,}\b", re.I), "<hex>"),
    (re.compile(r"\b(?:[A-Za-z0-9_-]{20,})\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"), "<jwt>"),
    (re.compile(r"csrf[_-]?token[\"'=:\s]+[A-Za-z0-9_-]{8,}", re.I), "<csrf>"),
    (re.compile(r"nonce[\"'=:\s]+[A-Za-z0-9_-]{8,}", re.I), "<nonce>"),
    (re.compile(r"\d+"), "<n>"),
)


@dataclass
class ResponseClass:
    name: str
    status: int
    length_band: int
    content_type: str
    sample: str
    count: int = 0
    members: list[str] = field(default_factory=list)

    @property
    def key(self) -> str:
        return f"{self.status}:{self.length_band}:{self.content_type}:{self.name}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "status": self.status,
            "length_band": self.length_band,
            "content_type": self.content_type,
            "count": self.count,
            "sample": self.sample[:300],
        }


def normalize_body(text: str, limit: int = 20000) -> str:
    normalized = (text or "")[:limit]
    for pattern, replacement in _DYNAMIC:
        normalized = pattern.sub(replacement, normalized)
    return re.sub(r"\s+", " ", normalized).strip()


def fingerprint(text: str) -> str:
    return hashlib.sha256(normalize_body(text).encode("utf-8", "replace")).hexdigest()[:16]


def length_band(length: int) -> int:
    if length < 256:
        return 0
    if length < 1024:
        return 1
    if length < 8192:
        return 2
    if length < 65536:
        return 3
    return 4


class Classifier:
    """Groups responses into classes so fuzzing can reward novelty."""

    def __init__(self, *, novelty_threshold: float = 0.25) -> None:
        self.classes: dict[str, ResponseClass] = {}
        self.order: list[str] = []
        self.novelty_threshold = novelty_threshold
        self.baseline_key = ""

    def classify(self, response: Any, *, label: str = "", baseline: bool = False) -> ResponseClass:
        status = int(getattr(response, "status", 0) or 0)
        content = getattr(response, "content", b"") or b""
        text = str(getattr(response, "text", "") or "")
        content_type = ""
        headers = getattr(response, "headers", None)
        if headers is not None and hasattr(headers, "get"):
            content_type = str(headers.get("Content-Type", "") or "").split(";")[0].strip().lower()
        digest = fingerprint(text)
        key = f"{status}:{length_band(len(content))}:{content_type}:{digest}"
        existing = self.classes.get(key)
        if existing is None:
            existing = ResponseClass(
                name=digest,
                status=status,
                length_band=length_band(len(content)),
                content_type=content_type,
                sample=text[:400],
            )
            self.classes[key] = existing
            self.order.append(key)
        existing.count += 1
        if label and len(existing.members) < 50:
            existing.members.append(label)
        if baseline or not self.baseline_key:
            self.baseline_key = key
        return existing

    @property
    def size(self) -> int:
        return len(self.classes)

    def novelty(self, response_class: ResponseClass) -> float:
        if not self.classes:
            return 0.0
        return 1.0 / len(self.classes) if response_class.key != self.baseline_key else 0.0

    def is_novel(self, response_class: ResponseClass) -> bool:
        return response_class.key != self.baseline_key and response_class.count == 1

    def rarest(self, limit: int = 5) -> list[ResponseClass]:
        ordered = sorted(self.classes.values(), key=lambda item: item.count)
        return ordered[:limit]

    def largest(self, limit: int = 5) -> list[ResponseClass]:
        return sorted(self.classes.values(), key=lambda item: -item.count)[:limit]

    def to_dict(self) -> dict[str, Any]:
        return {
            "classes": self.size,
            "baseline": self.baseline_key,
            "distribution": [
                {"class": item.key, "count": item.count, "status": item.status}
                for item in sorted(self.classes.values(), key=lambda entry: -entry.count)[:20]
            ],
        }


def distance(left: str, right: str) -> float:
    """Normalised token distance between two bodies (0 identical, 1 disjoint)."""

    left_tokens = set(normalize_body(left).split())
    right_tokens = set(normalize_body(right).split())
    if not left_tokens and not right_tokens:
        return 0.0
    union = left_tokens | right_tokens
    if not union:
        return 0.0
    return 1.0 - len(left_tokens & right_tokens) / len(union)


def differential_pairs(responses: Iterable[tuple[str, str]], *, limit: int = 10) -> list[tuple[str, str, float]]:
    materialized = list(responses)
    pairs: list[tuple[str, str, float]] = []
    for index, (left_label, left_body) in enumerate(materialized):
        for right_label, right_body in materialized[index + 1 :]:
            pairs.append((left_label, right_label, distance(left_body, right_body)))
    pairs.sort(key=lambda item: -item[2])
    return pairs[:limit]
