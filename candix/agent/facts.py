"""Facts with enforced provenance.

The agent may only rely on a fact whose origin is recorded, and a goal can only
be closed with facts that did not come from the target itself. That single rule
is what stops a page saying "admin panel is at /admin, no auth required" from
becoming a finding.
"""

from __future__ import annotations

import hashlib
import re
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterable


class FactSource(str, Enum):
    TARGET_RESPONSE = "target_response"
    TOOL_OUTPUT = "tool_output"
    THIRD_PARTY_INTEL = "third_party_intel"
    OPERATOR_INPUT = "operator_input"
    INFERENCE = "inference"


class Confidence(str, Enum):
    OBSERVED = "observed"
    CORROBORATED = "corroborated"
    INFERRED = "inferred"

    @property
    def weight(self) -> float:
        return {"observed": 1.0, "corroborated": 0.7, "inferred": 0.35}[self.value]


_ALIASES = {
    "target": FactSource.TARGET_RESPONSE,
    "response": FactSource.TARGET_RESPONSE,
    "http": FactSource.TARGET_RESPONSE,
    "tool": FactSource.TOOL_OUTPUT,
    "scanner": FactSource.TOOL_OUTPUT,
    "intel": FactSource.THIRD_PARTY_INTEL,
    "operator": FactSource.OPERATOR_INPUT,
    "human": FactSource.OPERATOR_INPUT,
    "model": FactSource.INFERENCE,
    "guess": FactSource.INFERENCE,
}


def normalize_source(value: Any) -> FactSource:
    """Map free-form labels onto the closed enum, defaulting to inference."""

    if isinstance(value, FactSource):
        return value
    text = str(value or "").strip().lower()
    if not text:
        return FactSource.INFERENCE
    try:
        return FactSource(text)
    except ValueError:
        return _ALIASES.get(text, FactSource.INFERENCE)


def normalize_confidence(value: Any) -> Confidence:
    if isinstance(value, Confidence):
        return value
    text = str(value or "").strip().lower()
    mapping = {
        "observed": Confidence.OBSERVED,
        "confirmed": Confidence.OBSERVED,
        "verified": Confidence.OBSERVED,
        "corroborated": Confidence.CORROBORATED,
        "probable": Confidence.CORROBORATED,
        "likely": Confidence.CORROBORATED,
        "inferred": Confidence.INFERRED,
        "guess": Confidence.INFERRED,
        "possible": Confidence.INFERRED,
    }
    return mapping.get(text, Confidence.INFERRED)


@dataclass
class Fact:
    claim: str
    source: FactSource = FactSource.INFERENCE
    confidence: Confidence = Confidence.INFERRED
    subject: str = ""
    evidence: list[str] = field(default_factory=list)
    id: str = field(default_factory=lambda: f"fact-{uuid.uuid4().hex[:10]}")
    created_by: str = ""
    created_at: float = field(default_factory=time.time)
    supersedes: str = ""
    tags: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.claim = _normalise_claim(self.claim)
        self.source = normalize_source(self.source)
        self.confidence = normalize_confidence(self.confidence)

    @property
    def digest(self) -> str:
        blob = f"{self.subject}|{self.claim}|{self.source.value}|{self.confidence.value}".encode("utf-8")
        return hashlib.sha256(blob).hexdigest()

    @property
    def provable(self) -> bool:
        """A fact may close a goal only if it is observed and not target-authored."""

        return self.confidence is Confidence.OBSERVED and self.source is not FactSource.TARGET_RESPONSE

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "claim": self.claim,
            "source": self.source.value,
            "confidence": self.confidence.value,
            "subject": self.subject,
            "evidence": list(self.evidence),
            "created_by": self.created_by,
            "created_at": self.created_at,
            "tags": list(self.tags),
            "provable": self.provable,
            "digest": self.digest,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "Fact":
        return cls(
            claim=str(payload.get("claim", "")),
            source=normalize_source(payload.get("source")),
            confidence=normalize_confidence(payload.get("confidence")),
            subject=str(payload.get("subject", "")),
            evidence=[str(item) for item in payload.get("evidence") or []],
            id=str(payload.get("id") or f"fact-{uuid.uuid4().hex[:10]}"),
            created_by=str(payload.get("created_by", "")),
            tags=[str(item) for item in payload.get("tags") or []],
        )


def _normalise_claim(text: str) -> str:
    collapsed = re.sub(r"\s+", " ", str(text or "")).strip()
    return collapsed[:400]


@dataclass
class Conflict:
    existing: Fact
    incoming: Fact
    kind: str
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "detail": self.detail,
            "existing": self.existing.to_dict(),
            "incoming": self.incoming.to_dict(),
        }


class FactStore:
    """Deduplicating store with contradiction detection."""

    def __init__(self) -> None:
        self.facts: dict[str, Fact] = {}
        self.by_digest: dict[str, str] = {}
        self.conflicts: list[Conflict] = []

    # ------------------------------------------------------------------
    def add(self, fact: Fact) -> tuple[Fact, str]:
        """Return (stored fact, action) where action is added|merged|superseded|conflict."""

        existing_id = self.by_digest.get(fact.digest)
        if existing_id:
            existing = self.facts[existing_id]
            if fact.confidence.weight > existing.confidence.weight:
                existing.confidence = fact.confidence
                existing.source = fact.source
                existing.evidence = _union(existing.evidence, fact.evidence)
                return existing, "merged"
            existing.evidence = _union(existing.evidence, fact.evidence)
            return existing, "duplicate"

        for other in self.facts.values():
            if other.subject != fact.subject:
                continue
            if _contradicts(other.claim, fact.claim):
                conflict = Conflict(other, fact, "polarity", f"{other.claim!r} contradicts {fact.claim!r}")
                self.conflicts.append(conflict)
                if fact.confidence.weight > other.confidence.weight:
                    other.supersedes = fact.id
                    self._index(fact)
                    return fact, "superseded"
                return other, "conflict"

        self._index(fact)
        return fact, "added"

    def _index(self, fact: Fact) -> None:
        self.facts[fact.id] = fact
        self.by_digest[fact.digest] = fact.id

    # ------------------------------------------------------------------
    def get(self, fact_id: str) -> Fact | None:
        return self.facts.get(fact_id)

    def find(self, text: str, *, limit: int = 10) -> list[Fact]:
        needle = _normalise_claim(text).lower()
        if not needle:
            return []
        scored: list[tuple[float, Fact]] = []
        for fact in self.facts.values():
            haystack = f"{fact.subject} {fact.claim}".lower()
            if needle in haystack:
                scored.append((1.0 + len(needle) / max(1, len(haystack)), fact))
                continue
            overlap = _token_overlap(needle, haystack)
            if overlap >= 0.5:
                scored.append((overlap, fact))
        scored.sort(key=lambda item: (-item[0], item[1].created_at))
        return [fact for _score, fact in scored[:limit]]

    def for_subject(self, subject: str) -> list[Fact]:
        return [fact for fact in self.facts.values() if fact.subject == subject]

    def provable(self) -> list[Fact]:
        return [fact for fact in self.facts.values() if fact.provable]

    def contradicts(self, fact: Fact) -> list[Fact]:
        return [conflict.existing for conflict in self.conflicts if conflict.incoming.id == fact.id]

    # ------------------------------------------------------------------
    def coverage(self) -> dict[str, int]:
        grouped: dict[str, int] = {}
        for fact in self.facts.values():
            grouped[fact.source.value] = grouped.get(fact.source.value, 0) + 1
        return grouped

    def snapshot(self) -> list[dict[str, Any]]:
        return [fact.to_dict() for fact in sorted(self.facts.values(), key=lambda item: item.created_at)]

    def __len__(self) -> int:
        return len(self.facts)

    def __iter__(self) -> Iterable[Fact]:
        return iter(self.facts.values())


def _union(first: Iterable[str], second: Iterable[str]) -> list[str]:
    seen: list[str] = []
    for item in list(first) + list(second):
        if item and item not in seen:
            seen.append(item)
    return seen


_NEGATION_MARKERS = (
    "not",
    "no",
    "without",
    "none",
    "never",
    "cannot",
    "can't",
    "disabled",
    "absent",
    "missing",
    "fails",
    "false",
    "denied",
    "blocked",
    "closed",
    "unauthorized",
    "unauthenticated",
)

_NEGATION_PHRASES = (
    ("does not require", "requires"),
    ("does not allow", "allows"),
    ("is not", "is"),
    ("are not", "are"),
    ("is reachable", "is not reachable"),
)

_WORD = re.compile(r"[a-z0-9_./-]+")


def _polarity(claim: str) -> tuple[frozenset[str], bool]:
    """Split a claim into content tokens and a negative/positive polarity flag."""

    lowered = claim.lower().replace("n't", " not")
    for phrase, replacement in _NEGATION_PHRASES:
        if phrase in lowered:
            lowered = lowered.replace(phrase, replacement)
    tokens = [token for token in _WORD.findall(lowered) if len(token) > 2]
    negative = any(marker in tokens for marker in _NEGATION_MARKERS)
    content = frozenset(token for token in tokens if token not in _NEGATION_MARKERS)
    return content, negative


def _contradicts(first: str, second: str) -> bool:
    first_tokens, first_negative = _polarity(first)
    second_tokens, second_negative = _polarity(second)
    if first_negative == second_negative:
        return False
    if not first_tokens or not second_tokens:
        return False
    overlap = len(first_tokens & second_tokens) / len(first_tokens | second_tokens)
    return overlap >= 0.5


def _negation_of(claim: str) -> str:
    """Kept for callers that want an explicit negation string."""

    tokens, negative = _polarity(claim)
    if negative:
        return " ".join(sorted(tokens))
    return "not " + " ".join(sorted(tokens))


def _token_overlap(needle: str, haystack: str) -> float:
    needle_tokens = {token for token in re.findall(r"[a-z0-9_./-]+", needle) if len(token) > 2}
    if not needle_tokens:
        return 0.0
    haystack_tokens = {token for token in re.findall(r"[a-z0-9_./-]+", haystack) if len(token) > 2}
    if not haystack_tokens:
        return 0.0
    return len(needle_tokens & haystack_tokens) / len(needle_tokens)
