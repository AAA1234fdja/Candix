"""Severity, confidence and CVSS 3.1 scoring.

The harness never invents a severity from a detector name alone: findings carry
a CVSS vector whenever the impact can be expressed, and the score is derived
with the official 3.1 base formula. Detectors that cannot justify a vector fall
back to a conservative qualitative rating plus a confidence level.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from enum import Enum
from typing import Final, Iterable


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]

    @property
    def label(self) -> str:
        return self.value.upper()

    @property
    def color(self) -> str:
        return {
            Severity.CRITICAL: "#7f1d1d",
            Severity.HIGH: "#b91c1c",
            Severity.MEDIUM: "#b45309",
            Severity.LOW: "#1d4ed8",
            Severity.INFO: "#475569",
        }[self]

    @property
    def sla_days(self) -> int:
        return {
            Severity.CRITICAL: 7,
            Severity.HIGH: 30,
            Severity.MEDIUM: 90,
            Severity.LOW: 180,
            Severity.INFO: 365,
        }[self]

    @classmethod
    def parse(cls, value: str | "Severity") -> "Severity":
        if isinstance(value, Severity):
            return value
        text = str(value).strip().lower()
        aliases = {
            "informational": cls.INFO,
            "none": cls.INFO,
            "moderate": cls.MEDIUM,
            "med": cls.MEDIUM,
            "severe": cls.CRITICAL,
            "crit": cls.CRITICAL,
        }
        if text in aliases:
            return aliases[text]
        for member in cls:
            if member.value == text:
                return member
        from candix.core.errors import ParseError

        raise ParseError(f"unknown severity: {value!r}")

    @classmethod
    def from_score(cls, score: float) -> "Severity":
        if score <= 0.0:
            return cls.INFO
        if score < 4.0:
            return cls.LOW
        if score < 7.0:
            return cls.MEDIUM
        if score < 9.0:
            return cls.HIGH
        return cls.CRITICAL

    def at_least(self, other: "Severity") -> bool:
        return self.rank >= other.rank

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank < other.rank


_SEVERITY_RANK: Final[dict[Severity, int]] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}

ALL_SEVERITIES: Final[tuple[Severity, ...]] = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
)


class Confidence(str, Enum):
    """How strongly the harness believes a finding is real."""

    CONFIRMED = "confirmed"
    LIKELY = "likely"
    POSSIBLE = "possible"

    @property
    def score(self) -> float:
        return {
            Confidence.CONFIRMED: 0.95,
            Confidence.LIKELY: 0.75,
            Confidence.POSSIBLE: 0.45,
        }[self]

    @classmethod
    def parse(cls, value: str | "Confidence") -> "Confidence":
        if isinstance(value, Confidence):
            return value
        text = str(value).strip().lower()
        for member in cls:
            if member.value == text:
                return member
        raise ValueError(f"unknown confidence: {value!r}")


_AV: Final[dict[str, float]] = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC: Final[dict[str, float]] = {"L": 0.77, "H": 0.44}
_PR_UNCHANGED: Final[dict[str, float]] = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED: Final[dict[str, float]] = {"N": 0.85, "L": 0.68, "H": 0.5}
_UI: Final[dict[str, float]] = {"N": 0.85, "R": 0.62}
_CIA: Final[dict[str, float]] = {"H": 0.56, "L": 0.22, "N": 0.0}


@dataclass(frozen=True)
class CVSS:
    """A CVSS 3.1 base metric set."""

    attack_vector: str = "N"
    attack_complexity: str = "L"
    privileges_required: str = "N"
    user_interaction: str = "N"
    scope: str = "U"
    confidentiality: str = "L"
    integrity: str = "L"
    availability: str = "N"

    @property
    def vector(self) -> str:
        return (
            f"CVSS:3.1/AV:{self.attack_vector}/AC:{self.attack_complexity}"
            f"/PR:{self.privileges_required}/UI:{self.user_interaction}"
            f"/S:{self.scope}/C:{self.confidentiality}/I:{self.integrity}"
            f"/A:{self.availability}"
        )

    @property
    def score(self) -> float:
        return _roundup(self._impact() + self._exploitability()) if self._impact() > 0 else 0.0

    @property
    def severity(self) -> Severity:
        return Severity.from_score(self.score)

    def _impact(self) -> float:
        iss = 1.0 - (
            (1.0 - _CIA[self.confidentiality])
            * (1.0 - _CIA[self.integrity])
            * (1.0 - _CIA[self.availability])
        )
        if self.scope == "U":
            return 6.42 * iss
        return 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15

    def _exploitability(self) -> float:
        pr_table = _PR_CHANGED if self.scope == "C" else _PR_UNCHANGED
        return (
            8.22
            * _AV[self.attack_vector]
            * _AC[self.attack_complexity]
            * pr_table[self.privileges_required]
            * _UI[self.user_interaction]
        )

    def to_dict(self) -> dict[str, object]:
        return {"vector": self.vector, "score": self.score, "severity": self.severity.value}


def _roundup(value: float) -> float:
    """CVSS 3.1 Appendix A round-up function."""

    scaled = int(round(value * 100000))
    if scaled % 10000 == 0:
        return scaled / 100000.0
    return (math.floor(scaled / 10000) + 1) / 10.0


def parse_vector(vector: str) -> CVSS:
    """Parse a CVSS 3.1 vector string into a :class:`CVSS` instance."""

    text = vector.strip()
    if text.lower().startswith("cvss:3.1/"):
        text = text[9:]
    elif text.lower().startswith("cvss:3.0/"):
        text = text[9:]
    fields: dict[str, str] = {}
    aliases = {
        "AV": "attack_vector",
        "AC": "attack_complexity",
        "PR": "privileges_required",
        "UI": "user_interaction",
        "S": "scope",
        "C": "confidentiality",
        "I": "integrity",
        "A": "availability",
    }
    for chunk in text.split("/"):
        if not chunk:
            continue
        key, _, raw = chunk.partition(":")
        key = key.upper()
        if key not in aliases:
            from candix.core.errors import ParseError

            raise ParseError(f"unknown CVSS metric: {key}")
        value = raw.strip().upper()
        if not value:
            from candix.core.errors import ParseError

            raise ParseError(f"empty CVSS metric: {key}")
        fields[aliases[key]] = value
    try:
        candidate = CVSS(**fields)  # type: ignore[arg-type]
    except TypeError as exc:
        from candix.core.errors import ParseError

        raise ParseError(f"incomplete CVSS vector: {vector!r}") from exc
    _validate(candidate)
    return candidate


def _validate(cvss: CVSS) -> None:
    from candix.core.errors import ParseError

    checks = {
        "attack_vector": _AV,
        "attack_complexity": _AC,
        "privileges_required": _PR_UNCHANGED,
        "user_interaction": _UI,
        "confidentiality": _CIA,
        "integrity": _CIA,
        "availability": _CIA,
    }
    for name, table in checks.items():
        value = getattr(cvss, name)
        if value not in table:
            raise ParseError(f"invalid CVSS value for {name}: {value!r}")
    if cvss.scope not in {"U", "C"}:
        raise ParseError(f"invalid CVSS scope: {cvss.scope!r}")


@dataclass(frozen=True)
class Rating:
    """A severity with an optional, authoritative CVSS justification."""

    severity: Severity
    cvss: CVSS | None = None
    confidence: Confidence = Confidence.LIKELY

    @property
    def score(self) -> float:
        if self.cvss is not None:
            return self.cvss.score
        return {
            Severity.CRITICAL: 9.5,
            Severity.HIGH: 8.0,
            Severity.MEDIUM: 5.5,
            Severity.LOW: 3.0,
            Severity.INFO: 0.0,
        }[self.severity]

    @property
    def vector(self) -> str:
        if self.cvss is not None:
            return self.cvss.vector
        return ""

    @classmethod
    def from_vector(
        cls,
        vector: str,
        confidence: Confidence = Confidence.CONFIRMED,
    ) -> "Rating":
        cvss = parse_vector(vector)
        return cls(cvss.severity, cvss, confidence)

    def to_dict(self) -> dict[str, object]:
        return {
            "severity": self.severity.value,
            "score": self.score,
            "vector": self.vector,
            "confidence": self.confidence.value,
        }


def worst(ratings: Iterable[Rating]) -> Rating:
    return max(ratings, key=lambda item: (item.severity.rank, item.score), default=Rating(Severity.INFO))
