"""What may leave the process and what must be redacted before it does.

Sending a full HTTP exchange to a model provider can hand over session cookies,
bearer tokens, API keys and customer data. The guardrail layer scrubs those
before the prompt is built, keeps a record of what it removed, and refuses to
transmit anything matching the deny patterns at all.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterable

from candix.core.redact import redact_text


@dataclass
class SecretPattern:
    name: str
    pattern: re.Pattern[str]
    replacement: str = "[REDACTED:{name}]"

    def apply(self, text: str) -> tuple[str, int]:
        matches = 0

        def substitute(_match: re.Match[str]) -> str:
            nonlocal matches
            matches += 1
            return self.replacement.format(name=self.name)

        return self.pattern.sub(substitute, text), matches


DEFAULT_PATTERNS: tuple[SecretPattern, ...] = (
    SecretPattern("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    SecretPattern("aws_secret", re.compile(r"\b(A3T[A-Z0-9]|AKIA)[A-Z0-9]{16}\b")),
    SecretPattern("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
    SecretPattern("slack_token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    SecretPattern("openai_key", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")),
    SecretPattern("anthropic_key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b")),
    SecretPattern("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    SecretPattern("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.DOTALL)),
    SecretPattern("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    SecretPattern("basic_auth", re.compile(r"(?i)\bAuthorization:\s*Basic\s+[A-Za-z0-9+/=]{8,}")),
    SecretPattern("bearer", re.compile(r"(?i)\bAuthorization:\s*Bearer\s+[A-Za-z0-9._~+/=-]{8,}")),
    SecretPattern("cookie", re.compile(r"(?i)\b(Set-)?Cookie:\s*[^\r\n]{8,200}")),
    SecretPattern("password", re.compile(r"(?i)\b(password|passwd|pwd)\s*[=:]\s*[^\s&\"']{4,}")),
    SecretPattern("connection_string", re.compile(r"(?i)\b(postgres|mysql|mongodb|redis|amqp)://[^\s\"']+")),
)


@dataclass
class RedactionReport:
    counts: dict[str, int] = field(default_factory=dict)
    characters_removed: int = 0
    blocked: list[str] = field(default_factory=list)

    @property
    def total(self) -> int:
        return sum(self.counts.values())

    def merge(self, other: "RedactionReport") -> "RedactionReport":
        for name, count in other.counts.items():
            self.counts[name] = self.counts.get(name, 0) + count
        self.characters_removed += other.characters_removed
        self.blocked.extend(other.blocked)
        return self

    def to_dict(self) -> dict[str, Any]:
        return {
            "total": self.total,
            "counts": dict(sorted(self.counts.items())),
            "characters_removed": self.characters_removed,
            "blocked": list(self.blocked),
        }

    def summary(self) -> str:
        if not self.total:
            return "nothing to redact"
        return ", ".join(f"{name}={count}" for name, count in sorted(self.counts.items()))


@dataclass
class Guardrails:
    """Redacts secrets and enforces a pre-flight allow policy."""

    patterns: tuple[SecretPattern, ...] = DEFAULT_PATTERNS
    max_prompt_chars: int = 120_000
    deny_phrases: tuple[str, ...] = (
        "-----BEGIN OPENSSH PRIVATE KEY-----",
        "aws_secret_access_key",
        "AKIA",
    )
    use_core_redaction: bool = True

    def redact(self, text: str, report: RedactionReport | None = None) -> tuple[str, RedactionReport]:
        report = report or RedactionReport()
        original = len(text or "")
        result = text or ""
        for pattern in self.patterns:
            result, count = pattern.apply(result)
            if count:
                report.counts[pattern.name] = report.counts.get(pattern.name, 0) + count
        if self.use_core_redaction:
            redacted = redact_text(result)
            if redacted != result:
                report.counts["core_redaction"] = report.counts.get("core_redaction", 0) + 1
                result = redacted
        report.characters_removed += max(0, original - len(result))
        return result, report

    def check(self, text: str) -> list[str]:
        """Return the deny phrases still present; empty means safe to send."""

        problems: list[str] = []
        for phrase in self.deny_phrases:
            if phrase in (text or ""):
                problems.append(f"contains denied material: {phrase[:24]}")
        if len(text or "") > self.max_prompt_chars:
            problems.append(f"prompt of {len(text)} characters exceeds the {self.max_prompt_chars} character ceiling")
        return problems

    def prepare(self, text: str) -> tuple[str, RedactionReport]:
        redacted, report = self.redact(text)
        report.blocked = self.check(redacted)
        return redacted, report

    def redact_mapping(self, payload: dict[str, Any]) -> tuple[dict[str, Any], RedactionReport]:
        report = RedactionReport()
        cleaned: dict[str, Any] = {}
        for key, value in payload.items():
            if isinstance(value, str):
                cleaned[key], _ = self.redact(value, report)
            elif isinstance(value, dict):
                cleaned[key], _ = self.redact_mapping(value)
            elif isinstance(value, list):
                cleaned[key] = [
                    self.redact(item, report)[0] if isinstance(item, str) else item for item in value
                ]
            else:
                cleaned[key] = value
        return cleaned, report

    def scan_response(self, text: str) -> dict[str, Any]:
        """Check model output for leaked secrets or instructions to itself."""

        _cleaned, report = self.redact(text)
        suspicious = []
        lowered = (text or "").lower()
        for phrase in ("ignore previous instructions", "system prompt", "you are now", "disregard the above"):
            if phrase in lowered:
                suspicious.append(phrase)
        return {"secrets": report.to_dict(), "suspicious_phrases": suspicious}


def redact_for_model(text: str) -> str:
    return Guardrails().redact(text)[0]


def count_secrets(text: str) -> int:
    return Guardrails().redact(text)[1].total
