"""Response fingerprinting against the technology catalogue."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterable

from candix.catalog.technologies import COOKIE_SIGNATURES, TECHNOLOGIES
from candix.net.http import Response


@dataclass
class Technology:
    name: str
    category: str
    version: str = ""
    confidence: str = "high"
    evidence: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "category": self.category,
            "version": self.version,
            "confidence": self.confidence,
            "evidence": self.evidence,
        }


@dataclass
class TechnologyFingerprint:
    technologies: list[Technology] = field(default_factory=list)

    def add(self, technology: Technology) -> None:
        for existing in self.technologies:
            if existing.name.lower() == technology.name.lower():
                if not existing.version and technology.version:
                    existing.version = technology.version
                return
        self.technologies.append(technology)

    def names(self) -> list[str]:
        return [technology.name for technology in self.technologies]

    def by_category(self, category: str) -> list[Technology]:
        return [item for item in self.technologies if item.category == category]

    def has(self, name: str) -> bool:
        return any(item.name.lower() == name.lower() for item in self.technologies)

    @property
    def server(self) -> str:
        for item in self.technologies:
            if item.category == "web-server":
                return f"{item.name} {item.version}".strip()
        return ""

    @property
    def framework(self) -> str:
        for item in self.technologies:
            if item.category in {"framework", "cms"}:
                return f"{item.name} {item.version}".strip()
        return ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "technologies": [item.to_dict() for item in self.technologies],
            "server": self.server,
            "framework": self.framework,
        }


def fingerprint_response(response: Response) -> TechnologyFingerprint:
    fingerprint = TechnologyFingerprint()
    headers = {name.lower(): value for name, value in response.headers.items()}
    body = response.text[:400_000]
    cookies = response.headers.get_all("Set-Cookie")
    cookie_names = [chunk.split("=")[0].strip().lower() for chunk in cookies for chunk in chunk.split(";")[:1]]
    for signature in TECHNOLOGIES:
        matched = False
        version = ""
        evidence = ""
        if signature.header:
            if signature.header not in headers:
                continue
            value = headers[signature.header]
            pattern = signature.pattern or ""
            match = re.search(pattern, value, re.IGNORECASE) if pattern else None
            if match or not pattern:
                matched = True
                evidence = f"header {signature.header}: {value}"
                if match:
                    groups = [group for group in match.groups() if group]
                    if groups:
                        version = groups[0]
        elif signature.cookie:
            for name in cookie_names:
                if re.search(signature.cookie, name):
                    matched = True
                    evidence = f"cookie {name}"
                    break
        elif signature.pattern:
            match = re.search(signature.pattern, body, re.IGNORECASE)
            if match and match.group(0):
                matched = True
                evidence = f"body pattern {signature.pattern[:40]}"
                if match.groups():
                    groups = [group for group in match.groups() if group]
                    if groups:
                        version = groups[0]
        if matched:
            fingerprint.add(
                Technology(
                    name=signature.name,
                    category=signature.category,
                    version=version,
                    confidence=signature.confidence,
                    evidence=evidence,
                )
            )
    for cookie in cookie_names:
        if cookie in COOKIE_SIGNATURES:
            fingerprint.add(
                Technology(
                    name=COOKIE_SIGNATURES[cookie],
                    category="framework",
                    confidence="medium",
                    evidence=f"cookie {cookie}",
                )
            )
    return fingerprint


def merge_fingerprints(items: Iterable[TechnologyFingerprint]) -> TechnologyFingerprint:
    merged = TechnologyFingerprint()
    for item in items:
        for technology in item.technologies:
            merged.add(technology)
    return merged
