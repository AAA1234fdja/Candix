"""Findings: the unit of work that flows from detectors to reports.

A finding aggregates everything an analyst needs: where the weakness lives, how
it was proven, how severe it is, and how to fix it. Findings are immutable in
spirit - detectors build them, the exploitation phase appends proofs - and the
:class:`FindingSet` owns de-duplication so that two detectors reporting the same
reflected parameter do not inflate the report.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Iterator

from candix.core.clock import isoformat, utcnow
from candix.core.evidence import Evidence
from candix.core.ids import finding_id as new_finding_id
from candix.core.ids import short_hash
from candix.core.severity import Confidence, Severity

SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}

STATUS_OPEN = "open"
STATUS_FIXED = "fixed"
STATUS_ACCEPTED = "risk-accepted"
STATUS_FALSE_POSITIVE = "false-positive"
STATUSES = (STATUS_OPEN, STATUS_FIXED, STATUS_ACCEPTED, STATUS_FALSE_POSITIVE)


@dataclass
class Remediation:
    """Concrete, actionable guidance for a finding."""

    summary: str = ""
    steps: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    effort: str = "medium"  # low | medium | high
    verification: str = ""
    owner_hint: str = ""

    def merge(self, other: "Remediation") -> "Remediation":
        steps = list(self.steps)
        for step in other.steps:
            if step not in steps:
                steps.append(step)
        references = list(self.references)
        for reference in other.references:
            if reference not in references:
                references.append(reference)
        return Remediation(
            summary=self.summary or other.summary,
            steps=steps,
            references=references,
            effort=self.effort if self.effort != "medium" else other.effort,
            verification=self.verification or other.verification,
            owner_hint=self.owner_hint or other.owner_hint,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "summary": self.summary,
            "steps": list(self.steps),
            "references": list(self.references),
            "effort": self.effort,
            "verification": self.verification,
            "owner_hint": self.owner_hint,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "Remediation":
        return cls(
            summary=payload.get("summary", ""),
            steps=list(payload.get("steps", [])),
            references=list(payload.get("references", [])),
            effort=payload.get("effort", "medium"),
            verification=payload.get("verification", ""),
            owner_hint=payload.get("owner_hint", ""),
        )


@dataclass
class Finding:
    """A single confirmed or suspected weakness."""

    title: str
    severity: Severity = Severity.MEDIUM
    detector: str = "manual"
    category: str = "general"
    target: str = ""
    url: str = ""
    method: str = "GET"
    parameter: str = ""
    location: str = ""  # query | body | header | cookie | path | config
    description: str = ""
    impact: str = ""
    remediation: Remediation = field(default_factory=Remediation)
    evidence: list[Evidence] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    cwe: list[str] = field(default_factory=list)
    owasp: list[str] = field(default_factory=list)
    tags: set[str] = field(default_factory=set)
    confidence: Confidence = Confidence.LIKELY
    score: float = 0.0
    vector: str = ""
    payload: str = ""
    verified: bool = False
    exploited: bool = False
    status: str = STATUS_OPEN
    metadata: dict[str, Any] = field(default_factory=dict)
    discovered_at: str = field(default_factory=isoformat)
    id: str = field(default_factory=new_finding_id)
    endpoint_id: str = ""
    auth_context: str = ""
    notes: str = ""

    # ------------------------------------------------------------------
    # derived values
    # ------------------------------------------------------------------
    @property
    def severity_rank(self) -> int:
        return SEVERITY_ORDER[self.severity]

    @property
    def effective_score(self) -> float:
        if self.score:
            return self.score
        return {
            Severity.CRITICAL: 9.5,
            Severity.HIGH: 8.0,
            Severity.MEDIUM: 5.5,
            Severity.LOW: 3.0,
            Severity.INFO: 0.0,
        }[self.severity]

    @property
    def endpoint_key(self) -> str:
        from candix.net.url import URL

        try:
            url = URL.parse(self.url)
            return f"{self.method.upper()} {url.scheme}://{url.netloc}{url.path}"
        except ValueError:
            return f"{self.method.upper()} {self.url}"

    def dedupe_key(self) -> str:
        return short_hash(
            self.detector,
            self.endpoint_key,
            self.parameter.lower(),
            self.location,
            self.category,
            self.title.lower(),
            length=20,
        )

    def fingerprint(self) -> str:
        return short_hash(self.detector, self.endpoint_key, self.parameter, length=16)

    # ------------------------------------------------------------------
    # mutation helpers
    # ------------------------------------------------------------------
    def add_evidence(self, evidence: Evidence) -> "Finding":
        self.evidence.append(evidence)
        return self

    def mark_verified(self, *, exploited: bool = False) -> "Finding":
        self.verified = True
        self.exploited = self.exploited or exploited
        self.confidence = Confidence.CONFIRMED
        return self

    def merge(self, other: "Finding") -> "Finding":
        """Merge a duplicate finding into this one, keeping the richer data."""

        if other.effective_score > self.effective_score:
            self.severity = other.severity
            self.score = other.score or self.score
            self.vector = other.vector or self.vector
        self.verified = self.verified or other.verified
        self.exploited = self.exploited or other.exploited
        if other.confidence.score > self.confidence.score:
            self.confidence = other.confidence
        known = {(item.kind, item.summary) for item in self.evidence}
        for item in other.evidence:
            if (item.kind, item.summary) not in known:
                self.evidence.append(item)
        self.tags |= other.tags
        for reference in other.references:
            if reference not in self.references:
                self.references.append(reference)
        for cwe in other.cwe:
            if cwe not in self.cwe:
                self.cwe.append(cwe)
        for item in other.owasp:
            if item not in self.owasp:
                self.owasp.append(item)
        self.remediation = self.remediation.merge(other.remediation)
        for key, value in other.metadata.items():
            self.metadata.setdefault(key, value)
        if not self.payload and other.payload:
            self.payload = other.payload
        if not self.notes and other.notes:
            self.notes = other.notes
        self.metadata.setdefault("merged_findings", 0)
        self.metadata["merged_findings"] = int(self.metadata["merged_findings"]) + 1
        return self

    # ------------------------------------------------------------------
    # serialisation
    # ------------------------------------------------------------------
    def to_dict(self, *, include_evidence: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "id": self.id,
            "title": self.title,
            "severity": self.severity.value,
            "score": round(self.effective_score, 1),
            "vector": self.vector,
            "detector": self.detector,
            "category": self.category,
            "target": self.target,
            "method": self.method,
            "url": self.url,
            "parameter": self.parameter,
            "location": self.location,
            "description": self.description,
            "impact": self.impact,
            "remediation": self.remediation.to_dict(),
            "references": list(self.references),
            "cwe": list(self.cwe),
            "owasp": list(self.owasp),
            "tags": sorted(self.tags),
            "confidence": self.confidence.value,
            "payload": self.payload,
            "verified": self.verified,
            "exploited": self.exploited,
            "status": self.status,
            "metadata": self.metadata,
            "discovered_at": self.discovered_at,
            "endpoint_id": self.endpoint_id,
            "auth_context": self.auth_context,
            "notes": self.notes,
            "dedupe_key": self.dedupe_key(),
            "fingerprint": self.fingerprint(),
        }
        if include_evidence:
            payload["evidence"] = [item.to_dict() for item in self.evidence]
        return payload

    @classmethod
    def from_dict(cls, payload: dict[str, Any], *, include_evidence: bool = True) -> "Finding":
        evidence = [Evidence.from_dict(item) for item in payload.get("evidence", [])] if include_evidence else []
        return cls(
            id=payload.get("id", new_finding_id()),
            title=payload.get("title", "unnamed"),
            severity=Severity.parse(payload.get("severity", "medium")),
            score=float(payload.get("score", 0.0)),
            vector=payload.get("vector", ""),
            detector=payload.get("detector", "manual"),
            category=payload.get("category", "general"),
            target=payload.get("target", ""),
            method=payload.get("method", "GET"),
            url=payload.get("url", ""),
            parameter=payload.get("parameter", ""),
            location=payload.get("location", ""),
            description=payload.get("description", ""),
            impact=payload.get("impact", ""),
            remediation=Remediation.from_dict(payload.get("remediation", {})),
            evidence=evidence,
            references=list(payload.get("references", [])),
            cwe=list(payload.get("cwe", [])),
            owasp=list(payload.get("owasp", [])),
            tags=set(payload.get("tags", [])),
            confidence=Confidence.parse(payload.get("confidence", "likely")),
            payload=payload.get("payload", ""),
            verified=bool(payload.get("verified", False)),
            exploited=bool(payload.get("exploited", False)),
            status=payload.get("status", STATUS_OPEN),
            metadata=dict(payload.get("metadata", {})),
            discovered_at=payload.get("discovered_at", isoformat()),
            endpoint_id=payload.get("endpoint_id", ""),
            auth_context=payload.get("auth_context", ""),
            notes=payload.get("notes", ""),
        )

    def __str__(self) -> str:  # pragma: no cover - display helper
        return f"[{self.severity.label}] {self.title} ({self.url})"


class FindingSet:
    """De-duplicating collection of findings."""

    def __init__(self, findings: Iterable[Finding] | None = None) -> None:
        self._items: dict[str, Finding] = {}
        if findings:
            for finding in findings:
                self.add(finding)

    def __len__(self) -> int:
        return len(self._items)

    def __iter__(self) -> Iterator[Finding]:
        return iter(self._items.values())

    def __contains__(self, key: object) -> bool:
        if isinstance(key, Finding):
            return key.dedupe_key() in self._items
        return key in self._items

    def add(self, finding: Finding) -> Finding:
        key = finding.dedupe_key()
        existing = self._items.get(key)
        if existing is None:
            self._items[key] = finding
            return finding
        return existing.merge(finding)

    def extend(self, findings: Iterable[Finding]) -> "FindingSet":
        for finding in findings:
            self.add(finding)
        return self

    def get(self, key: str) -> Finding | None:
        return self._items.get(key)

    def remove(self, key: str) -> None:
        self._items.pop(key, None)

    def filter(
        self,
        *,
        min_severity: Severity | None = None,
        categories: Iterable[str] | None = None,
        tags: Iterable[str] | None = None,
        verified_only: bool = False,
        detector: str | None = None,
        status: str | None = None,
    ) -> list[Finding]:
        category_set = {item.lower() for item in categories} if categories else None
        tag_set = {item.lower() for item in tags} if tags else None
        result: list[Finding] = []
        for finding in self._items.values():
            if min_severity is not None and finding.severity.rank < min_severity.rank:
                continue
            if category_set is not None and finding.category.lower() not in category_set:
                continue
            if tag_set is not None and not (tag_set & {tag.lower() for tag in finding.tags}):
                continue
            if verified_only and not finding.verified:
                continue
            if detector is not None and finding.detector != detector:
                continue
            if status is not None and finding.status != status:
                continue
            result.append(finding)
        return result

    def sorted(self) -> list[Finding]:
        return sorted(
            self._items.values(),
            key=lambda item: (item.severity_rank, -item.effective_score, item.title.lower()),
        )

    def counts(self) -> dict[str, int]:
        result = {severity.value: 0 for severity in Severity}
        for finding in self._items.values():
            result[finding.severity.value] += 1
        result["total"] = len(self._items)
        return result

    def categories(self) -> dict[str, int]:
        result: dict[str, int] = {}
        for finding in self._items.values():
            result[finding.category] = result.get(finding.category, 0) + 1
        return dict(sorted(result.items(), key=lambda pair: (-pair[1], pair[0])))

    def to_list(self, *, include_evidence: bool = True) -> list[dict[str, Any]]:
        return [finding.to_dict(include_evidence=include_evidence) for finding in self.sorted()]

    def to_dict(self) -> dict[str, Any]:
        return {
            "counts": self.counts(),
            "categories": self.categories(),
            "findings": self.to_list(),
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "FindingSet":
        items = payload.get("findings", payload if isinstance(payload, list) else [])
        return cls(Finding.from_dict(item) for item in items)

    def merge(self, other: "FindingSet") -> "FindingSet":
        for finding in other:
            self.add(finding)
        return self

    @property
    def risk_score(self) -> float:
        """Simple aggregate used to rank scans and track remediation progress."""

        if not self._items:
            return 0.0
        weights = {Severity.CRITICAL: 10.0, Severity.HIGH: 6.0, Severity.MEDIUM: 3.0, Severity.LOW: 1.0, Severity.INFO: 0.1}
        return round(sum(weights[finding.severity] for finding in self._items.values()), 2)


def finding_from_probe(
    *,
    title: str,
    detector: str,
    category: str,
    severity: Severity,
    url: str,
    method: str = "GET",
    parameter: str = "",
    location: str = "query",
    description: str = "",
    impact: str = "",
    payload: str = "",
    cwe: Iterable[str] = (),
    owasp: Iterable[str] = (),
    references: Iterable[str] = (),
    remediation: Remediation | None = None,
    tags: Iterable[str] = (),
    confidence: Confidence = Confidence.LIKELY,
    score: float = 0.0,
    vector: str = "",
    target: str = "",
) -> Finding:
    """Convenience constructor used by detectors."""

    from candix.net.url import URL

    if not target:
        try:
            target = URL.parse(url).host
        except ValueError:
            target = ""
    return Finding(
        title=title,
        detector=detector,
        category=category,
        severity=severity,
        confidence=confidence,
        score=score,
        vector=vector,
        url=url,
        method=method.upper(),
        parameter=parameter,
        location=location,
        description=description,
        impact=impact,
        payload=payload,
        cwe=list(cwe),
        owasp=list(owasp),
        references=list(references),
        remediation=remediation or Remediation(),
        tags=set(tags),
        target=target,
    )
