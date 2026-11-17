"""Turns a list of agent findings into a ranked, de-duplicated picture."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Sequence

from candix.core.severity import Severity
from candix.llm.embeddings import cluster

_ORDER = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4}
_SEVERITY_WEIGHT = {"critical": 10.0, "high": 6.0, "medium": 3.0, "low": 1.0, "info": 0.2}


def severity_of(value: Any) -> Severity:
    if isinstance(value, Severity):
        return value
    try:
        return Severity(str(value).strip().lower())
    except ValueError:
        return Severity.INFO


@dataclass
class Cluster:
    key: str
    title: str
    severity: str
    urls: list[str] = field(default_factory=list)
    members: list[str] = field(default_factory=list)
    confirmed: bool = False

    @property
    def size(self) -> int:
        return len(self.members)

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "title": self.title,
            "severity": self.severity,
            "size": self.size,
            "confirmed": self.confirmed,
            "urls": sorted(set(self.urls))[:10],
        }


@dataclass
class Ranked:
    finding: dict[str, Any]
    priority: float
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.finding.get("id", ""), "title": self.finding.get("title", ""), "priority": round(self.priority, 2), "reasons": self.reasons}


@dataclass
class TriageResult:
    ranked: list[Ranked] = field(default_factory=list)
    clusters: list[Cluster] = field(default_factory=list)
    duplicates: int = 0
    unconfirmed: int = 0
    chains: list[dict[str, Any]] = field(default_factory=list)
    risk: float = 0.0
    grade: str = "A"

    def top(self, limit: int = 5) -> list[dict[str, Any]]:
        return [item.finding for item in self.ranked[:limit]]

    def to_dict(self) -> dict[str, Any]:
        return {
            "findings": len(self.ranked),
            "duplicates": self.duplicates,
            "unconfirmed": self.unconfirmed,
            "risk": round(self.risk, 2),
            "grade": self.grade,
            "clusters": [cluster.to_dict() for cluster in self.clusters],
            "ranked": [item.to_dict() for item in self.ranked],
            "chains": self.chains,
            "summary": self.summary(),
        }

    def summary(self) -> str:
        return (
            f"{len(self.ranked)} finding(s), {self.duplicates} duplicate(s) merged, "
            f"{self.unconfirmed} unconfirmed, risk {self.risk:.1f} ({self.grade})"
        )


def _text(finding: dict[str, Any]) -> str:
    return " ".join(
        str(finding.get(key, "")) for key in ("title", "category", "url", "parameter", "description")
    ).strip()


def find_duplicates(findings: Sequence[dict[str, Any]], *, threshold: float = 0.7) -> list[list[int]]:
    texts = [_text(item) for item in findings]
    return cluster(texts, threshold=threshold)


def _confidence(finding: dict[str, Any]) -> float:
    raw = finding.get("confidence", 0.5)
    if isinstance(raw, (int, float)):
        return max(0.0, min(1.0, float(raw)))
    mapping = {"confirmed": 1.0, "likely": 0.7, "possible": 0.4, "tentative": 0.2, "observed": 0.9}
    return mapping.get(str(raw).lower(), 0.5)


def _priority(finding: dict[str, Any]) -> tuple[float, list[str]]:
    severity = severity_of(finding.get("severity"))
    base = _SEVERITY_WEIGHT.get(severity.value, 1.0)
    score = base
    reasons = [f"severity {severity.value}"]
    if finding.get("verified"):
        score *= 1.35
        reasons.append("verified by a second request")
    if finding.get("exploited"):
        score *= 1.25
        reasons.append("exploited with a captured proof")
    confidence = _confidence(finding)
    score *= 0.6 + 0.8 * confidence
    if confidence >= 0.9:
        reasons.append("high confidence evidence")
    if str(finding.get("parameter", "")):
        score *= 1.1
        reasons.append("has an injectable parameter")
    if str(finding.get("category", "")).lower() in {"rce", "sqli", "ssrf", "xxe", "deserialization", "auth"}:
        score *= 1.15
        reasons.append("impact class escalates easily")
    return round(score, 3), reasons


def triage(findings: Iterable[dict[str, Any]], *, threshold: float = 0.7, assets: Any = None) -> TriageResult:
    items = [dict(item) for item in findings]
    result = TriageResult()
    if not items:
        result.grade = "n/a"
        return result

    groups = find_duplicates(items, threshold=threshold)
    kept: list[dict[str, Any]] = []
    for group in groups:
        members = [items[index] for index in group]
        primary = max(members, key=lambda item: (_SEVERITY_WEIGHT.get(severity_of(item.get("severity")).value, 0), bool(item.get("verified"))))
        if len(members) > 1:
            result.duplicates += len(members) - 1
        kept.append(primary)
        result.clusters.append(
            Cluster(
                key=str(primary.get("id", "")),
                title=str(primary.get("title", "")),
                severity=severity_of(primary.get("severity")).value,
                urls=[str(item.get("url", "")) for item in members],
                members=[str(item.get("id", "")) for item in members],
                confirmed=any(bool(item.get("verified")) for item in members),
            )
        )

    for finding in kept:
        priority, reasons = _priority(finding)
        result.ranked.append(Ranked(finding=finding, priority=priority, reasons=reasons))
        if not finding.get("verified") and not finding.get("exploited"):
            result.unconfirmed += 1
    result.ranked.sort(key=lambda item: (-item.priority, str(item.finding.get("title", ""))))

    result.risk = _risk(result.ranked, assets)
    result.grade = _grade(result.risk, result.unconfirmed, len(result.ranked))
    result.chains = _chains(items)
    return result


def _risk(ranked: Sequence[Ranked], assets: Any) -> float:
    if not ranked:
        return 0.0
    score = 0.0
    for index, item in enumerate(ranked[:12]):
        decay = 1.0 / (1 + index * 0.35)
        score += item.priority * decay
    verified = sum(1 for item in ranked if item.finding.get("verified") or item.finding.get("exploited"))
    score *= 1.0 + min(0.25, 0.05 * verified)
    if assets is not None:
        try:
            coverage = assets.coverage()
            untouched = coverage.get("endpoints_untested", 0)
            total = max(1, coverage.get("endpoints", 1))
            score *= 1.0 + 0.2 * (untouched / total)
        except Exception:
            pass
    return min(100.0, round(score * 2.6, 2))


def _grade(risk: float, unconfirmed: int, total: int) -> str:
    if total == 0:
        return "A"
    penalty = 0.0 if total == 0 else min(15.0, 100.0 * unconfirmed / max(total, 1) * 0.15)
    adjusted = risk + penalty
    for threshold, grade in ((80, "F"), (65, "E"), (50, "D"), (35, "C"), (20, "B")):
        if adjusted >= threshold:
            return grade
    return "A"


def _chains(findings: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    """Use the exploit chain builder when findings can be mapped onto it."""

    try:
        from candix.core.finding import Finding
        from candix.exploit.chain import build_chains
    except Exception:
        return []
    mapped = []
    for item in findings:
        try:
            mapped.append(Finding.from_dict(item))
        except Exception:
            continue
    if not mapped:
        return []
    try:
        return [chain.to_dict() for chain in build_chains(mapped)]
    except Exception:
        return []


def merge_priority(findings: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Annotate findings with their triage priority, highest first."""

    result = triage(findings)
    annotated = []
    for item in result.ranked:
        enriched = dict(item.finding)
        enriched["priority"] = item.priority
        enriched["priority_reasons"] = item.reasons
        annotated.append(enriched)
    return annotated
