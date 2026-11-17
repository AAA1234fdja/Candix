"""Cross-finding correlation used to prioritise and explain combined risk."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable
from urllib.parse import urlsplit

_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

_AMPLIFIERS: tuple[tuple[frozenset[str], int, str], ...] = (
    (frozenset({"exposed", "auth"}), 3, "exposed credentials plus an authentication weakness"),
    (frozenset({"rce", "exposed"}), 3, "code execution combined with leaked configuration"),
    (frozenset({"sqli", "auth"}), 2, "database injection with an authentication gap"),
    (frozenset({"lfi", "exposed"}), 2, "arbitrary file read with exposed artifacts"),
    (frozenset({"ssrf", "cache"}), 2, "server-side request forgery with cache influence"),
    (frozenset({"xss", "cookies"}), 2, "script execution with weak cookie flags"),
    (frozenset({"headers", "xss"}), 1, "missing headers that make script execution easier"),
    (frozenset({"crlf", "cache"}), 2, "header injection reaching the cache layer"),
    (frozenset({"smuggling", "cache"}), 3, "request smuggling in front of a shared cache"),
    (frozenset({"takeover", "dns"}), 3, "subdomain takeover with DNS control"),
    (frozenset({"dependency", "rce"}), 2, "vulnerable component reachable for exploitation"),
)


@dataclass
class Cluster:
    key: str
    category: str
    findings: list[Any] = field(default_factory=list)
    severity: str = "info"
    score: float = 0.0
    reasons: list[str] = field(default_factory=list)

    @property
    def count(self) -> int:
        return len(self.findings)

    @property
    def urls(self) -> list[str]:
        return sorted({urlsplit(getattr(finding, "url", "")).path or "/" for finding in self.findings})

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "category": self.category,
            "severity": self.severity,
            "count": self.count,
            "score": round(self.score, 2),
            "reasons": list(self.reasons),
            "urls": self.urls,
            "finding_ids": [getattr(finding, "id", "") for finding in self.findings],
            "titles": [getattr(finding, "title", "") for finding in self.findings][:10],
        }


@dataclass
class Correlation:
    clusters: list[Cluster] = field(default_factory=list)
    amplifiers: list[dict[str, Any]] = field(default_factory=list)
    risk_multiplier: float = 1.0
    summary: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "clusters": [cluster.to_dict() for cluster in self.clusters],
            "amplifiers": list(self.amplifiers),
            "risk_multiplier": round(self.risk_multiplier, 2),
            "summary": self.summary,
        }


def _category(finding: Any) -> str:
    return str(getattr(finding, "category", "") or getattr(finding, "detector", "")).lower()


def _payload(finding: Any) -> dict[str, Any]:
    if isinstance(finding, dict):
        severity = finding.get("severity", "info")
        if isinstance(severity, dict):
            severity = severity.get("name", "info")
        return {
            "id": finding.get("id", ""),
            "title": finding.get("title", ""),
            "category": str(finding.get("category") or finding.get("detector") or "").lower(),
            "severity": str(severity).lower(),
            "url": finding.get("url", ""),
            "parameter": finding.get("parameter", ""),
            "verified": bool(finding.get("verified")),
            "exploited": bool(finding.get("exploited")),
        }
    return {
        "id": getattr(finding, "id", ""),
        "title": getattr(finding, "title", ""),
        "category": _category(finding),
        "severity": getattr(getattr(finding, "severity", None), "value", "info"),
        "url": getattr(finding, "url", ""),
        "parameter": getattr(finding, "parameter", ""),
        "verified": bool(getattr(finding, "verified", False)),
        "exploited": bool(getattr(finding, "exploited", False)),
    }


def cluster_findings(findings: Iterable[Any]) -> list[Cluster]:
    clusters: dict[str, Cluster] = {}
    for finding in findings:
        payload = _payload(finding)
        key = f"{payload['category']}:{urlsplit(payload['url']).netloc}"
        cluster = clusters.get(key)
        if cluster is None:
            cluster = Cluster(key=key, category=payload["category"], severity=payload["severity"])
            clusters[key] = cluster
        cluster.findings.append(finding)
        if _SEVERITY_RANK.get(payload["severity"], 5) < _SEVERITY_RANK.get(cluster.severity, 5):
            cluster.severity = payload["severity"]
    for cluster in clusters.values():
        base = {"critical": 10.0, "high": 8.0, "medium": 5.0, "low": 3.0, "info": 1.0}.get(cluster.severity, 1.0)
        cluster.score = base * min(1.0, 0.6 + 0.1 * cluster.count)
        if cluster.count > 3:
            cluster.reasons.append(f"{cluster.count} findings share the same weakness class")
        if len(cluster.urls) > 2:
            cluster.reasons.append(f"affects {len(cluster.urls)} endpoints")
    return sorted(clusters.values(), key=lambda item: (-item.score, item.key))


def detect_amplifiers(findings: Iterable[Any]) -> list[dict[str, Any]]:
    categories = {_payload(finding)["category"] for finding in findings}
    amplifiers: list[dict[str, Any]] = []
    for required, weight, description in _AMPLIFIERS:
        if required <= categories:
            amplifiers.append(
                {
                    "categories": sorted(required),
                    "weight": weight,
                    "description": description,
                }
            )
    return amplifiers


def correlate(findings: Iterable[Any]) -> Correlation:
    materialized = list(findings)
    clusters = cluster_findings(materialized)
    amplifiers = detect_amplifiers(materialized)
    multiplier = 1.0 + 0.1 * sum(item["weight"] for item in amplifiers)
    exploited = [finding for finding in materialized if _payload(finding)["exploited"]]
    summary_bits = [f"{len(materialized)} findings in {len(clusters)} clusters"]
    if amplifiers:
        summary_bits.append(f"{len(amplifiers)} amplifying combinations")
    if exploited:
        summary_bits.append(f"{len(exploited)} exploited")
    return Correlation(
        clusters=clusters,
        amplifiers=amplifiers,
        risk_multiplier=round(min(3.0, multiplier), 2),
        summary="; ".join(summary_bits),
    )


def priority_order(findings: Iterable[Any]) -> list[Any]:
    materialized = list(findings)
    correlation = correlate(materialized)
    weights = {id(cluster): cluster for cluster in correlation.clusters for _ in cluster.findings}

    def sort_key(finding: Any) -> tuple[int, float, str]:
        payload = _payload(finding)
        cluster_bonus = 0.0
        key = f"{payload['category']}:{urlsplit(payload['url']).netloc}"
        for cluster in correlation.clusters:
            if cluster.key == key:
                cluster_bonus = cluster.count * 0.1
                break
        return (
            _SEVERITY_RANK.get(payload["severity"], 5),
            -(1.0 if payload["exploited"] else 0.0) - cluster_bonus,
            payload["title"].lower(),
        )

    return sorted(materialized, key=sort_key)


def explain(correlation: Correlation) -> str:
    lines = [correlation.summary] if correlation.summary else []
    for amplifier in correlation.amplifiers:
        lines.append(f"- {amplifier['description']} (weight {amplifier['weight']})")
    if correlation.risk_multiplier > 1.0:
        lines.append(f"- combined risk multiplier: {correlation.risk_multiplier}")
    return "\n".join(lines)
