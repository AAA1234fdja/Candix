"""Choose what to attack next when there is more surface than budget.

Coverage says how much is untested; targeting says which untested thing is worth
the next hundred requests. Scoring combines reachability, parameter presence,
prior findings, technology interest and how recently the endpoint was touched.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

_INTERESTING_PARAMS = {
    "id", "user", "username", "email", "file", "path", "url", "redirect", "next", "return",
    "callback", "cmd", "command", "exec", "template", "q", "query", "search", "page", "host",
    "format", "debug", "token", "key", "api", "dir", "download", "src", "dest", "output",
}

_INTERESTING_EXTENSIONS = (".php", ".asp", ".aspx", ".jsp", ".do", ".action", ".json", ".xml", ".cgi", ".pl")


@dataclass
class Target:
    url: str
    method: str = "GET"
    score: float = 0.0
    parameters: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    findings: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "method": self.method,
            "score": round(self.score, 2),
            "parameters": self.parameters,
            "findings": self.findings,
            "reasons": self.reasons,
        }


def score_endpoint(node: Any, *, findings_by_url: dict[str, int] | None = None, parameters: Iterable[str] = ()) -> Target:
    attributes = getattr(node, "attributes", {}) or {}
    label = str(attributes.get("url") or getattr(node, "label", ""))
    method = str(attributes.get("method", "GET"))
    params = [str(name) for name in parameters]
    target = Target(url=label, method=method, parameters=params)
    score = 1.0
    reasons = []

    if params:
        score += min(2.5, 0.6 * len(params))
        reasons.append(f"{len(params)} parameter(s)")
    interesting = [name for name in params if name.lower() in _INTERESTING_PARAMS]
    if interesting:
        score += 0.8 * len(interesting)
        reasons.append("injectable names: " + ", ".join(interesting[:4]))
    if any(label.lower().split("?")[0].endswith(extension) for extension in _INTERESTING_EXTENSIONS):
        score += 0.9
        reasons.append("dynamic extension")
    if method.upper() in {"POST", "PUT", "PATCH", "DELETE"}:
        score += 0.7
        reasons.append(f"{method} accepts a body")
    prior = (findings_by_url or {}).get(label, 0)
    if prior:
        score += 1.2 * prior
        target.findings = prior
        reasons.append(f"{prior} finding(s) here already")
    status = int(attributes.get("status", 0) or 0)
    if status == 200:
        score += 0.5
        reasons.append("live (200)")
    elif status in (401, 403):
        score += 0.9
        reasons.append(f"protected ({status})")
    if "login" in label.lower() or "auth" in label.lower():
        score += 0.6
        reasons.append("authentication surface")
    if "admin" in label.lower():
        score += 0.5
        reasons.append("administrative surface")
    target.score = round(score, 3)
    target.reasons = reasons
    return target


def rank_endpoints(
    assets: Any,
    *,
    limit: int = 12,
    findings_by_url: dict[str, int] | None = None,
    exclude: Iterable[str] = (),
) -> list[Target]:
    skip = set(exclude)
    ranked: list[Target] = []
    for node in assets.endpoints():
        url = str((node.attributes or {}).get("url", node.label))
        if url in skip:
            continue
        names: list[str] = []
        for edge in assets.outgoing(node.id):
            target_node = assets.node(edge.dst)
            if target_node is None:
                continue
            if str(getattr(target_node.kind, "value", target_node.kind)) == "parameter":
                names.append(str(target_node.attributes.get("name", target_node.label)))
        ranked.append(score_endpoint(node, findings_by_url=findings_by_url, parameters=names))
    ranked.sort(key=lambda target: (-target.score, target.url))
    return ranked[:limit]


def findings_by_url(findings: Iterable[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for finding in findings:
        url = str(finding.get("url", ""))
        if url:
            counts[url] = counts.get(url, 0) + 1
    return counts


def parameter_priority(names: Iterable[str]) -> list[str]:
    """Order parameters by how often they are injectable in practice."""

    def weight(name: str) -> tuple[int, str]:
        lowered = name.lower()
        if lowered in _INTERESTING_PARAMS:
            return (0, lowered)
        if any(marker in lowered for marker in ("id", "file", "url", "path", "name")):
            return (1, lowered)
        return (2, lowered)

    return sorted(dict.fromkeys(names), key=weight)


def next_targets(assets: Any, findings: Iterable[dict[str, Any]], *, limit: int = 5) -> list[Target]:
    return rank_endpoints(assets, limit=limit, findings_by_url=findings_by_url(findings))


def describe(targets: Iterable[Target]) -> str:
    lines = []
    for target in targets:
        lines.append(f"{target.score:5.2f} {target.method:6} {target.url[:80]}")
        if target.reasons:
            lines.append(f"      {'; '.join(target.reasons[:3])}")
    return "\n".join(lines)


def select_for_fuzz(assets: Any, *, limit: int = 3, per_endpoint: int = 2) -> list[dict[str, Any]]:
    """Endpoint and parameter pairs a bounded fuzz run can afford."""

    selection: list[dict[str, Any]] = []
    for target in rank_endpoints(assets, limit=limit):
        for name in parameter_priority(target.parameters)[:per_endpoint]:
            selection.append({"url": target.url, "parameter": name})
    return selection
