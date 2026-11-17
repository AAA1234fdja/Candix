"""Compact, token-bounded renderings of the asset graph for prompts."""

from __future__ import annotations

from typing import Any, Iterable

from candix.agent.graph import AssetGraph, Node, NodeKind
from candix.llm.tokens import estimate_text, truncate_text


def endpoint_lines(graph: AssetGraph, *, limit: int = 30) -> list[str]:
    lines: list[str] = []
    for node in graph.endpoints()[:limit]:
        method = node.attributes.get("method", "GET")
        url = node.attributes.get("url", "")
        status = node.attributes.get("status", 0)
        parameters = [
            edge.dst.split("#", 1)[-1]
            for edge in graph.outgoing(node.id)
            if edge.kind.value == "has_parameter"
        ]
        suffix = f" params={','.join(parameters)}" if parameters else ""
        findings = graph.incoming(node.id)
        marker = " *" if findings else ""
        lines.append(f"- {method} {url} [{status}]{suffix}{marker}")
    return lines


def finding_lines(findings: Iterable[dict[str, Any]], *, limit: int = 15) -> list[str]:
    rows: list[str] = []
    for finding in list(findings)[:limit]:
        rows.append(
            "- {severity} {title} at {url} ({verified})".format(
                severity=str(finding.get("severity", "?")).upper(),
                title=str(finding.get("title", ""))[:70],
                url=str(finding.get("url", ""))[:80],
                verified="verified" if finding.get("verified") else "unverified",
            )
        )
    return rows


def technology_lines(graph: AssetGraph) -> list[str]:
    rows = []
    for node in graph.of_kind(NodeKind.TECHNOLOGY):
        version = node.attributes.get("version") or "?"
        rows.append(f"- {node.label} {version} ({node.attributes.get('category', 'unknown')})")
    return rows


def asset_view(graph: AssetGraph | None, *, max_tokens: int = 900, limit: int = 30) -> str:
    """Render the graph as a short briefing that fits in a prompt."""

    if graph is None:
        return "no asset graph available"
    sections: list[str] = []
    coverage = graph.coverage()
    sections.append(
        ("coverage: {e} endpoints ({u} untested), {p} parameters, {f} findings").format(
            e=coverage.get("endpoints", 0),
            u=coverage.get("endpoints_untested", 0),
            p=coverage.get("parameters", 0),
            f=coverage.get("findings", 0),
        )
    )
    technologies = technology_lines(graph)
    if technologies:
        sections.append("technologies:\n" + "\n".join(technologies[:12]))
    endpoints = endpoint_lines(graph, limit=limit)
    if endpoints:
        sections.append("endpoints (* = has a finding):\n" + "\n".join(endpoints))
    findings = [
        {
            "severity": node.attributes.get("severity"),
            "title": node.label,
            "url": node.attributes.get("url"),
            "verified": node.attributes.get("verified"),
        }
        for node in graph.of_kind(NodeKind.FINDING)
    ]
    if findings:
        sections.append("findings:\n" + "\n".join(finding_lines(findings)))
    text = "\n".join(sections)
    if estimate_text(text) > max_tokens:
        text = truncate_text(text, max_tokens, marker="\n… [asset view truncated]")
    return text


def node_brief(node: Node, graph: AssetGraph) -> dict[str, Any]:
    return {
        "id": node.id,
        "kind": node.kind.value,
        "label": node.label,
        "attributes": dict(node.attributes),
        "neighbors": len(graph.neighbors(node.id)),
    }
