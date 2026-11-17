"""Two linked graphs: what exists on the target, and what was tried.

``AssetGraph`` is shared knowledge about the target: hosts, services, endpoints,
parameters, technologies and findings. ``ExplorationGraph`` is scoped to one
goal: intents, observations, facts and decisions. Anchors join them, so a fact
can be traced to the endpoint it came from and an endpoint can list every fact
that mentions it.
"""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterable, Iterator
from urllib.parse import urlsplit, urlunsplit


class NodeKind(str, Enum):
    HOST = "host"
    SERVICE = "service"
    ENDPOINT = "endpoint"
    PARAMETER = "parameter"
    TECHNOLOGY = "technology"
    FINDING = "finding"
    FACT = "fact"
    INTENT = "intent"
    OBSERVATION = "observation"
    DECISION = "decision"


class EdgeKind(str, Enum):
    RESOLVES_TO = "resolves_to"
    EXPOSES = "exposes"
    HAS_PARAMETER = "has_parameter"
    FINGERPRINTS = "fingerprints"
    ANCHORS = "anchors"
    PRODUCED = "produced"
    RELATES_TO = "relates_to"
    DEPENDS_ON = "depends_on"
    CONTRADICTS = "contradicts"


def _node_id(kind: NodeKind, key: str) -> str:
    return f"{kind.value}:{key}"


@dataclass
class Node:
    id: str
    kind: NodeKind
    label: str
    attributes: dict[str, Any] = field(default_factory=dict)
    created_at: float = 0.0
    updated_at: float = 0.0
    hits: int = 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind.value,
            "label": self.label,
            "attributes": dict(self.attributes),
            "hits": self.hits,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "Node":
        return cls(
            id=str(payload.get("id", "")),
            kind=NodeKind(payload.get("kind", "endpoint")),
            label=str(payload.get("label", "")),
            attributes=dict(payload.get("attributes") or {}),
            hits=int(payload.get("hits", 1) or 1),
        )


@dataclass
class Edge:
    src: str
    dst: str
    kind: EdgeKind
    attributes: dict[str, Any] = field(default_factory=dict)

    @property
    def id(self) -> str:
        return f"{self.src}->{self.dst}:{self.kind.value}"

    def to_dict(self) -> dict[str, Any]:
        return {"src": self.src, "dst": self.dst, "kind": self.kind.value, "attributes": dict(self.attributes)}

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "Edge":
        return cls(
            src=str(payload.get("src", "")),
            dst=str(payload.get("dst", "")),
            kind=EdgeKind(payload.get("kind", "relates_to")),
            attributes=dict(payload.get("attributes") or {}),
        )


class Graph:
    """Small property graph with typed edges and deterministic serialisation."""

    def __init__(self) -> None:
        self.nodes: dict[str, Node] = {}
        self.edges: dict[str, Edge] = {}
        self._out: dict[str, list[str]] = defaultdict(list)
        self._in: dict[str, list[str]] = defaultdict(list)

    # ------------------------------------------------------------------
    def upsert(self, node_id: str, kind: NodeKind, label: str = "", **attributes: Any) -> Node:
        existing = self.nodes.get(node_id)
        if existing is not None:
            existing.hits += 1
            existing.attributes.update({key: value for key, value in attributes.items() if value not in (None, "", [])})
            if label and not existing.label:
                existing.label = label
            return existing
        node = Node(id=node_id, kind=kind, label=label or node_id, attributes=dict(attributes))
        self.nodes[node_id] = node
        return node

    def connect(self, src: str, dst: str, kind: EdgeKind, **attributes: Any) -> Edge:
        edge = Edge(src=src, dst=dst, kind=kind, attributes=dict(attributes))
        if edge.id not in self.edges:
            self.edges[edge.id] = edge
            self._out[src].append(edge.id)
            self._in[dst].append(edge.id)
        else:
            self.edges[edge.id].attributes.update(attributes)
        return edge

    # ------------------------------------------------------------------
    def node(self, node_id: str) -> Node | None:
        return self.nodes.get(node_id)

    def of_kind(self, kind: NodeKind | str) -> list[Node]:
        wanted = NodeKind(kind) if not isinstance(kind, NodeKind) else kind
        return [node for node in self.nodes.values() if node.kind is wanted]

    def outgoing(self, node_id: str, kind: EdgeKind | None = None) -> list[Edge]:
        edges = [self.edges[edge_id] for edge_id in self._out.get(node_id, [])]
        return [edge for edge in edges if kind is None or edge.kind is kind]

    def incoming(self, node_id: str, kind: EdgeKind | None = None) -> list[Edge]:
        edges = [self.edges[edge_id] for edge_id in self._in.get(node_id, [])]
        return [edge for edge in edges if kind is None or edge.kind is kind]

    def neighbors(self, node_id: str, kind: EdgeKind | None = None, *, depth: int = 1) -> set[str]:
        seen: set[str] = set()
        frontier = deque([(node_id, 0)])
        while frontier:
            current, distance = frontier.popleft()
            if distance >= depth:
                continue
            for edge in self.outgoing(current, kind) + self.incoming(current, kind):
                other = edge.dst if edge.src == current else edge.src
                if other not in seen and other != node_id:
                    seen.add(other)
                    frontier.append((other, distance + 1))
        return seen

    def path(self, src: str, dst: str, *, limit: int = 6) -> list[str]:
        if src not in self.nodes or dst not in self.nodes:
            return []
        queue = deque([[src]])
        visited = {src}
        while queue:
            trail = queue.popleft()
            if len(trail) > limit:
                continue
            current = trail[-1]
            if current == dst:
                return trail
            for edge in self.outgoing(current):
                if edge.dst in visited:
                    continue
                visited.add(edge.dst)
                queue.append(trail + [edge.dst])
        return []

    def degree(self) -> dict[str, int]:
        return {node_id: len(self._out.get(node_id, [])) + len(self._in.get(node_id, [])) for node_id in self.nodes}

    def hubs(self, limit: int = 5) -> list[tuple[str, int]]:
        return sorted(self.degree().items(), key=lambda item: (-item[1], item[0]))[:limit]

    # ------------------------------------------------------------------
    def stats(self) -> dict[str, Any]:
        kinds: dict[str, int] = {}
        for node in self.nodes.values():
            kinds[node.kind.value] = kinds.get(node.kind.value, 0) + 1
        edges: dict[str, int] = {}
        for edge in self.edges.values():
            edges[edge.kind.value] = edges.get(edge.kind.value, 0) + 1
        return {"nodes": len(self.nodes), "edges": len(self.edges), "by_kind": kinds, "by_edge": edges}

    def digest(self) -> str:
        payload = json.dumps(self.to_dict(), sort_keys=True, ensure_ascii=False).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        return {
            "nodes": [node.to_dict() for node in sorted(self.nodes.values(), key=lambda item: item.id)],
            "edges": [edge.to_dict() for edge in sorted(self.edges.values(), key=lambda item: item.id)],
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "Graph":
        graph = cls()
        for item in payload.get("nodes") or []:
            node = Node.from_dict(item)
            graph.nodes[node.id] = node
        for item in payload.get("edges") or []:
            edge = Edge.from_dict(item)
            graph.edges[edge.id] = edge
            graph._out[edge.src].append(edge.id)
            graph._in[edge.dst].append(edge.id)
        return graph

    def __len__(self) -> int:
        return len(self.nodes)

    def __iter__(self) -> Iterator[Node]:
        return iter(self.nodes.values())


# ----------------------------------------------------------------------
# Asset graph


def endpoint_key(method: str, url: str) -> str:
    parts = urlsplit(url)
    path = parts.path or "/"
    query = sorted(parts.query.split("&")) if parts.query else []
    query_text = "&".join(item for item in query if item and not item.endswith("="))
    return f"{method.upper()} {urlunsplit((parts.scheme, parts.netloc, path, query_text, ''))}"


class AssetGraph(Graph):
    """Knowledge about the target shared by every goal in an engagement."""

    def add_host(self, host: str, **attributes: Any) -> Node:
        return self.upsert(_node_id(NodeKind.HOST, host), NodeKind.HOST, host, **attributes)

    def add_service(self, host: str, port: int, scheme: str = "http", **attributes: Any) -> Node:
        host_node = self.add_host(host)
        node = self.upsert(
            _node_id(NodeKind.SERVICE, f"{host}:{port}/{scheme}"),
            NodeKind.SERVICE,
            f"{scheme}://{host}:{port}",
            port=port,
            scheme=scheme,
            **attributes,
        )
        self.connect(host_node.id, node.id, EdgeKind.RESOLVES_TO)
        return node

    def add_endpoint(self, method: str, url: str, *, host: str = "", status: int = 0, **attributes: Any) -> Node:
        parts = urlsplit(url)
        host = host or parts.hostname or ""
        port = parts.port or (443 if parts.scheme == "https" else 80)
        service = self.add_service(host, port, parts.scheme or "http")
        node = self.upsert(
            _node_id(NodeKind.ENDPOINT, endpoint_key(method, url)),
            NodeKind.ENDPOINT,
            f"{method.upper()} {parts.path or '/'}",
            method=method.upper(),
            url=urlunsplit((parts.scheme, parts.netloc, parts.path, parts.query, "")),
            path=parts.path or "/",
            status=status,
            **attributes,
        )
        self.connect(service.id, node.id, EdgeKind.EXPOSES)
        if parts.query:
            for pair in parts.query.split("&"):
                name = pair.split("=", 1)[0]
                if name:
                    parameter = self.add_parameter(node.id, name, location="query")
                    self.connect(node.id, parameter.id, EdgeKind.HAS_PARAMETER)
        return node

    def add_parameter(self, endpoint_id: str, name: str, *, location: str = "query", **attributes: Any) -> Node:
        return self.upsert(
            _node_id(NodeKind.PARAMETER, f"{endpoint_id}#{location}:{name}"),
            NodeKind.PARAMETER,
            name,
            location=location,
            endpoint=endpoint_id,
            **attributes,
        )

    def add_technology(self, name: str, *, version: str = "", category: str = "", confidence: float = 0.0) -> Node:
        return self.upsert(
            _node_id(NodeKind.TECHNOLOGY, name.lower()),
            NodeKind.TECHNOLOGY,
            name,
            version=version,
            category=category,
            confidence=confidence,
        )

    def add_finding(self, finding: dict[str, Any]) -> Node:
        identifier = str(finding.get("id") or finding.get("dedupe_key") or finding.get("title", ""))
        node = self.upsert(
            _node_id(NodeKind.FINDING, identifier),
            NodeKind.FINDING,
            str(finding.get("title", "finding")),
            severity=str(finding.get("severity", "")),
            url=str(finding.get("url", "")),
            verified=bool(finding.get("verified", False)),
            category=str(finding.get("category", "")),
        )
        url = str(finding.get("url", ""))
        if url:
            endpoint = self.add_endpoint(str(finding.get("method", "GET")), url)
            self.connect(node.id, endpoint.id, EdgeKind.RELATES_TO)
        return node

    # ------------------------------------------------------------------
    def endpoints(self, *, path_contains: str = "") -> list[Node]:
        nodes = self.of_kind(NodeKind.ENDPOINT)
        if path_contains:
            nodes = [node for node in nodes if path_contains in str(node.attributes.get("path", ""))]
        return sorted(nodes, key=lambda item: str(item.attributes.get("url", "")))

    def endpoints_without_findings(self) -> list[Node]:
        tested = self.endpoints_with_findings()
        return [node for node in self.endpoints() if node.id not in {item.id for item in tested}]

    def endpoints_with_findings(self) -> list[Node]:
        covered: list[Node] = []
        for node in self.endpoints():
            if self.incoming(node.id, EdgeKind.RELATES_TO):
                covered.append(node)
        return covered

    def parameters(self) -> list[Node]:
        return sorted(self.of_kind(NodeKind.PARAMETER), key=lambda item: item.label)

    def findings_by_severity(self) -> dict[str, int]:
        grouped: dict[str, int] = {}
        for node in self.of_kind(NodeKind.FINDING):
            severity = str(node.attributes.get("severity", "info"))
            grouped[severity] = grouped.get(severity, 0) + 1
        return grouped

    def coverage(self) -> dict[str, Any]:
        endpoints = self.endpoints()
        covered = self.endpoints_with_findings()
        return {
            "hosts": len(self.of_kind(NodeKind.HOST)),
            "services": len(self.of_kind(NodeKind.SERVICE)),
            "endpoints": len(endpoints),
            "endpoints_with_findings": len(covered),
            "endpoints_untested": len(endpoints) - len(covered),
            "parameters": len(self.parameters()),
            "technologies": len(self.of_kind(NodeKind.TECHNOLOGY)),
            "findings": len(self.of_kind(NodeKind.FINDING)),
        }

    def to_mermaid(self, *, limit: int = 60) -> str:
        lines = ["graph LR"]
        nodes = sorted(self.nodes.values(), key=lambda item: (-item.hits, item.id))[:limit]
        keep = {node.id for node in nodes}
        for node in nodes:
            label = node.label.replace('"', "'")[:40]
            shape = {
                NodeKind.HOST: (f'{_short(node.id)}["{label}"]'),
                NodeKind.SERVICE: (f'{_short(node.id)}(("{label}"))'),
                NodeKind.ENDPOINT: (f'{_short(node.id)}("{label}")'),
                NodeKind.FINDING: (f'{_short(node.id)}{{{{"{label}"}}}}'),
            }.get(node.kind, f'{_short(node.id)}["{label}"]')
            lines.append(f"  {shape}")
        for edge in self.edges.values():
            if edge.src in keep and edge.dst in keep and edge.kind is not EdgeKind.ANCHORS:
                lines.append(f"  {_short(edge.src)} -->|{edge.kind.value}| {_short(edge.dst)}")
        return "\n".join(lines)


def _short(node_id: str) -> str:
    return hashlib.sha1(node_id.encode("utf-8")).hexdigest()[:8]


# ----------------------------------------------------------------------
# Exploration graph


class ExplorationGraph(Graph):
    """What this goal tried, observed and concluded."""

    def add_intent(self, intent: Any) -> Node:
        return self.upsert(
            _node_id(NodeKind.INTENT, intent.id),
            NodeKind.INTENT,
            intent.title,
            phase=intent.phase.value,
            status=intent.status.value,
            tool=intent.tool,
            risk=intent.risk,
        )

    def add_observation(self, observation: Any) -> Node:
        key = observation.digest or observation.summary[:32]
        return self.upsert(
            _node_id(NodeKind.OBSERVATION, key),
            NodeKind.OBSERVATION,
            observation.summary[:120],
            tool=observation.tool,
            untrusted=observation.untrusted,
        )

    def add_fact(self, fact: Any) -> Node:
        return self.upsert(
            _node_id(NodeKind.FACT, fact.id),
            NodeKind.FACT,
            fact.claim[:120],
            source=fact.source.value,
            confidence=fact.confidence.value,
            provable=fact.provable,
        )

    def add_decision(self, decision: Any, *, index: int = 0) -> Node:
        return self.upsert(
            _node_id(NodeKind.DECISION, str(index)),
            NodeKind.DECISION,
            decision.action,
            reasoning=decision.reasoning[:200],
            confidence=decision.confidence,
        )

    def link_intent_observation(self, intent_id: str, observation_id: str, *, step: str = "") -> Edge:
        source = intent_id if ":" in intent_id else _node_id(NodeKind.INTENT, intent_id)
        return self.connect(source, observation_id, EdgeKind.PRODUCED, step=step)

    def link_fact_evidence(self, fact_node: str, observation_node: str) -> Edge:
        return self.connect(fact_node, observation_node, EdgeKind.ANCHORS)

    def contradiction(self, first_fact: str, second_fact: str) -> Edge:
        return self.connect(
            _node_id(NodeKind.FACT, first_fact),
            _node_id(NodeKind.FACT, second_fact),
            EdgeKind.CONTRADICTS,
        )

    def blocked_paths(self) -> list[Node]:
        return [node for node in self.of_kind(NodeKind.INTENT) if node.attributes.get("status") == "blocked"]

    def failed_intents(self) -> list[Node]:
        return [node for node in self.of_kind(NodeKind.INTENT) if node.attributes.get("status") == "failed"]

    def summary(self) -> dict[str, Any]:
        stats = self.stats()
        return {
            "intents": stats["by_kind"].get("intent", 0),
            "observations": stats["by_kind"].get("observation", 0),
            "facts": stats["by_kind"].get("fact", 0),
            "decisions": stats["by_kind"].get("decision", 0),
            "blocked": len(self.blocked_paths()),
            "failed": len(self.failed_intents()),
        }


@dataclass
class LinkedGraphs:
    """Both graphs plus the anchors between them."""

    assets: AssetGraph = field(default_factory=AssetGraph)
    exploration: ExplorationGraph = field(default_factory=ExplorationGraph)
    anchors: list[dict[str, str]] = field(default_factory=list)

    def anchor(self, asset_id: str, fact_id: str, *, relation: str = "supports") -> None:
        entry = {"asset": asset_id, "fact": fact_id, "relation": relation}
        if entry not in self.anchors:
            self.anchors.append(entry)
        self.exploration.connect(_node_id(NodeKind.FACT, fact_id), asset_id, EdgeKind.ANCHORS, relation=relation)

    def facts_for(self, asset_id: str) -> list[str]:
        return [entry["fact"] for entry in self.anchors if entry["asset"] == asset_id]

    def assets_for(self, fact_id: str) -> list[str]:
        return [entry["asset"] for entry in self.anchors if entry["fact"] == fact_id]

    def to_dict(self) -> dict[str, Any]:
        return {
            "assets": self.assets.to_dict(),
            "exploration": self.exploration.to_dict(),
            "anchors": list(self.anchors),
        }

    def summary(self) -> dict[str, Any]:
        return {
            "assets": self.assets.stats(),
            "exploration": self.exploration.summary(),
            "anchors": len(self.anchors),
            "coverage": self.assets.coverage(),
        }

    def mermaid(self) -> str:
        return self.assets.to_mermaid()
