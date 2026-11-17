"""GraphQL: read the schema, then ask narrow questions.

Introspection is the cheapest map a GraphQL endpoint can give away, and a
publicly introspectable production schema is worth reporting on its own. Queries
built from the schema are also the only practical way to test authorization on
fields the UI never shows.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from candix.agent.web import Fetch, fetch, is_json_response
from candix.core.log import get_logger

log = get_logger("candix.agent.graphql")

INTROSPECTION = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      kind
      name
      fields {
        name
        args { name type { kind name ofType { kind name ofType { kind name } } } }
        type { kind name ofType { kind name ofType { kind name } } }
      }
      enumValues { name }
    }
  }
}
""".strip()

MINIMAL_INTROSPECTION = "query { __schema { types { name kind } } }"

DEFAULT_ENDPOINTS = ("/graphql", "/api/graphql", "/v1/graphql", "/query", "/gql")

_SCALARS = {"String", "Int", "Float", "Boolean", "ID"}


@dataclass
class Field:
    name: str
    type_name: str = ""
    arguments: list[str] = field(default_factory=list)
    is_list: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "type": self.type_name, "args": self.arguments, "list": self.is_list}


@dataclass
class ObjectType:
    name: str
    kind: str = "OBJECT"
    fields: list[Field] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "kind": self.kind, "fields": [item.to_dict() for item in self.fields[:40]]}


@dataclass
class Schema:
    endpoint: str
    query_type: str = "Query"
    mutation_type: str = ""
    types: dict[str, ObjectType] = field(default_factory=dict)

    @property
    def query_fields(self) -> list[Field]:
        return list(self.types.get(self.query_type, ObjectType(self.query_type)).fields)

    @property
    def mutation_fields(self) -> list[Field]:
        return list(self.types.get(self.mutation_type, ObjectType(self.mutation_type)).fields) if self.mutation_type else []

    def interesting_types(self) -> list[str]:
        return sorted(name for name in self.types if not name.startswith("__") and name not in _SCALARS)

    def to_dict(self) -> dict[str, Any]:
        return {
            "endpoint": self.endpoint,
            "query_type": self.query_type,
            "mutation_type": self.mutation_type,
            "types": [self.types[name].to_dict() for name in self.interesting_types()][:40],
            "query_fields": [item.to_dict() for item in self.query_fields[:20]],
            "mutation_fields": [item.to_dict() for item in self.mutation_fields[:20]],
        }

    def summary(self) -> str:
        return (
            f"{len(self.interesting_types())} type(s), {len(self.query_fields)} query field(s), "
            f"{len(self.mutation_fields)} mutation(s) at {self.endpoint}"
        )


def _type_name(node: Any, depth: int = 0) -> tuple[str, bool]:
    if not isinstance(node, dict) or depth > 5:
        return "", False
    kind = node.get("kind")
    name = node.get("name") or ""
    if kind == "LIST":
        inner, _ = _type_name(node.get("ofType"), depth + 1)
        return inner, True
    if kind == "NON_NULL":
        return _type_name(node.get("ofType"), depth + 1)
    return str(name), False


def parse_schema(payload: dict[str, Any], endpoint: str) -> Schema | None:
    data = (payload.get("data") or {}).get("__schema") if isinstance(payload.get("data"), dict) else payload.get("__schema")
    if not isinstance(data, dict):
        return None
    schema = Schema(endpoint=endpoint)
    schema.query_type = str((data.get("queryType") or {}).get("name") or "Query")
    schema.mutation_type = str((data.get("mutationType") or {}).get("name") or "")
    for raw in data.get("types") or []:
        if not isinstance(raw, dict):
            continue
        name = str(raw.get("name") or "")
        if not name:
            continue
        object_type = ObjectType(name=name, kind=str(raw.get("kind") or "OBJECT"))
        for raw_field in raw.get("fields") or []:
            if not isinstance(raw_field, dict):
                continue
            type_name, is_list = _type_name(raw_field.get("type"))
            arguments = []
            for argument in raw_field.get("args") or []:
                if isinstance(argument, dict) and argument.get("name"):
                    arguments.append(str(argument["name"]))
            object_type.fields.append(
                Field(name=str(raw_field.get("name") or ""), type_name=type_name, arguments=arguments, is_list=is_list)
            )
        schema.types[name] = object_type
    return schema


def query_endpoint(ctx: Any, url: str, query: str, *, variables: dict[str, Any] | None = None, headers: dict[str, str] | None = None) -> Fetch:
    payload: dict[str, Any] = {"query": query}
    if variables:
        payload["variables"] = variables
    merged = {"content-type": "application/json", "accept": "application/json"}
    merged.update(headers or {})
    return fetch(ctx, url, method="POST", json_body=payload, headers=merged, max_bytes=200000)


def introspect(ctx: Any, url: str, *, headers: dict[str, str] | None = None) -> tuple[Schema | None, Fetch]:
    record = query_endpoint(ctx, url, INTROSPECTION, headers=headers)
    if not record.ok:
        return None, record
    payload = record.json()
    if not isinstance(payload, dict):
        return None, record
    if payload.get("errors"):
        record.body = json.dumps({"errors": payload["errors"]})[:2000]
        return None, record
    return parse_schema(payload, url), record


def discover(ctx: Any, base: str, *, endpoints: tuple[str, ...] = DEFAULT_ENDPOINTS) -> tuple[Schema | None, str, list[str]]:
    tried: list[str] = []
    root = base.rstrip("/")
    for path in endpoints:
        url = root + path
        schema, record = introspect(ctx, url)
        tried.append(f"{path}:{record.status}")
        if schema is not None and (schema.query_fields or schema.interesting_types()):
            return schema, url, tried
        if record.ok and isinstance(record.json(), dict) and record.json().get("errors"):
            return None, url, tried
    return None, "", tried


def sample_query(field_spec: Field, *, limit: int = 6) -> str:
    """Build a small selection for a field, using scalar subfields."""

    name = field_spec.name
    args = "".join(f"(${argument}: String)" for argument in field_spec.arguments[:3])
    call = name
    if args:
        call = f"{name}({args[1:-1].replace('$', '')})"
    return "query { %s { __typename } }" % call


def selection_for(schema: Schema, type_name: str, *, depth: int = 1) -> str:
    object_type = schema.types.get(type_name)
    if object_type is None:
        return "__typename"
    parts = ["__typename"]
    for field_spec in object_type.fields:
        if field_spec.arguments:
            continue
        if field_spec.type_name in _SCALARS:
            parts.append(field_spec.name)
            continue
        if depth > 1:
            parts.append(f"{field_spec.name} {{ {selection_for(schema, field_spec.type_name, depth=depth - 1)} }}")
    return " ".join(parts[:12])


def build_query(schema: Schema, *, type_name: str = "", limit: int = 5) -> str:
    object_type = schema.types.get(type_name or schema.query_type)
    if object_type is None:
        return "query { __typename }"
    parts = []
    for field_spec in object_type.fields[:limit]:
        if field_spec.arguments:
            continue
        if field_spec.type_name in _SCALARS:
            parts.append(field_spec.name)
        else:
            parts.append(f"{field_spec.name} {{ {selection_for(schema, field_spec.type_name)} }}")
    return "query { " + " ".join(parts) + " }"


def finding_for(schema: Schema) -> dict[str, Any]:
    return {
        "title": "GraphQL introspection is enabled",
        "severity": "low",
        "category": "exposure",
        "detector": "agent.graphql",
        "url": schema.endpoint,
        "description": f"The schema is readable through introspection: {schema.summary()}",
        "impact": "Attackers can enumerate every type, field and mutation without guessing.",
        "remediation": "Disable introspection in production, or restrict it to authenticated operators.",
        "confidence": "observed",
        "verified": True,
        "tags": ["graphql", "exposure"],
    }


def tool_graphql(ctx: Any, arguments: dict[str, Any]) -> dict[str, Any]:
    base = str(arguments.get("url", "")).rstrip("/")
    if not base:
        targets = list(ctx.state.get("targets") or [])
        base = targets[0] if targets else ""
    headers = dict(arguments.get("headers") or {})
    query = str(arguments.get("query", "")).strip()
    if query:
        record = query_endpoint(ctx, base, query, variables=arguments.get("variables"), headers=headers)
        payload = record.json() if is_json_response(record) else None
        return {
            "summary": f"query executed: {record.status} ({record.length} bytes)",
            "status": record.status,
            "data": (payload or {}).get("data") if isinstance(payload, dict) else None,
            "errors": (payload or {}).get("errors") if isinstance(payload, dict) else None,
        }
    schema, endpoint, tried = discover(ctx, base)
    if schema is None:
        return {"summary": f"no introspectable GraphQL endpoint under {base}", "tried": tried}
    assets = ctx.state.get("assets")
    if assets is not None:
        for name in schema.interesting_types()[:100]:
            assets.add_endpoint("POST", endpoint, source="graphql")
            break
    return {
        "summary": schema.summary(),
        "endpoint": endpoint,
        "tried": tried,
        "schema": schema.to_dict(),
        "sample_query": build_query(schema),
        "findings": [finding_for(schema)],
    }
