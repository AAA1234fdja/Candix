"""Read the API description the target publishes about itself.

An OpenAPI document is a free map: paths, methods, parameters, schemas and, quite
often, the authentication scheme. When it is public it is also a finding: the
attack surface is documented for anyone who asks.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

from candix.agent.web import Fetch, fetch, is_json_response, join, origin_of
from candix.core.log import get_logger

log = get_logger("candix.agent.spec")

SPEC_PATHS = (
    "/openapi.json",
    "/openapi.yaml",
    "/openapi.yml",
    "/swagger.json",
    "/swagger/v1/swagger.json",
    "/api-docs",
    "/api-docs.json",
    "/v2/api-docs",
    "/v3/api-docs",
    "/api/swagger.json",
    "/docs/openapi.json",
    "/.well-known/openapi.json",
)

_METHODS = ("get", "post", "put", "patch", "delete", "head", "options", "trace")
_INDENT = re.compile(r"^(\s*)([A-Za-z0-9_./{}\-]+):\s*(.*)$")


@dataclass
class Operation:
    path: str
    method: str
    operation_id: str = ""
    summary: str = ""
    parameters: list[dict[str, Any]] = field(default_factory=list)
    request_fields: list[str] = field(default_factory=list)
    security: list[str] = field(default_factory=list)
    deprecated: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "method": self.method,
            "operation_id": self.operation_id,
            "summary": self.summary[:160],
            "parameters": [parameter.get("name", "") for parameter in self.parameters],
            "request_fields": self.request_fields[:20],
            "security": self.security,
            "deprecated": self.deprecated,
        }

    def url_for(self, base: str) -> str:
        return join(base, self.path)


@dataclass
class Spec:
    source: str
    title: str = ""
    version: str = ""
    openapi: str = ""
    servers: list[str] = field(default_factory=list)
    operations: list[Operation] = field(default_factory=list)
    security_schemes: dict[str, str] = field(default_factory=dict)
    schemas: list[str] = field(default_factory=list)
    raw_size: int = 0

    @property
    def count(self) -> int:
        return len(self.operations)

    def bases(self, fallback: str = "") -> list[str]:
        out = []
        for server in self.servers:
            if server.startswith("http"):
                out.append(server.rstrip("/"))
            elif server.startswith("/") and fallback:
                out.append(origin_of(fallback) + server.rstrip("/"))
        return out or ([fallback] if fallback else [])

    def by_tag(self) -> dict[str, int]:
        tags: dict[str, int] = {}
        for operation in self.operations:
            key = operation.path.split("/")[1] if "/" in operation.path.strip("/") else "root"
            tags[key] = tags.get(key, 0) + 1
        return dict(sorted(tags.items(), key=lambda pair: -pair[1]))

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "title": self.title,
            "version": self.version,
            "openapi": self.openapi,
            "servers": self.servers,
            "operations": [operation.to_dict() for operation in self.operations],
            "security_schemes": self.security_schemes,
            "schemas": self.schemas[:40],
            "groups": self.by_tag(),
        }

    def summary(self) -> str:
        groups = ", ".join(f"{name}:{count}" for name, count in list(self.by_tag().items())[:4])
        return f"{self.count} operation(s) from {self.source}" + (f" ({groups})" if groups else "")


# ----------------------------------------------------------------------
def _parameters(items: Any) -> list[dict[str, Any]]:
    output = []
    for item in items or []:
        if not isinstance(item, dict):
            continue
        output.append(
            {
                "name": str(item.get("name", "")),
                "in": str(item.get("in", "query")),
                "required": bool(item.get("required", False)),
                "type": str((item.get("schema") or {}).get("type", item.get("type", "string"))),
            }
        )
    return output


def _body_fields(operation: dict[str, Any]) -> list[str]:
    body = operation.get("requestBody") or {}
    content = body.get("content") or {}
    for _media, descriptor in content.items():
        schema = (descriptor or {}).get("schema") or {}
        properties = schema.get("properties") or {}
        if properties:
            return sorted(properties)
        reference = schema.get("$ref", "")
        if reference:
            return [reference.rsplit("/", 1)[-1]]
    parameters = operation.get("parameters") or []
    for parameter in parameters:
        if isinstance(parameter, dict) and parameter.get("in") == "body":
            schema = parameter.get("schema") or {}
            return sorted(schema.get("properties") or {})
    return []


def parse_json_spec(payload: dict[str, Any], source: str) -> Spec:
    info = payload.get("info") or {}
    spec = Spec(
        source=source,
        title=str(info.get("title", "")),
        version=str(info.get("version", "")),
        openapi=str(payload.get("openapi") or payload.get("swagger") or ""),
        servers=[str(server.get("url", "")) for server in payload.get("servers") or [] if isinstance(server, dict)],
        raw_size=len(json.dumps(payload)),
    )
    if not spec.servers and payload.get("host"):
        scheme = (payload.get("schemes") or ["https"])[0]
        spec.servers = [f"{scheme}://{payload.get('host')}{payload.get('basePath', '')}"]
    for name, definition in (payload.get("securityDefinitions") or payload.get("components", {}).get("securitySchemes") or {}).items():
        if isinstance(definition, dict):
            spec.security_schemes[str(name)] = str(definition.get("type", ""))
    schemas = (payload.get("definitions") or payload.get("components", {}).get("schemas") or {})
    spec.schemas = sorted(schemas)[:200]
    global_security = payload.get("security") or []
    for path, item in (payload.get("paths") or {}).items():
        if not isinstance(item, dict):
            continue
        for method in _METHODS:
            operation = item.get(method)
            if not isinstance(operation, dict):
                continue
            security = operation.get("security", global_security)
            spec.operations.append(
                Operation(
                    path=str(path),
                    method=method.upper(),
                    operation_id=str(operation.get("operationId", "")),
                    summary=str(operation.get("summary") or operation.get("description") or ""),
                    parameters=_parameters((item.get("parameters") or []) + (operation.get("parameters") or [])),
                    request_fields=_body_fields(operation),
                    security=[str(list(entry)[0]) for entry in security if isinstance(entry, dict) and entry],
                    deprecated=bool(operation.get("deprecated", False)),
                )
            )
    return spec


def _scalar(value: str) -> Any:
    text = value.strip()
    if not text:
        return ""
    if text[0:1] in {"'", '"'} and text[-1:] == text[0]:
        return text[1:-1]
    lowered = text.lower()
    if lowered in {"true", "false"}:
        return lowered == "true"
    if lowered in {"null", "~"}:
        return None
    if text.startswith("{") and text.endswith("}"):
        return _flow_mapping(text)
    if text.startswith("[") and text.endswith("]"):
        return [_scalar(item) for item in text[1:-1].split(",") if item.strip()]
    try:
        return int(text)
    except ValueError:
        pass
    try:
        return float(text)
    except ValueError:
        return text


def _flow_mapping(text: str) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for part in text[1:-1].split(","):
        if ":" not in part:
            continue
        key, _, value = part.partition(":")
        output[key.strip().strip("'\"")] = _scalar(value)
    return output


def _lines(text: str) -> list[tuple[int, str]]:
    output: list[tuple[int, str]] = []
    for raw in text.splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("---"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        output.append((indent, stripped))
    return output


def parse_yaml_lite(text: str) -> Any:
    """Parse the block subset of YAML that API documents use.

    Mappings, nested mappings, sequences of mappings and scalar values, plus
    inline ``{k: v}`` flow mappings. Anchors, multi-line strings and merge keys
    are out of scope, which is fine: OpenAPI documents rarely use them.
    """

    rows = _lines(text)
    if not rows:
        return {}
    value, index = _parse_block(rows, 0, rows[0][0])
    if index < len(rows):
        # tolerate trailing content at an unexpected indent
        extra, _index = _parse_block(rows, index, rows[index][0])
        if isinstance(value, dict) and isinstance(extra, dict):
            value.update(extra)
    return value


def _parse_block(rows: list[tuple[int, str]], index: int, indent: int) -> tuple[Any, int]:
    if index >= len(rows):
        return {}, index
    if rows[index][1].startswith("-"):
        return _parse_sequence(rows, index, indent)
    return _parse_mapping(rows, index, indent)


def _parse_mapping(rows: list[tuple[int, str]], index: int, indent: int) -> tuple[dict[str, Any], int]:
    output: dict[str, Any] = {}
    while index < len(rows):
        current_indent, text = rows[index]
        if current_indent < indent:
            break
        if current_indent > indent:
            index += 1
            continue
        if text.startswith("-"):
            break
        key, separator, value = text.partition(":")
        key = key.strip().strip("'\"")
        if not separator:
            index += 1
            continue
        index += 1
        if value.strip():
            output[key] = _scalar(value)
            continue
        if index < len(rows) and rows[index][0] > current_indent:
            child, index = _parse_block(rows, index, rows[index][0])
            output[key] = child
        elif index < len(rows) and rows[index][0] == current_indent and rows[index][1].startswith("-"):
            child, index = _parse_sequence(rows, index, current_indent)
            output[key] = child
        else:
            output[key] = {}
    return output, index


def _parse_sequence(rows: list[tuple[int, str]], index: int, indent: int) -> tuple[list[Any], int]:
    output: list[Any] = []
    while index < len(rows):
        current_indent, text = rows[index]
        if current_indent != indent or not text.startswith("-"):
            break
        rest = text[1:].strip()
        index += 1
        if not rest:
            if index < len(rows) and rows[index][0] > current_indent:
                child, index = _parse_block(rows, index, rows[index][0])
                output.append(child)
            else:
                output.append(None)
            continue
        if ":" in rest and not rest.startswith("{") and not rest.startswith("["):
            item: dict[str, Any] = {}
            key, _separator, value = rest.partition(":")
            key = key.strip().strip("'\"")
            item[key] = _scalar(value) if value.strip() else {}
            if index < len(rows) and rows[index][0] > current_indent:
                extra, index = _parse_mapping(rows, index, rows[index][0])
                if item[key] == {} and len(extra) == 1 and isinstance(list(extra.values())[0], dict):
                    item[key] = extra
                else:
                    item.update(extra)
            output.append(item)
        else:
            output.append(_scalar(rest))
            if index < len(rows) and rows[index][0] > current_indent:
                _ignored, index = _parse_block(rows, index, rows[index][0])
    return output, index


def parse_spec(record: Fetch) -> Spec | None:
    if is_json_response(record):
        payload = record.json()
        if isinstance(payload, dict):
            return parse_json_spec(payload, record.url)
        return None
    text = record.body
    if not text.strip():
        return None
    if "openapi" in text[:4000] or "swagger" in text[:4000] or "paths:" in text:
        try:
            payload = parse_yaml_lite(text)
        except Exception as error:
            log.debug(f"yaml parse failed for {record.url}: {error}")
            return None
        if isinstance(payload, dict) and payload.get("paths"):
            return parse_json_spec(payload, record.url)
    return None


def discover(ctx: Any, base: str, *, paths: tuple[str, ...] = SPEC_PATHS, limit: int = 12) -> tuple[Spec | None, list[str]]:
    tried: list[str] = []
    for path in paths[:limit]:
        url = join(base, path)
        record = fetch(ctx, url)
        tried.append(f"{path}:{record.status}")
        if record.status not in (200, 201):
            continue
        spec = parse_spec(record)
        if spec is not None and spec.operations:
            return spec, tried
    return None, tried


def ingest(spec: Spec, assets: Any, *, base: str = "") -> dict[str, int]:
    counts = {"endpoints": 0, "parameters": 0}
    bases = spec.bases(base)
    for operation in spec.operations:
        for candidate in bases or [base]:
            url = operation.url_for(candidate)
            node = assets.add_endpoint(operation.method, url, source="openapi")
            counts["endpoints"] += 1
            seen: set[str] = set()
            for parameter in operation.parameters:
                name = str(parameter.get("name", ""))
                if not name or name in seen:
                    continue
                seen.add(name)
                assets.add_parameter(node.id, name, location=str(parameter.get("in", "query")))
                counts["parameters"] += 1
            for name in operation.request_fields:
                if name in seen:
                    continue
                seen.add(name)
                assets.add_parameter(node.id, name, location="body")
                counts["parameters"] += 1
    return counts


def finding_for(spec: Spec) -> dict[str, Any]:
    return {
        "title": "API specification is publicly accessible",
        "severity": "low",
        "category": "exposure",
        "detector": "agent.api_spec",
        "url": spec.source,
        "description": (
            f"The API description at {spec.source} is readable without authentication and documents "
            f"{spec.count} operation(s)."
        ),
        "impact": "Attackers get a complete map of endpoints, parameters and authentication schemes.",
        "remediation": "Require authentication for the specification, or publish only a curated subset.",
        "confidence": "observed",
        "verified": True,
        "tags": ["api", "exposure"],
        "evidence": [{"kind": "response", "summary": f"{spec.count} operations enumerated"}],
    }


def tool_api_spec(ctx: Any, arguments: dict[str, Any]) -> dict[str, Any]:
    base = str(arguments.get("url", "")).rstrip("/")
    if not base:
        targets = list(ctx.state.get("targets") or [])
        base = targets[0] if targets else ""
    spec, tried = discover(ctx, base, limit=int(arguments.get("limit", 12)))
    if spec is None:
        return {"summary": f"no API specification found at {base}", "tried": tried, "operations": []}
    assets = ctx.state.get("assets")
    counts = ingest(spec, assets) if assets is not None else {"endpoints": 0, "parameters": 0}
    return {
        "summary": spec.summary(),
        "tried": tried,
        "operations": [operation.to_dict() for operation in spec.operations[:80]],
        "servers": spec.servers,
        "security_schemes": spec.security_schemes,
        "schemas": spec.schemas[:40],
        "ingested": counts,
        "findings": [finding_for(spec)] if spec.count else [],
    }
