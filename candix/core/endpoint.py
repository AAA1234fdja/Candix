"""Endpoint and parameter modelling.

Detectors do not work against raw URLs: they need to know which parameters are
injectable, where they live (query, body, header, cookie, path) and what the
baseline value was. The crawler and the OpenAPI importer both emit
:class:`Endpoint` objects so detectors have a single input contract.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Iterable, Iterator

from candix.core.ids import endpoint_id as new_endpoint_id
from candix.net.url import URL, QueryParams


@dataclass
class Param:
    """A single request parameter."""

    name: str
    value: str = ""
    location: str = "query"  # query | body | json | header | cookie | path
    kind: str = "string"  # string | int | bool | json | array | file
    observed: list[str] = field(default_factory=list)
    reflected: bool = False
    injectable: bool = True

    @property
    def key(self) -> str:
        return f"{self.location}:{self.name}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "value": self.value,
            "location": self.location,
            "kind": self.kind,
            "observed": list(self.observed),
            "reflected": self.reflected,
            "injectable": self.injectable,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "Param":
        return cls(
            name=payload.get("name", ""),
            value=payload.get("value", ""),
            location=payload.get("location", "query"),
            kind=payload.get("kind", "string"),
            observed=list(payload.get("observed", [])),
            reflected=bool(payload.get("reflected", False)),
            injectable=bool(payload.get("injectable", True)),
        )


@dataclass
class Body:
    """Request body representation."""

    content_type: str = ""
    raw: str = ""
    form: dict[str, str] = field(default_factory=dict)
    json: Any = None
    files: dict[str, str] = field(default_factory=dict)

    @property
    def kind(self) -> str:
        lowered = self.content_type.lower()
        if "json" in lowered:
            return "json"
        if "x-www-form-urlencoded" in lowered:
            return "form"
        if "multipart/form-data" in lowered:
            return "multipart"
        if "xml" in lowered:
            return "xml"
        return "raw"

    def to_dict(self) -> dict[str, Any]:
        return {
            "content_type": self.content_type,
            "raw": self.raw,
            "form": dict(self.form),
            "json": self.json,
            "files": dict(self.files),
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "Body":
        return cls(
            content_type=payload.get("content_type", ""),
            raw=payload.get("raw", ""),
            form=dict(payload.get("form", {})),
            json=payload.get("json"),
            files=dict(payload.get("files", {})),
        )


@dataclass
class Endpoint:
    """A request template discovered during recon."""

    url: str
    method: str = "GET"
    params: list[Param] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    body: Body | None = None
    source: str = "crawler"
    tags: set[str] = field(default_factory=set)
    auth_required: bool = False
    forms: list[dict[str, Any]] = field(default_factory=list)
    response_hint: dict[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=new_endpoint_id)
    depth: int = 0
    first_seen: str = ""

    # ------------------------------------------------------------------
    @classmethod
    def from_url(
        cls,
        url: str,
        *,
        method: str = "GET",
        source: str = "crawler",
        params: Iterable[Param] | None = None,
    ) -> "Endpoint":
        parsed = URL.parse(url)
        discovered = list(params) if params else [
            Param(name=name, value=value, location="query")
            for name, value in parsed.query.get_all()
        ]
        return cls(url=parsed.render(), method=method.upper(), params=discovered, source=source)

    @property
    def parsed(self) -> URL:
        return URL.parse(self.url)

    @property
    def host(self) -> str:
        return URL.parse(self.url).host

    @property
    def path(self) -> str:
        return URL.parse(self.url).path

    def identity(self) -> str:
        parsed = URL.parse(self.url)
        param_names = "&".join(sorted(param.name for param in self.params if param.location == "query"))
        return f"{self.method.upper()} {parsed.scheme}://{parsed.netloc}{parsed.path}?{param_names}"

    def key(self) -> str:
        from candix.core.ids import short_hash

        return short_hash(self.identity(), self.source, length=16)

    def parameters(self, locations: Iterable[str] = ("query", "body", "json", "header", "cookie")) -> list[Param]:
        wanted = set(locations)
        return [param for param in self.params if param.location in wanted and param.injectable]

    def add_param(self, param: Param) -> "Endpoint":
        if not any(existing.key == param.key for existing in self.params):
            self.params.append(param)
        return self

    def has_param(self, name: str, location: str | None = None) -> bool:
        return any(
            param.name == name and (location is None or param.location == location)
            for param in self.params
        )

    def with_params(self, values: dict[str, str], *, location: str = "query") -> "Endpoint":
        """Return a copy with parameter values replaced."""

        clone = self.copy()
        for param in clone.params:
            if param.location == location and param.name in values:
                param.value = values[param.name]
        return clone

    def copy(self) -> "Endpoint":
        return Endpoint(
            url=self.url,
            method=self.method,
            params=[Param.from_dict(param.to_dict()) for param in self.params],
            headers=dict(self.headers),
            cookies=dict(self.cookies),
            body=Body.from_dict(self.body.to_dict()) if self.body else None,
            source=self.source,
            tags=set(self.tags),
            auth_required=self.auth_required,
            forms=[dict(form) for form in self.forms],
            response_hint=dict(self.response_hint),
            depth=self.depth,
            first_seen=self.first_seen,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "url": self.url,
            "method": self.method,
            "params": [param.to_dict() for param in self.params],
            "headers": self.headers,
            "cookies": self.cookies,
            "body": self.body.to_dict() if self.body else None,
            "source": self.source,
            "tags": sorted(self.tags),
            "auth_required": self.auth_required,
            "forms": self.forms,
            "response_hint": self.response_hint,
            "depth": self.depth,
            "first_seen": self.first_seen,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "Endpoint":
        return cls(
            id=payload.get("id", new_endpoint_id()),
            url=payload.get("url", ""),
            method=payload.get("method", "GET"),
            params=[Param.from_dict(item) for item in payload.get("params", [])],
            headers=dict(payload.get("headers", {})),
            cookies=dict(payload.get("cookies", {})),
            body=Body.from_dict(payload["body"]) if payload.get("body") else None,
            source=payload.get("source", "crawler"),
            tags=set(payload.get("tags", [])),
            auth_required=bool(payload.get("auth_required", False)),
            forms=list(payload.get("forms", [])),
            response_hint=dict(payload.get("response_hint", {})),
            depth=int(payload.get("depth", 0)),
            first_seen=payload.get("first_seen", ""),
        )

    def __str__(self) -> str:  # pragma: no cover - display helper
        return f"{self.method} {self.url}"


class EndpointStore:
    """De-duplicated endpoint collection with light indexing."""

    def __init__(self, limit: int = 2000) -> None:
        self.limit = limit
        self._items: dict[str, Endpoint] = {}
        self._by_host: dict[str, list[str]] = {}

    def add(self, endpoint: Endpoint) -> Endpoint | None:
        key = endpoint.key()
        if key in self._items:
            existing = self._items[key]
            for param in endpoint.params:
                existing.add_param(param)
            existing.tags |= endpoint.tags
            return existing
        if len(self._items) >= self.limit:
            return None
        self._items[key] = endpoint
        self._by_host.setdefault(endpoint.host, []).append(key)
        return endpoint

    def extend(self, endpoints: Iterable[Endpoint]) -> int:
        added = 0
        for endpoint in endpoints:
            if self.add(endpoint) is not None:
                added += 1
        return added

    def __iter__(self) -> Iterator[Endpoint]:
        return iter(self._items.values())

    def __len__(self) -> int:
        return len(self._items)

    def for_host(self, host: str) -> list[Endpoint]:
        return [self._items[key] for key in self._by_host.get(host, [])]

    def with_params(self) -> list[Endpoint]:
        return [endpoint for endpoint in self._items.values() if endpoint.parameters()]

    def filter(self, *, method: str | None = None, tag: str | None = None) -> list[Endpoint]:
        result = list(self._items.values())
        if method:
            result = [endpoint for endpoint in result if endpoint.method.upper() == method.upper()]
        if tag:
            result = [endpoint for endpoint in result if tag in endpoint.tags]
        return result

    def to_list(self) -> list[dict[str, Any]]:
        return [endpoint.to_dict() for endpoint in self._items.values()]

    def load(self, payload: Iterable[dict[str, Any]]) -> None:
        for item in payload:
            self.add(Endpoint.from_dict(item))

    @property
    def hosts(self) -> list[str]:
        return sorted(self._by_host)

    def stats(self) -> dict[str, Any]:
        methods: dict[str, int] = {}
        locations: dict[str, int] = {}
        for endpoint in self._items.values():
            methods[endpoint.method] = methods.get(endpoint.method, 0) + 1
            for param in endpoint.params:
                locations[param.location] = locations.get(param.location, 0) + 1
        return {
            "endpoints": len(self._items),
            "hosts": len(self._by_host),
            "methods": methods,
            "parameter_locations": locations,
            "with_parameters": len(self.with_params()),
        }


def params_from_json(payload: Any, prefix: str = "") -> list[Param]:
    """Flatten a JSON sample into leaf parameters."""

    result: list[Param] = []
    if isinstance(payload, dict):
        for key, value in payload.items():
            name = f"{prefix}.{key}" if prefix else str(key)
            if isinstance(value, (dict, list)):
                result.extend(params_from_json(value, name))
            else:
                result.append(Param(name=name, value="" if value is None else str(value), location="json"))
    elif isinstance(payload, list):
        for index, item in enumerate(payload[:3]):
            result.extend(params_from_json(item, f"{prefix}[{index}]"))
    elif prefix:
        result.append(Param(name=prefix, value=str(payload), location="json"))
    return result


def parse_form_fields(html: str, base_url: str) -> list[Endpoint]:
    """Extract HTML forms as endpoints (lightweight, no external parser)."""

    from candix.analysis.html import parse_forms

    endpoints: list[Endpoint] = []
    for form in parse_forms(html, base_url):
        params = [Param(name=item["name"], value=item.get("value", ""), location="body") for item in form["fields"]]
        body = Body(content_type="application/x-www-form-urlencoded", form={item["name"]: item.get("value", "") for item in form["fields"]})
        endpoint = Endpoint(
            url=form["action"],
            method=form["method"].upper(),
            params=params,
            body=body,
            source="form",
            forms=[form],
        )
        endpoints.append(endpoint)
    return endpoints


def dump_body(body: Body) -> str:
    if body.kind == "json":
        try:
            return json.dumps(body.json, separators=(",", ":"))
        except (TypeError, ValueError):
            return body.raw
    if body.kind == "form":
        query = QueryParams(body.form.items())
        return query.render()
    return body.raw


def dedupe_params(params: Iterable[Param]) -> list[Param]:
    seen: dict[str, Param] = {}
    for param in params:
        seen.setdefault(param.key, param)
    return list(seen.values())
