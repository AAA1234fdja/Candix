"""GraphQL endpoint exposure and introspection."""

from __future__ import annotations

import json
from typing import Iterable

from candix.core.finding import Finding
from candix.core.severity import Confidence, Severity
from candix.detectors.base import BaseDetector, DetectorMeta, register_detector
from candix.net.url import join_url

_PATHS = ("/graphql", "/graphiql", "/api/graphql", "/v1/graphql", "/query", "/api/query", "/gql")
_INTROSPECTION = "query IntrospectionQuery { __schema { queryType { name } mutationType { name } types { name kind } } }"


@register_detector
class GraphqlDetector(BaseDetector):
    meta = DetectorMeta(
        id="graphql",
        name="GraphQL introspection and schema exposure",
        category="graphql",
        description="Locates GraphQL endpoints, runs an introspection query and checks whether the schema is publicly disclosed.",
        severity=Severity.MEDIUM,
        cwe=("CWE-200", "CWE-284"),
        owasp=("A05:2021 Security Misconfiguration",),
        intrusive=False,
        tags=("api", "graphql"),
        order=125,
        remediation_key="graphql",
    )

    def run(self) -> Iterable[Finding]:
        candidates: set[str] = set()
        for endpoint in self.ctx.endpoints:
            if "graphql" in endpoint.url.lower() or "graphiql" in endpoint.url.lower():
                candidates.add(endpoint.url)
        for target in self.ctx.targets:
            for path in _PATHS:
                try:
                    candidates.add(join_url(target.base_url, path).render())
                except ValueError:
                    continue
        for url in candidates:
            if self.ctx.scope is not None and not self.ctx.scope.matches(url):
                continue
            finding = self._probe(url)
            if finding is not None:
                yield self.emit(finding)

    def _probe(self, url: str) -> Finding | None:
        payloads = [
            {"query": _INTROSPECTION},
            {"query": "{__typename}"},
            {"query": "{ __schema { types { name } } }"},
        ]
        for body in payloads:
            try:
                response = self.http.post(url, json_body=body, tag="graphql")
            except Exception:
                return None
            if self.missing(response):
                return None
            if response.status >= 400 and response.status not in {400}:
                continue
            data = response.try_json()
            if not isinstance(data, dict):
                if response.status == 200 and "graphql" in response.text.lower():
                    return None
                continue
            schema = data.get("data", {}).get("__schema") if isinstance(data.get("data"), dict) else None
            if not schema:
                continue
            types = schema.get("types", []) if isinstance(schema, dict) else []
            type_names = [item.get("name") for item in types if isinstance(item, dict)]
            return self.build_finding(
                title="GraphQL introspection enabled",
                severity=Severity.LOW,
                url=url,
                method="POST",
                location="body",
                description=(
                    "The GraphQL endpoint answers introspection queries, disclosing the full schema"
                    + (f" ({len(type_names)} types including {', '.join(name for name in type_names[:5] if name)})." if type_names else ".")
                ),
                impact="Attackers can map every query, mutation and field, which removes most of the effort from API abuse.",
                payload=_INTROSPECTION[:200],
                confidence=Confidence.CONFIRMED,
                cwe=("CWE-200",),
                tags=("graphql", "api"),
                evidence=[self.capture(response, summary="Introspection response returned the schema")],
                metadata={"types": type_names[:50], "query_type": schema.get("queryType")},
            )
        return None
