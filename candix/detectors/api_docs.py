"""Exposed API documentation and specification files."""

from __future__ import annotations

import json
from typing import Any, Iterable

from candix.core.finding import Finding
from candix.core.severity import Confidence, Severity
from candix.detectors.base import BaseDetector, DetectorMeta, register_detector
from candix.net.url import join_url

_CANDIDATES = (
    "/swagger.json",
    "/openapi.json",
    "/api-docs",
    "/v2/api-docs",
    "/v3/api-docs",
    "/swagger/v1/swagger.json",
    "/swagger-ui.html",
    "/swagger-ui/index.html",
    "/docs",
    "/redoc",
    "/api/swagger.json",
)


@register_detector
class ApiDocsDetector(BaseDetector):
    meta = DetectorMeta(
        id="apidocs",
        name="Exposed API specification",
        category="apidocs",
        description="Looks for Swagger/OpenAPI documents and reports the operations they reveal.",
        severity=Severity.MEDIUM,
        cwe=("CWE-200", "CWE-1059"),
        owasp=("A05:2021 Security Misconfiguration",),
        intrusive=False,
        tags=("exposure", "api"),
        order=45,
        remediation_key="debug",
    )

    def run(self) -> Iterable[Finding]:
        seen: set[str] = set()
        for target in self.ctx.targets:
            for path in _CANDIDATES:
                finding = self._test(target.base_url, path)
                if finding is None:
                    continue
                key = str(finding.metadata.get("title", ""))
                if key in seen:
                    continue
                seen.add(key)
                yield self.emit(finding)

    def _test(self, base_url: str, path: str) -> Finding | None:
        url = join_url(base_url, path).render()
        if self.ctx.scope is not None and not self.ctx.scope.matches(url):
            return None
        try:
            response = self.http.get(url, tag="apidocs")
        except Exception:
            return None
        if self.missing(response) or response.status != 200:
            return None
        document = self.json_body(response)
        operations: list[str] = []
        title = ""
        if isinstance(document, dict):
            paths = document.get("paths") or {}
            if isinstance(paths, dict):
                for route, methods in list(paths.items())[:40]:
                    if isinstance(methods, dict):
                        names = [name.upper() for name in methods if name.lower() in {"get", "post", "put", "patch", "delete"}]
                        operations.append(f"{'/'.join(names) or 'ANY'} {route}")
            info = document.get("info") or {}
            if isinstance(info, dict):
                title = str(info.get("title", ""))
        if not operations:
            lowered = response.text.lower()
            if "swagger" not in lowered and "openapi" not in lowered:
                return None
            if "<html" in lowered and "swagger-ui" not in lowered:
                return None
        severity = Severity.MEDIUM if operations else Severity.LOW
        shown = operations[:8]
        return self.build_finding(
            title="API specification is publicly readable",
            severity=severity,
            url=url,
            method="GET",
            description=(
                f"The specification is served without authentication"
                + (f" ({title})" if title else "")
                + (f" and documents {len(operations)} operation(s): " + ", ".join(shown) if operations else ".")
            ),
            impact=(
                "Unauthenticated documentation maps the entire attack surface, including internal "
                "and administrative operations that are otherwise hard to discover."
            ),
            payload=path,
            confidence=Confidence.CONFIRMED if operations else Confidence.LIKELY,
            cwe=("CWE-200",),
            tags=("exposure", "api"),
            evidence=[self.capture(response, summary="API specification served without authentication")],
            metadata={"path": path, "operations": operations[:40], "title": title},
        )


def _dump_operations(document: Any) -> list[str]:
    if not isinstance(document, dict):
        return []
    paths = document.get("paths") or {}
    result: list[str] = []
    for route, methods in paths.items():
        if isinstance(methods, dict):
            for method in methods:
                result.append(f"{method.upper()} {route}")
    return result


def parse_spec(text: str) -> dict[str, Any]:
    try:
        document = json.loads(text)
    except json.JSONDecodeError:
        return {}
    operations = _dump_operations(document)
    return {"operations": operations, "count": len(operations), "version": str(document.get("openapi") or document.get("swagger") or "")}
