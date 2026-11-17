"""Detector framework.

A detector is a small, focused class with a declarative :class:`DetectorMeta`
and a ``run`` method that yields :class:`Finding` objects. Everything a
detector needs - HTTP access, baselines, evidence capture, remediation text -
is provided by the base class so detectors stay short and auditable.

Detectors must be *fail-safe*: an exception is caught by the engine, logged with
the detector id and does not abort the scan. They must also be *idempotent*:
running twice must not duplicate findings, which the finding set enforces by
de-duplication key.
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, ClassVar, Iterable, Iterator, Sequence

from candix.analysis.baseline import Baseline, BaselineCollector
from candix.analysis.diff import ResponseDiff, compare_responses, looks_like_error_page
from candix.analysis.reflection import Reflection, find_reflection, score_reflection
from candix.core.context import ScanContext, evidence_for
from candix.core.endpoint import Endpoint, Param, dump_body
from candix.core.evidence import Evidence, Exchange
from candix.core.finding import Finding, Remediation, finding_from_probe
from candix.core.ids import marker as new_marker
from candix.core.redact import REDACTED
from candix.core.registry import LazyRegistry
from candix.core.severity import Confidence, Severity
from candix.net.http import Response
from candix.net.url import URL

DETECTOR_PACKAGES = ("candix.detectors",)


@dataclass(frozen=True)
class DetectorMeta:
    id: str
    name: str
    category: str
    description: str
    severity: Severity = Severity.MEDIUM
    cwe: tuple[str, ...] = ()
    owasp: tuple[str, ...] = ()
    intrusive: bool = False
    requires_auth: bool = False
    safe_mode: bool = True
    tags: tuple[str, ...] = ()
    references: tuple[str, ...] = ()
    order: int = 100
    remediation_key: str = ""
    min_profile: str = "safe"

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "category": self.category,
            "description": self.description,
            "severity": self.severity.value,
            "cwe": list(self.cwe),
            "owasp": list(self.owasp),
            "intrusive": self.intrusive,
            "requires_auth": self.requires_auth,
            "tags": list(self.tags),
            "references": list(self.references),
            "min_profile": self.min_profile,
        }


DETECTORS: LazyRegistry[type["BaseDetector"]] = LazyRegistry("detectors", DETECTOR_PACKAGES)


def register_detector(cls: type["BaseDetector"]) -> type["BaseDetector"]:
    DETECTORS.register(cls.meta.id, cls)
    return cls


class BaseDetector(ABC):
    """Base class with request, baseline and evidence helpers."""

    meta: ClassVar[DetectorMeta]
    supports_batching: ClassVar[bool] = False

    def __init__(self, ctx: ScanContext) -> None:
        self.ctx = ctx
        self.http = ctx.http
        self.config = ctx.config
        self.logger = ctx.logger.child(self.meta.id) if hasattr(ctx.logger, "child") else ctx.logger
        self._baselines = BaselineCollector(self.http, samples=1 if self.ctx.options.dry_run else 2)
        self._rng_marker = new_marker
        self.findings: list[Finding] = []

    # ------------------------------------------------------------------
    # lifecycle
    # ------------------------------------------------------------------
    def applicable(self) -> bool:
        if not self.ctx.options.allows_detector(self.meta.id):
            return False
        if not self.ctx.options.allows_category(self.meta.category):
            return False
        if self.meta.intrusive and not self.ctx.options.intrusive:
            return False
        if self.meta.intrusive and not int(self.config.get("detect.intrusive", True)):
            return False
        return True

    @abstractmethod
    def run(self) -> Iterable[Finding]:
        """Yield findings. Must not raise for expected HTTP errors."""

    # ------------------------------------------------------------------
    # target selection
    # ------------------------------------------------------------------
    def endpoints(self, *, with_params: bool = True) -> list[Endpoint]:
        items = list(self.ctx.endpoints)
        scope = self.ctx.scope
        if scope is not None:
            items = [item for item in items if scope.matches(item.url)]
        if with_params:
            items = [item for item in items if item.parameters()]
        limit = int(self.config.get("detect.max_params_per_endpoint", 40))
        for item in items:
            item.params[:] = item.params[:limit]
        return items

    def endpoints_for_urls(self, urls: Iterable[str]) -> list[Endpoint]:
        return [item for item in self.ctx.endpoints if item.url in set(urls)]

    def params_for(self, endpoint: Endpoint) -> list[Param]:
        limit = int(self.config.get("detect.max_params_per_endpoint", 40))
        return endpoint.parameters()[:limit]

    # ------------------------------------------------------------------
    # probing
    # ------------------------------------------------------------------
    def send(
        self,
        endpoint: Endpoint,
        overrides: dict[str, str],
        *,
        method: str | None = None,
        headers: dict[str, str] | None = None,
        body: str | None = None,
        tag: str = "",
    ) -> Response:
        self.ctx.budget.check()
        return self.http.request_endpoint(
            endpoint,
            overrides=overrides,
            method=method,
            headers=headers,
            body_override=body,
            tag=tag or self.meta.id,
        )

    def probe_url(
        self,
        url: str,
        *,
        method: str = "GET",
        param: str | None = None,
        value: str | None = None,
        data: str | None = None,
        headers: dict[str, str] | None = None,
        tag: str = "",
    ) -> Response:
        self.ctx.budget.check()
        return self.http.probe(
            url,
            method=method,
            param=param,
            value=value,
            data=data,
            headers=headers,
            tag=tag or self.meta.id,
        )

    def baseline(
        self,
        endpoint: Endpoint,
        *,
        method: str | None = None,
        body: str | None = None,
        samples: int | None = None,
    ) -> Baseline:
        method = (method or endpoint.method).upper()
        data = body if body is not None else (dump_body(endpoint.body) if endpoint.body else None)
        return self._baselines.collect(
            endpoint.url,
            method=method,
            data=data,
            headers=endpoint.headers or None,
            samples=samples,
        )

    def baseline_url(self, url: str, *, method: str = "GET", data: str | None = None) -> Baseline:
        return self._baselines.collect(url, method=method, data=data)

    def diff(self, baseline: Baseline, response: Response) -> ResponseDiff:
        reference = baseline.responses[-1] if baseline.responses else None
        if reference is None:
            return ResponseDiff(
                attack_status=response.status,
                attack_length=response.size,
            )
        return compare_responses(reference, response)

    # ------------------------------------------------------------------
    # evidence and findings
    # ------------------------------------------------------------------
    def capture(
        self,
        response: Response,
        *,
        summary: str,
        control: Response | None = None,
        notes: str = "",
        kind: str = "http",
        data: dict[str, Any] | None = None,
    ) -> Evidence:
        evidence = evidence_for(response, summary=summary, control=control, notes=notes, kind=kind, data=data)
        return evidence

    def build_finding(
        self,
        *,
        title: str,
        severity: Severity,
        url: str,
        parameter: str = "",
        location: str = "query",
        method: str = "GET",
        description: str = "",
        impact: str = "",
        payload: str = "",
        confidence: Confidence = Confidence.LIKELY,
        confidence_hint: float | None = None,
        cwe: Sequence[str] | None = None,
        owasp: Sequence[str] | None = None,
        references: Sequence[str] | None = None,
        tags: Sequence[str] | None = None,
        evidence: Iterable[Evidence] = (),
        remediation: Remediation | None = None,
        score: float = 0.0,
        vector: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> Finding:
        from candix.catalog.remediation import remediation_for

        remediation = remediation or remediation_for(self.meta.remediation_key or self.meta.category)
        finding = finding_from_probe(
            title=title,
            detector=self.meta.id,
            category=self.meta.category,
            severity=severity,
            url=url,
            method=method,
            parameter=parameter,
            location=location,
            description=description or self.meta.description,
            impact=impact,
            payload=payload,
            cwe=cwe if cwe is not None else self.meta.cwe,
            owasp=owasp if owasp is not None else self.meta.owasp,
            references=[*(references or ()), *self.meta.references],
            remediation=remediation,
            tags=[*(tags or ()), "active" if self.meta.intrusive else "passive"],
            confidence=confidence,
            score=score,
            vector=vector,
            target=self.ctx.primary_target.host,
        )
        finding.verified = confidence is Confidence.CONFIRMED
        finding.metadata.update(metadata or {})
        if confidence_hint is not None:
            finding.metadata["confidence_score"] = round(confidence_hint, 3)
        for item in evidence:
            finding.add_evidence(item)
        return finding

    def emit(self, finding: Finding) -> Finding:
        stored = self.ctx.register_finding(finding)
        self.findings.append(stored)
        if self.logger is not None:
            self.logger.info(
                "finding",
                title=finding.title,
                severity=finding.severity.value,
                url=finding.url,
                parameter=finding.parameter,
            )
        return stored

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------
    def marker(self, prefix: str = "cdx") -> str:
        return self._rng_marker(prefix)

    def reflected(self, response: Response, marker: str, payload: str | None = None) -> Reflection:
        return find_reflection(response.text, marker, payload=payload)

    def reflection_score(self, reflection: Reflection, payload: str) -> float:
        return score_reflection(reflection, payload_has_script="<" in payload or "script" in payload.lower())

    def looks_broken(self, response: Response) -> bool:
        return response.status >= 500 or looks_like_error_page(response.text) or "error" in response.reason.lower()

    def rate_limited(self, response: Response) -> bool:
        return response.status in {429, 503}

    def missing(self, response: Response) -> bool:
        return response.status == 0 or response.error

    def scope_allows(self, url: str) -> bool:
        if self.ctx.scope is None:
            return True
        try:
            return self.ctx.scope.matches(url)
        except Exception:  # pragma: no cover - malformed URL
            return False

    def json_body(self, response: Response) -> Any:
        return response.try_json()

    def payload_budget(self) -> int:
        return int(self.config.get("detect.max_payloads_per_param", 12))

    def load_payloads(self, name: str, *, limit: int | None = None) -> list[str]:
        from candix.catalog.payloads import get_payloads

        payloads = get_payloads(name)
        if limit is not None:
            return payloads[:limit]
        return payloads[: self.payload_budget()]

    def truncate(self, text: str, limit: int = 400) -> str:
        value = (text or "").strip()
        if len(value) <= limit:
            return value
        return value[:limit] + "..."

    def redact(self, text: str) -> str:
        return self.ctx.registry_secrets.apply(text)

    def request_timeout(self) -> float:
        return float(self.config.get("http.timeout", 10.0))

    def time_based_enabled(self) -> bool:
        return bool(self.config.get("detect.time_based", True))

    def safe_mode(self) -> bool:
        return bool(self.config.get("detect.safe_mode", True))

    def auth_headers(self) -> dict[str, str]:
        target = self.ctx.primary_target
        return dict(target.headers)

    # ------------------------------------------------------------------
    def __repr__(self) -> str:  # pragma: no cover - display helper
        return f"<{self.__class__.__name__} id={self.meta.id}>"


def detector_catalog() -> list[dict[str, Any]]:
    return [cls.meta.to_dict() for cls in DETECTORS.values()]


def select_detectors(
    ctx: ScanContext,
    *,
    only: Iterable[str] = (),
    categories: Iterable[str] = (),
    include_intrusive: bool = True,
) -> list[type[BaseDetector]]:
    """Return detector classes applicable to a context, ordered for execution."""

    only_set = set(only)
    category_set = {item.lower() for item in categories}
    selected: list[type[BaseDetector]] = []
    for detector_id in DETECTORS.keys():
        cls = DETECTORS.get(detector_id)
        if cls is None:
            continue
        meta = cls.meta
        if only_set and meta.id not in only_set:
            continue
        if category_set and meta.category.lower() not in category_set:
            continue
        if meta.intrusive and not include_intrusive:
            continue
        selected.append(cls)
    selected.sort(key=lambda item: (item.meta.order, item.meta.id))
    return selected


def summarize_detectors() -> dict[str, Any]:
    categories: dict[str, int] = {}
    intrusive = 0
    for cls in DETECTORS.values():
        categories[cls.meta.category] = categories.get(cls.meta.category, 0) + 1
        intrusive += 1 if cls.meta.intrusive else 0
    return {"total": len(DETECTORS), "intrusive": intrusive, "categories": categories}
