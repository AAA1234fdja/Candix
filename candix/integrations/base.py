"""Integration framework.

Every integration shares the same lifecycle: build a payload from a report,
send it, and return a structured result. Sending is disabled unless an endpoint
and credential are configured, so importing this package never contacts a third
party during a scan.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Mapping

from candix import VERSION


class IntegrationError(Exception):
    """Raised when an integration cannot deliver its payload."""


@dataclass
class Notification:
    """Provider-neutral description of what should be sent."""

    title: str
    body: str
    severity: str = "info"
    summary: dict[str, Any] = field(default_factory=dict)
    findings: list[dict[str, Any]] = field(default_factory=list)
    proofs: list[dict[str, Any]] = field(default_factory=list)
    link: str = ""
    tags: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_report(cls, payload: Mapping[str, Any], *, link: str = "", limit: int = 25) -> "Notification":
        summary = dict(payload.get("summary") or {})
        findings = list(payload.get("findings") or [])[:limit]
        counts = summary.get("counts") or {}
        worst = next((severity for severity in ("critical", "high", "medium", "low") if counts.get(severity)), "info")
        title = f"[{worst.upper()}] {summary.get('title') or 'Candix assessment'} — {counts.get('total', len(findings))} findings"
        lines = [
            f"Scan {summary.get('scan_id', '')} finished in {summary.get('duration_human', '')}.",
            f"Findings: {counts.get('critical', 0)} critical, {counts.get('high', 0)} high, "
            f"{counts.get('medium', 0)} medium, {counts.get('low', 0)} low.",
            f"Verified: {summary.get('verified', 0)} · exploited: {summary.get('exploited', 0)} · "
            f"risk score {summary.get('risk_score', 0)}.",
            "",
        ]
        for finding in findings[:10]:
            severity = finding.get("severity", "info")
            lines.append(f"- {str(severity).upper()} · {finding.get('title')} · {finding.get('url')}")
        return cls(
            title=title[:240],
            body="\n".join(lines),
            severity=worst,
            summary=summary,
            findings=findings,
            proofs=list(payload.get("proofs") or [])[:10],
            link=link,
            tags=["candix", "security", worst],
            metadata={"generator": f"candix/{VERSION}", "scan_id": summary.get("scan_id", "")},
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "body": self.body,
            "severity": self.severity,
            "summary": self.summary,
            "findings": self.findings,
            "proofs": self.proofs,
            "link": self.link,
            "tags": self.tags,
            "metadata": self.metadata,
        }


@dataclass
class IntegrationResult:
    integration: str
    ok: bool
    status: int = 0
    reference: str = ""
    message: str = ""
    attempts: int = 1
    payload: dict[str, Any] = field(default_factory=dict)
    elapsed: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "integration": self.integration,
            "ok": self.ok,
            "status": self.status,
            "reference": self.reference,
            "message": self.message,
            "attempts": self.attempts,
            "payload": self.payload,
            "elapsed": round(self.elapsed, 3),
        }


class Integration(ABC):
    """Base class for delivery targets."""

    name: str = "integration"
    requires_network: bool = True

    def __init__(
        self,
        *,
        endpoint: str = "",
        token: str = "",
        secret: str = "",
        project: str = "",
        dry_run: bool = True,
        timeout: float = 10.0,
        retries: int = 2,
        headers: Mapping[str, str] | None = None,
        logger: Any = None,
    ) -> None:
        self.endpoint = endpoint
        self.token = token
        self.secret = secret
        self.project = project
        self.dry_run = dry_run or not endpoint
        self.timeout = timeout
        self.retries = max(0, retries)
        self.headers = dict(headers or {})
        self.logger = logger

    # ------------------------------------------------------------------
    @property
    def configured(self) -> bool:
        return bool(self.endpoint)

    @abstractmethod
    def build_payload(self, notification: Notification) -> dict[str, Any]:
        """Return the provider-specific JSON body."""

    def target_url(self) -> str:
        return self.endpoint

    def request_headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json", "User-Agent": f"candix/{VERSION}"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        headers.update(self.headers)
        return headers

    def signature(self, body: bytes) -> str:
        if not self.secret:
            return ""
        return hmac.new(self.secret.encode("utf-8"), body, hashlib.sha256).hexdigest()

    def reference_from(self, response: Mapping[str, Any], status: int) -> str:
        for key in ("id", "key", "number", "html_url", "url", "self"):
            if key in response:
                return str(response[key])
        return f"http-{status}"

    # ------------------------------------------------------------------
    def send(self, notification: Notification) -> IntegrationResult:
        payload = self.build_payload(notification)
        body = json.dumps(payload, default=str).encode("utf-8")
        if self.dry_run:
            return IntegrationResult(
                integration=self.name,
                ok=True,
                status=0,
                reference="dry-run",
                message="dry run: payload built but not sent",
                payload=payload,
            )
        started = time.monotonic()
        last_error = ""
        for attempt in range(1, self.retries + 2):
            try:
                response, status = self._post(self.target_url(), body)
                reference = self.reference_from(response, status)
                return IntegrationResult(
                    integration=self.name,
                    ok=200 <= status < 300,
                    status=status,
                    reference=reference,
                    message="" if 200 <= status < 300 else f"unexpected status {status}",
                    attempts=attempt,
                    payload=payload,
                    elapsed=time.monotonic() - started,
                )
            except urllib.error.HTTPError as exc:
                detail = _read_error(exc)
                last_error = f"HTTP {exc.code}: {detail}"
                if exc.code < 500 and exc.code != 429:
                    break
            except (urllib.error.URLError, TimeoutError, OSError) as exc:
                last_error = f"network error: {exc}"
            if attempt <= self.retries:
                time.sleep(min(4.0, 0.5 * (2 ** (attempt - 1))))
        return IntegrationResult(
            integration=self.name,
            ok=False,
            message=last_error or "delivery failed",
            attempts=self.retries + 1,
            payload=payload,
            elapsed=time.monotonic() - started,
        )

    def _post(self, url: str, body: bytes) -> tuple[dict[str, Any], int]:
        request = urllib.request.Request(url, data=body, method="POST", headers=self.request_headers())
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as handle:
                raw = handle.read(65536)
                status = handle.status
        except urllib.error.HTTPError as exc:
            raise
        parsed: dict[str, Any] = {}
        if raw:
            try:
                decoded = json.loads(raw.decode("utf-8", "replace"))
                parsed = decoded if isinstance(decoded, dict) else {"data": decoded}
            except json.JSONDecodeError:
                parsed = {"raw": raw.decode("utf-8", "replace")[:500]}
        return parsed, status


def _read_error(exc: urllib.error.HTTPError) -> str:
    try:
        body = exc.read(4096).decode("utf-8", "replace")
    except Exception:
        return exc.reason or "no detail"
    try:
        document = json.loads(body)
    except json.JSONDecodeError:
        return body[:300]
    for key in ("message", "error", "detail", "errors"):
        if key in document:
            value = document[key]
            return str(value)[:300]
    return body[:300]


_REGISTRY: dict[str, Callable[..., Integration]] = {}


def register(name: str) -> Callable[[type[Integration]], type[Integration]]:
    def decorator(cls: type[Integration]) -> type[Integration]:
        cls.name = name
        _REGISTRY[name] = cls
        return cls

    return decorator


def available() -> list[str]:
    return sorted(_REGISTRY)


def build(name: str, **options: Any) -> Integration:
    if name not in _REGISTRY:
        raise IntegrationError(f"unknown integration: {name}", available=", ".join(available()))
    return _REGISTRY[name](**options)


def build_many(config: Mapping[str, Any], *, logger: Any = None) -> list[Integration]:
    integrations: list[Integration] = []
    for name, options in (config or {}).items():
        if not isinstance(options, Mapping):
            continue
        integrations.append(build(name, logger=logger, **dict(options)))
    return integrations


def dispatch(integrations: Iterable[Integration], notification: Notification) -> list[IntegrationResult]:
    results: list[IntegrationResult] = []
    for integration in integrations:
        try:
            results.append(integration.send(notification))
        except Exception as exc:
            results.append(IntegrationResult(integration=integration.name, ok=False, message=str(exc)))
    return results


def load_plugins() -> list[str]:
    """Import optional integration modules so decorators register them."""

    import importlib
    import pkgutil

    import candix.integrations as package

    loaded: list[str] = []
    for module in pkgutil.iter_modules(package.__path__):
        if module.name.startswith("_") or module.name == "base":
            continue
        try:
            importlib.import_module(f"candix.integrations.{module.name}")
            loaded.append(module.name)
        except Exception:
            continue
    return loaded
