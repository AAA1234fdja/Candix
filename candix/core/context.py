"""Scan context: the object every phase and detector receives.

The context is deliberately explicit rather than a bag of globals: a detector
can only reach the HTTP client, the scope, the configuration and the evidence
store through it, which keeps tests hermetic and makes the execution trace
reproducible.
"""

from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from candix.core.budget import Budget, BudgetLimits
from candix.core.clock import isoformat, utcnow
from candix.core.config import Config
from candix.core.endpoint import Endpoint, EndpointStore
from candix.core.evidence import Evidence, EvidenceStore, Exchange
from candix.core.finding import Finding, FindingSet
from candix.core.ids import scan_id
from candix.core.log import Logger, get_logger
from candix.core.redact import RedactionPolicy, SecretRegistry
from candix.core.scope import Engagement, Scope
from candix.core.severity import Confidence, Severity
from candix.net.http import HttpClient, Response
from candix.net.ratelimit import HostRateLimiter
from candix.net.url import URL


@dataclass
class ScanOptions:
    """Per-run overrides supplied by the CLI."""

    categories: list[str] = field(default_factory=list)
    exclude_categories: list[str] = field(default_factory=list)
    detectors: list[str] = field(default_factory=list)
    exclude_detectors: list[str] = field(default_factory=list)
    min_severity: Severity = Severity.INFO
    min_confidence: Confidence = Confidence.POSSIBLE
    max_endpoints: int = 2000
    intrusive: bool = True
    exploit: bool = False
    dry_run: bool = False
    resume_from: str = ""
    verbose: bool = False
    no_evidence: bool = False
    headless: bool = True

    def allows_category(self, category: str) -> bool:
        if self.categories and category.lower() not in {item.lower() for item in self.categories}:
            return False
        if category.lower() in {item.lower() for item in self.exclude_categories}:
            return False
        return True

    def allows_detector(self, detector_id: str) -> bool:
        if self.detectors and detector_id not in self.detectors:
            return False
        if detector_id in self.exclude_detectors:
            return False
        return True

    def to_dict(self) -> dict[str, Any]:
        return {
            "categories": list(self.categories),
            "exclude_categories": list(self.exclude_categories),
            "detectors": list(self.detectors),
            "exclude_detectors": list(self.exclude_detectors),
            "min_severity": self.min_severity.value,
            "min_confidence": self.min_confidence.value,
            "max_endpoints": self.max_endpoints,
            "intrusive": self.intrusive,
            "exploit": self.exploit,
            "dry_run": self.dry_run,
            "no_evidence": self.no_evidence,
        }


@dataclass
class Target:
    """A single asset under test."""

    url: str
    label: str = ""
    auth_context: str = "anonymous"
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def parsed(self) -> URL:
        return URL.parse(self.url)

    @property
    def host(self) -> str:
        return self.parsed.host

    @property
    def origin(self) -> str:
        return self.parsed.origin

    @property
    def base_url(self) -> str:
        parsed = self.parsed
        return f"{parsed.scheme}://{parsed.netloc}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "label": self.label,
            "auth_context": self.auth_context,
            "cookies": sorted(self.cookies),
            "metadata": self.metadata,
        }


class ScanContext:
    """Shared state for one scan."""

    def __init__(
        self,
        targets: Iterable[Target | str],
        *,
        config: Config | None = None,
        engagement: Engagement | None = None,
        options: ScanOptions | None = None,
        artifacts_dir: str | Path | None = None,
        logger: Logger | None = None,
        http: HttpClient | None = None,
        scope: Scope | None = None,
    ) -> None:
        self.id = scan_id()
        self.started_at = isoformat()
        self.started_monotonic = time.monotonic()
        self.config = config or Config()
        self.engagement = engagement
        self.scope = scope or (engagement.scope if engagement else None)
        self.options = options or ScanOptions()
        self.logger = logger or get_logger("candix.scan")
        self.targets = [Target(url=item) if isinstance(item, str) else item for item in targets]
        self.findings = FindingSet()
        self.endpoints = EndpointStore(limit=max(100, int(self.config.get("scan.max_endpoints", 2000))))
        self.registry_secrets = SecretRegistry(RedactionPolicy.parse(str(self.config.get("evidence.redaction", "standard"))))
        self.policy = self.registry_secrets.policy
        self.artifacts_dir = Path(artifacts_dir or self._default_artifacts())
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)
        self.budget = Budget(
            BudgetLimits.from_config(self.config),
            kill_switch=self.config.get("safety.kill_switch_file", "") or None,
        )
        self.limiter = HostRateLimiter(
            float(self.config.get("scan.max_rps", 5.0)),
            int(self.config.get("scan.burst", 5)),
        )
        self.http = http or HttpClient(
            self.config,
            scope=self.scope,
            budget=self.budget,
            limiter=self.limiter,
            logger=self.logger.child("http"),
            registry=self.registry_secrets,
        )
        if self.options.no_evidence or not self.config.get("evidence.enabled", True):
            from candix.core.evidence import NullEvidenceStore

            self.evidence = NullEvidenceStore()
        else:
            self.evidence = EvidenceStore(
                self.artifacts_dir / str(self.config.get("evidence.dir", "evidence")),
                policy=self.policy,
                registry=self.registry_secrets,
            )
        self.stats: dict[str, Any] = {
            "detectors_run": 0,
            "detectors_skipped": 0,
            "detectors_failed": 0,
            "endpoints_crawled": 0,
            "verifications": 0,
            "exploits_attempted": 0,
            "exploits_succeeded": 0,
        }
        self.warnings: list[str] = []
        self.notes: list[str] = []
        self.phase = "init"
        self.phase_times: dict[str, float] = {}
        self.report_paths: dict[str, str] = {}
        self.lab_mode = self.config.get("profile") == "lab"
        self._listeners: list[Any] = []
        self._finding_lock = threading.RLock()
        self._evidence_lock = threading.RLock()

    # ------------------------------------------------------------------
    def _default_artifacts(self) -> str:
        base = Path(os.environ.get("CANDIX_HOME", Path.cwd()))
        return str(base / ".candix" / "runs" / self.id)

    # ------------------------------------------------------------------
    @property
    def elapsed(self) -> float:
        return time.monotonic() - self.started_monotonic

    @property
    def primary_target(self) -> Target:
        return self.targets[0]

    @property
    def base_url(self) -> str:
        return self.primary_target.base_url

    def warn(self, message: str) -> None:
        self.warnings.append(message)
        self.logger.warning(message)

    def note(self, message: str) -> None:
        self.notes.append(message)

    def add_listener(self, listener: Any) -> None:
        self._listeners.append(listener)

    def emit(self, event: str, payload: dict[str, Any]) -> None:
        for listener in self._listeners:
            try:
                listener(event, payload)
            except Exception:  # pragma: no cover - listeners must not break scans
                continue

    # ------------------------------------------------------------------
    def register_finding(self, finding: Finding) -> Finding:
        with self._finding_lock:
            return self._register_finding_locked(finding)

    def _register_finding_locked(self, finding: Finding) -> Finding:
        existing = self.findings.add(finding)
        self.budget.record_finding()
        if existing is finding:
            for item in finding.evidence:
                try:
                    stored = self.evidence.add(finding.id, item)
                    item.path = stored.path
                    item.sha256 = stored.sha256
                except Exception as exc:  # pragma: no cover - disk issues
                    self.logger.warning("could not persist evidence", error=str(exc))
            self.emit("finding", finding.to_dict(include_evidence=False))
        return existing

    def attach_evidence(self, finding: Finding, evidence: Evidence) -> None:
        with self._evidence_lock:
            stored = self.evidence.add(finding.id, evidence)
        evidence.path = stored.path
        evidence.sha256 = stored.sha256
        finding.add_evidence(evidence)

    def record_phase(self, phase: str) -> None:
        now = time.monotonic()
        if self.phase != phase:
            self.phase_times.setdefault(self.phase, 0.0)
        self.phase_times[phase] = self.phase_times.get(phase, 0.0) + 0.0
        self.phase = phase
        self.emit("phase", {"phase": phase, "timestamp": now})

    # ------------------------------------------------------------------
    def probe(
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
        return self.http.probe(url, param=param, value=value, method=method, data=data, headers=headers, tag=tag)

    def add_endpoint(self, endpoint: Endpoint) -> Endpoint | None:
        added = self.endpoints.add(endpoint)
        if added is not None:
            self.stats["endpoints_crawled"] = len(self.endpoints)
        return added

    # ------------------------------------------------------------------
    def summary(self) -> dict[str, Any]:
        return {
            "scan_id": self.id,
            "started_at": self.started_at,
            "finished_at": isoformat(),
            "elapsed_seconds": round(self.elapsed, 3),
            "profile": self.config.get("profile"),
            "targets": [target.to_dict() for target in self.targets],
            "engagement": self.engagement.summary() if self.engagement else None,
            "options": self.options.to_dict(),
            "stats": dict(self.stats),
            "findings": self.findings.counts(),
            "risk_score": self.findings.risk_score,
            "warnings": list(self.warnings),
            "notes": list(self.notes),
            "budget": self.budget.snapshot(),
            "http": self.http.snapshot(),
            "endpoint_stats": self.endpoints.stats(),
            "phases": {key: round(value, 3) for key, value in self.phase_times.items()},
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "summary": self.summary(),
            "findings": self.findings.to_list(include_evidence=False),
        }

    def close(self) -> None:
        try:
            self.http.close()
        except Exception:  # pragma: no cover
            pass

    def __enter__(self) -> "ScanContext":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # ------------------------------------------------------------------
    @classmethod
    def create(
        cls,
        targets: Iterable[str],
        *,
        config: Config | None = None,
        engagement: Engagement | None = None,
        options: ScanOptions | None = None,
        artifacts_dir: str | Path | None = None,
        logger: Logger | None = None,
    ) -> "ScanContext":
        target_list = [Target(url=item) for item in targets]
        if engagement is not None:
            for target in target_list:
                engagement.guard_url(target.url, "GET")
        return cls(
            target_list,
            config=config,
            engagement=engagement,
            options=options,
            artifacts_dir=artifacts_dir,
            logger=logger,
        )


def exchange_from(response: Response) -> Exchange:
    return Exchange(
        method=response.method,
        url=response.url,
        request_headers=dict(response.request_headers),
        request_body=response.request_body,
        status=response.status,
        reason=response.reason,
        response_headers=response.headers.to_dict(),
        response_body=response.text,
        elapsed=response.elapsed,
        error=response.error,
        http_version=response.http_version,
    )


def evidence_for(
    response: Response,
    *,
    summary: str,
    kind: str = "http",
    control: Response | None = None,
    notes: str = "",
    data: dict[str, Any] | None = None,
) -> Evidence:
    return Evidence(
        kind=kind,
        summary=summary,
        exchange=exchange_from(response),
        control=exchange_from(control) if control else None,
        notes=notes,
        data=data or {},
    )


def utc_stamp() -> str:
    return isoformat(utcnow())
