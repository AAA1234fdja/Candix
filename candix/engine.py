"""Scan orchestration.

The engine runs four phases in order and treats each as fail-soft:

``preflight``   validate scope, reachability and configuration
``recon``       crawl, discover paths, fingerprint the stack, detect a WAF
``detect``      run every applicable detector in a bounded worker pool
``exploit``     prove verified findings (only when the engagement allows it)

A stop signal (budget, kill switch, operator interrupt) stops new work but the
engine still returns whatever was collected so a partial report can be written.
"""

from __future__ import annotations

import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable

from candix.core.context import ScanContext, Target
from candix.core.finding import Finding, FindingSet
from candix.core.log import Progress
from candix.core.severity import Severity
from candix.detectors.base import BaseDetector, DETECTORS, select_detectors, summarize_detectors
from candix.recon.crawler import CrawlResult, Crawler
from candix.recon.discovery import DiscoveredPath, PathDiscovery
from candix.recon.tech import TechnologyFingerprint, fingerprint_response
from candix.recon.waf import WafDetection, probe_waf

DETECTOR_TIMEOUT = 600.0


@dataclass
class PhaseResult:
    name: str
    started: float
    finished: float = 0.0
    ok: bool = True
    error: str = ""
    details: dict[str, Any] = field(default_factory=dict)

    @property
    def duration(self) -> float:
        return (self.finished or time.monotonic()) - self.started


@dataclass
class ScanResult:
    context: ScanContext
    phases: list[PhaseResult] = field(default_factory=list)
    crawl: CrawlResult | None = None
    discovery: list[DiscoveredPath] = field(default_factory=list)
    fingerprint: TechnologyFingerprint | None = None
    waf: WafDetection | None = None
    exploited: list[Finding] = field(default_factory=list)
    interrupted: bool = False
    started_at: str = ""
    finished_at: str = ""

    @property
    def findings(self) -> FindingSet:
        return self.context.findings

    @property
    def duration(self) -> float:
        return self.context.elapsed

    def summary(self) -> dict[str, Any]:
        return {
            **self.context.summary(),
            "phases": [
                {
                    "name": phase.name,
                    "duration": round(phase.duration, 3),
                    "ok": phase.ok,
                    "error": phase.error,
                    "details": phase.details,
                }
                for phase in self.phases
            ],
            "crawl": self.crawl.summary() if self.crawl else None,
            "discovery": {
                "paths_found": len(self.discovery),
                "interesting": len([item for item in self.discovery if item.reasons]),
            },
            "technologies": self.fingerprint.to_dict() if self.fingerprint else None,
            "waf": self.waf.to_dict() if self.waf else None,
            "exploited": len(self.exploited),
        }

    def top_findings(self, limit: int = 20) -> list[Finding]:
        return self.findings.sorted()[:limit]


class ScanEngine:
    def __init__(
        self,
        context: ScanContext,
        *,
        crawl: bool = True,
        discover: bool = True,
        exploit: bool = False,
        detect: bool = True,
        on_progress: Callable[[str, dict[str, Any]], None] | None = None,
    ) -> None:
        self.ctx = context
        self.do_crawl = crawl
        self.do_discover = discover
        self.do_exploit = exploit
        self.do_detect = detect
        self.on_progress = on_progress
        self.result = ScanResult(context=context)
        self._stop = threading.Event()
        self.ctx.budget.add_listener(lambda reason: self.stop(reason))
        self.ctx.add_listener(self._forward_context_event)

    def _forward_context_event(self, event: str, payload: dict[str, Any]) -> None:
        """Relay finding-level events to the progress callback (TUI/CLI consumers)."""

        if self.on_progress is None or event not in {"finding", "evidence"}:
            return
        try:
            self.on_progress(event, payload)
        except Exception:  # pragma: no cover - progress callbacks are advisory
            pass

    # ------------------------------------------------------------------
    def stop(self, reason: str = "operator interrupt") -> None:
        self._stop.set()
        self.ctx.logger.warning("stop requested", reason=reason)

    @property
    def stopped(self) -> bool:
        return self._stop.is_set() or self.ctx.budget.stopped

    # ------------------------------------------------------------------
    def run(self) -> ScanResult:
        self.result.started_at = self.ctx.started_at
        self.ctx.logger.info(
            "scan starting",
            scan_id=self.ctx.id,
            targets=len(self.ctx.targets),
            profile=self.ctx.config.get("profile"),
            detectors=len(DETECTORS),
        )
        self._phase("preflight", self._preflight)
        if not self.stopped:
            self._phase("recon", self._recon)
        if not self.stopped and self.do_detect:
            self._phase("detect", self._detect)
        if not self.stopped and self.do_exploit:
            self._phase("exploit", self._exploit)
        self.result.finished_at = ""
        self.ctx.logger.info(
            "scan finished",
            findings=len(self.ctx.findings),
            severity=self.ctx.findings.counts(),
            elapsed=round(self.ctx.elapsed, 2),
            stopped=self.stopped,
        )
        self._notify("scan_finished", self.result.summary())
        return self.result

    # ------------------------------------------------------------------
    def _phase(self, name: str, function: Callable[[], dict[str, Any]]) -> None:
        phase = PhaseResult(name=name, started=time.monotonic())
        self.ctx.record_phase(name)
        self._notify("phase_started", {"phase": name})
        try:
            details = function() or {}
            phase.details = details
        except Exception as exc:
            phase.ok = False
            phase.error = str(exc)
            self.ctx.logger.exception(f"phase failed: {name}")
            self.ctx.warn(f"phase {name} failed: {exc}")
        finally:
            phase.finished = time.monotonic()
            self.ctx.phase_times[name] = round(phase.duration, 3)
            self.result.phases.append(phase)
            self._notify("phase_finished", {"phase": name, "duration": phase.duration, "ok": phase.ok})

    # ------------------------------------------------------------------
    def _preflight(self) -> dict[str, Any]:
        if not self.ctx.targets:
            raise ValueError("no targets supplied")
        for target in self.ctx.targets:
            if self.ctx.scope is not None:
                self.ctx.scope.assert_url(target.url, "GET")
        reachable = 0
        for target in self.ctx.targets:
            try:
                response = self.ctx.http.get(target.url, tag="preflight", allow_redirects=True)
            except Exception as exc:
                self.ctx.warn(f"target unreachable: {target.url}: {exc}")
                continue
            if response.error:
                self.ctx.warn(f"target unreachable: {target.url}: {response.error}")
                continue
            reachable += 1
            fingerprint = fingerprint_response(response)
            if self.result.fingerprint is None:
                self.result.fingerprint = fingerprint
            else:
                for technology in fingerprint.technologies:
                    self.result.fingerprint.add(technology)
            try:
                probe = self.ctx.http.get(
                    target.url,
                    headers={"X-Candix-Probe": "<svg/onload=alert(1)>"},
                    tag="preflight-waf",
                )
                detection = probe_waf(response, probe)
            except Exception:
                detection = probe_waf(response, None)
            self.result.waf = detection
            if detection.detected:
                self.ctx.logger.info(
                    "WAF detected",
                    vendor=detection.vendor,
                    confidence=detection.confidence,
                )
        if reachable == 0:
            raise RuntimeError("no target responded; check connectivity and scope")
        return {
            "reachable": reachable,
            "technologies": self.result.fingerprint.names() if self.result.fingerprint else [],
            "waf": self.result.waf.vendor if self.result.waf else "",
            "detectors": summarize_detectors(),
        }

    # ------------------------------------------------------------------
    def _recon(self) -> dict[str, Any]:
        if self.ctx.config.get("recon.enabled", True) and self.do_crawl:
            crawler = Crawler(self.ctx)
            self.result.crawl = crawler.crawl()
            self.ctx.stats["endpoints_crawled"] = len(self.ctx.endpoints)
            self._notify("crawl_finished", self.result.crawl.summary())
            self.ctx.logger.info("crawl complete", **self.result.crawl.summary())
        if self.do_discover and self.ctx.config.get("recon.discovery", True):
            discovery = PathDiscovery(self.ctx)
            self.result.discovery = discovery.run()
            interesting = [item for item in self.result.discovery if item.reasons]
            self.ctx.logger.info(
                "discovery complete",
                found=len(self.result.discovery),
                interesting=len(interesting),
            )
            self._notify(
                "discovery_finished",
                {"found": len(self.result.discovery), "interesting": len(interesting)},
            )
        for target in self.ctx.targets:
            if not any(endpoint.host == target.host for endpoint in self.ctx.endpoints):
                from candix.core.endpoint import Endpoint

                self.ctx.add_endpoint(Endpoint(url=target.url, method="GET", source="target"))
        if self.ctx.options.max_endpoints:
            # EndpointStore already enforces the limit; record the truncation.
            if len(self.ctx.endpoints) >= self.ctx.options.max_endpoints:
                self.ctx.warn(
                    f"endpoint limit reached ({self.ctx.options.max_endpoints}); "
                    "some endpoints were not tested"
                )
        return {
            "endpoints": len(self.ctx.endpoints),
            "crawl": self.result.crawl.summary() if self.result.crawl else {},
            "discovered": len(self.result.discovery),
        }

    # ------------------------------------------------------------------
    def _detect(self) -> dict[str, Any]:
        classes = select_detectors(
            self.ctx,
            only=self.ctx.options.detectors,
            categories=self.ctx.options.categories,
            include_intrusive=self.ctx.options.intrusive,
        )
        skipped = [cls.meta.id for cls in classes if not self._applicable(cls)]
        classes = [cls for cls in classes if cls.meta.id not in skipped]
        self.ctx.logger.info(
            "detection starting",
            detectors=len(classes),
            excluded_extensions=len(self.ctx.options.exclude_detectors),
        )
        self._notify("detection_started", {"detectors": [cls.meta.id for cls in classes]})
        progress = Progress(self.ctx.logger, max(1, len(classes)), label="detect", every=1.5)
        concurrency = max(1, int(self.ctx.config.get("scan.concurrency", 8)))
        max_workers = min(concurrency, max(1, len(classes)))
        failures: list[str] = []
        with ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="detector") as executor:
            futures: dict[Future[Any], BaseDetector] = {}
            for cls in classes:
                if self.stopped:
                    break
                try:
                    detector = cls(self.ctx)
                except Exception as exc:
                    failures.append(f"{cls.meta.id}: init failed: {exc}")
                    continue
                self.ctx.stats["detectors_run"] += 1
                futures[executor.submit(self._run_detector, detector)] = detector
            for future in as_completed(futures):
                detector = futures[future]
                try:
                    count, error = future.result(timeout=DETECTOR_TIMEOUT)
                    if error:
                        failures.append(f"{detector.meta.id}: {error}")
                except Exception as exc:
                    failures.append(f"{detector.meta.id}: {exc}")
                progress.advance()
        self.ctx.stats["detectors_skipped"] += len(skipped)
        self.ctx.stats["detectors_failed"] += len(failures)
        for failure in failures:
            self.ctx.warn(f"detector failure: {failure}")
        merged = self._triage()
        counts = self.ctx.findings.counts()
        self.ctx.logger.info("detection complete", findings=len(self.ctx.findings), merged=len(merged), **counts)
        self._notify("detection_finished", {"counts": counts, "failures": failures})
        return {
            "detectors": len(classes),
            "skipped": skipped,
            "failures": failures,
            "findings": counts,
        }


    _OVERSHADOWING = {"rce", "ssti", "sqli", "lfi"}

    def _triage(self) -> list[str]:
        """Fold peripheral findings into the injection that already proves the same flaw.

        A parameter that executes commands also reflects markup; reporting both at high
        severity inflates the register without adding an actionable item. The low-value
        finding is recorded on the stronger one instead of being dropped silently.
        """

        stronger: dict[tuple[str, str, str], Any] = {}
        for finding in self.ctx.findings:
            if finding.category in self._OVERSHADOWING and finding.parameter:
                key = (finding.endpoint_key, finding.parameter.lower(), finding.location)
                current = stronger.get(key)
                if current is None or finding.severity_rank > current.severity_rank:
                    stronger[key] = finding
        removed: list[str] = []
        for finding in list(self.ctx.findings):
            if finding.category not in {"xss", "crlf"} or not finding.parameter:
                continue
            parent = stronger.get((finding.endpoint_key, finding.parameter.lower(), finding.location))
            if parent is None or finding.severity_rank <= parent.severity_rank:
                continue
            related = parent.metadata.setdefault("related_findings", [])
            related.append({"id": finding.id, "title": finding.title, "severity": finding.severity.value})
            parent.metadata.setdefault(
                "also_enables",
                "The same parameter " + finding.title.lower() + " can also be abused from the browser.",
            )
            self.ctx.findings.remove(finding.dedupe_key())
            removed.append(finding.id)
        if removed:
            self.ctx.stats["triage_merged"] = len(removed)
        return removed

    def _applicable(self, cls: type[BaseDetector]) -> bool:
        try:
            instance = cls(self.ctx)
            return instance.applicable()
        except Exception:
            return True

    def _run_detector(self, detector: BaseDetector) -> tuple[int, str]:
        started = time.monotonic()
        count = 0
        try:
            for finding in detector.run() or ():
                if finding is None:
                    continue
                count += 1
                if self.stopped:
                    break
        except Exception as exc:
            self.ctx.logger.exception(f"detector crashed: {detector.meta.id}")
            return count, str(exc)
        finally:
            duration = time.monotonic() - started
            self.ctx.logger.debug(
                "detector finished",
                detector=detector.meta.id,
                findings=count,
                seconds=round(duration, 2),
            )
        return count, ""

    # ------------------------------------------------------------------
    def _exploit(self) -> dict[str, Any]:
        from candix.exploit.engine import ExploitEngine

        if not self.ctx.scope or not self.ctx.scope.allows_exploit():
            self.ctx.warn("exploitation skipped: the engagement does not allow exploitation")
            return {"skipped": True, "reason": "not allowed by scope"}
        engine = ExploitEngine(self.ctx)
        executed = engine.run()
        self.result.exploited = executed
        return {
            "attempted": self.ctx.stats.get("exploits_attempted", 0),
            "succeeded": self.ctx.stats.get("exploits_succeeded", 0),
            "proofs": len(executed),
        }

    # ------------------------------------------------------------------
    def _notify(self, event: str, payload: dict[str, Any]) -> None:
        if self.on_progress is None:
            return
        try:
            self.on_progress(event, payload)
        except Exception:  # pragma: no cover - progress callbacks are advisory
            pass
        self.ctx.emit(event, payload)


def scan(
    targets: Iterable[str],
    *,
    config: Any,
    engagement: Any,
    options: Any = None,
    artifacts_dir: str | None = None,
    crawl: bool = True,
    discover: bool = True,
    exploit: bool = False,
    on_progress: Callable[[str, dict[str, Any]], None] | None = None,
) -> ScanResult:
    """Convenience wrapper used by the CLI, the API and tests."""

    from candix.core.context import ScanContext

    context = ScanContext.create(
        targets,
        config=config,
        engagement=engagement,
        options=options,
        artifacts_dir=artifacts_dir,
    )
    engine = ScanEngine(
        context,
        crawl=crawl,
        discover=discover,
        exploit=exploit,
        on_progress=on_progress,
    )
    return engine.run()


def severity_gate(findings: FindingSet, minimum: Severity) -> list[Finding]:
    return [finding for finding in findings.sorted() if finding.severity.rank >= minimum.rank]
