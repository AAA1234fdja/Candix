"""Minimal JSON HTTP API used by CI pipelines.

Endpoints
---------
``GET  /health``            liveness and queue summary
``GET  /version``           build information
``GET  /detectors``         detector catalogue
``GET  /scans``             recent jobs
``POST /scans``             queue a scan, returns ``202`` with a job id
``GET  /scans/<id>``        job status (``?wait=SECONDS`` blocks until finished)
``GET  /scans/<id>/report`` rendered report, ``?format=json|html|markdown|sarif``
``POST /scans/<id>/cancel`` request cancellation
``GET  /jobs/<id>/events``  progress events

The server binds to loopback by default, refuses to start without a bearer token
unless ``allow_anonymous`` is set (intended for local development only), and
never accepts a target outside the scope of the engagement supplied per request.
"""

from __future__ import annotations

import json
import os
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable
from urllib.parse import parse_qs, urlparse

from candix import VERSION
from candix.api.models import ApiError, JobStore, ScanJob, ScanRequest
from candix.core.clock import isoformat
from candix.core.config import Config
from candix.core.errors import CandixError
from candix.core.scope import Engagement, build_authorization

MAX_BODY_BYTES = 256 * 1024
REPORT_FORMATS = ("json", "html", "markdown", "sarif", "csv", "summary")


@dataclass
class ApiConfig:
    host: str = "127.0.0.1"
    port: int = 8088
    token: str = field(default_factory=lambda: os.environ.get("CANDIX_API_TOKEN", ""))
    allow_anonymous: bool = False
    artifacts_dir: str = "artifacts/api"
    max_workers: int = 2
    max_jobs: int = 200
    cors_origin: str = ""
    request_timeout: float = 30.0

    def validate(self) -> None:
        if not self.token and not self.allow_anonymous:
            raise ApiError(500, "CANDIX_API_TOKEN is not set; refusing to start an unauthenticated API")


class ScanRunner:
    """Executes queued scans on a bounded thread pool."""

    def __init__(self, config: ApiConfig, store: JobStore) -> None:
        self.config = config
        self.store = store
        self.executor = ThreadPoolExecutor(max_workers=max(1, config.max_workers), thread_name_prefix="candix-api")
        self._lock = threading.Lock()

    def submit(self, request: ScanRequest) -> ScanJob:
        job = self.store.create(request)
        job.event("queued", {"targets": request.targets})
        self.executor.submit(self._run, job)
        return job

    # ------------------------------------------------------------------
    def _run(self, job: ScanJob) -> None:
        from candix.engine import scan
        from candix.report import build_report

        request = job.request
        job.state = "running"
        job.started_at = isoformat()
        job.phase = "preflight"
        job.event("started")
        try:
            config = Config.profile(request.profile)
            config.set("exploit.enabled", request.exploit)
            if request.max_rps is not None:
                config.set("scan.max_rps", request.max_rps)
            if request.max_pages is not None:
                config.set("recon.max_crawl_pages", request.max_pages)
            if request.max_proofs is not None:
                config.set("exploit.max_proofs", request.max_proofs)
            if request.include_subdomains is not None:
                config.set("scan.include_subdomains", request.include_subdomains)
            config.set("detect.min_severity", request.min_severity)
            engagement = self._engagement(request)
            options = None
            if request.detectors or request.categories:
                from candix.core.context import ScanOptions

                options = ScanOptions(detectors=list(request.detectors), categories=list(request.categories))
                options.exploit = request.exploit
            progress = _JobProgress(job)
            result = scan(
                request.targets,
                config=config,
                engagement=engagement,
                options=options,
                artifacts_dir=self.config.artifacts_dir,
                exploit=request.exploit,
                on_progress=progress,
            )
            if job.cancel.is_set():
                job.state = "cancelled"
                job.finished_at = isoformat()
                job.event("cancelled")
                return
            job.counts = result.summary().get("findings") or {}
            job.risk_score = float(result.summary().get("risk_score", 0) or 0)
            job.phase = "report"
            job.progress = 0.9
            outdir = os.path.join(self.config.artifacts_dir, job.id)
            bundle = build_report(
                result,
                outdir=outdir,
                formats=request.formats,
                title=request.title or None,
                min_severity=request.min_severity,
            )
            job.artifacts = {artifact.format: str(artifact.path) for artifact in bundle.artifacts}
            job.report = {
                "summary": result.summary(),
                "findings": [finding.to_dict(include_evidence=False) for finding in result.findings.sorted()],
                "proofs": list(getattr(result.context, "metadata", {}).get("proofs", []) or []),
            }
            job.phase = "complete"
            job.progress = 1.0
            job.state = "succeeded"
            job.finished_at = isoformat()
            job.event("succeeded", {"counts": job.counts, "risk_score": job.risk_score})
        except Exception as exc:
            job.state = "failed"
            job.error = f"{type(exc).__name__}: {exc}"
            job.phase = "failed"
            job.finished_at = isoformat()
            job.event("failed", {"error": job.error})

    def _engagement(self, request: ScanRequest) -> Engagement:
        if request.engagement:
            engagement = Engagement.load(request.engagement)
            for target in request.targets:
                if not engagement.scope.matches(target):
                    raise ApiError(403, f"target {target} is outside the engagement scope")
            return engagement
        document = build_authorization(
            engagement=f"api-{request.authorized}",
            client="api",
            operator=request.authorized,
            authorized_by=request.authorized_by,
            include=[_scope_text(target) for target in request.targets],
            allow_exploit=request.exploit,
            max_rps=request.max_rps or 5.0,
        )
        return Engagement.from_document(document)

    def shutdown(self) -> None:
        self.executor.shutdown(wait=False)


class _JobProgress:
    def __init__(self, job: ScanJob) -> None:
        self.job = job
        self.steps = 0

    def __call__(self, event: str, payload: dict[str, Any]) -> None:
        self.steps += 1
        if event in {"phase_started", "phase_finished"}:
            self.job.phase = str(payload.get("phase", self.job.phase))
            self.job.progress = min(0.85, 0.1 + 0.05 * self.steps)
        self.job.event(event, payload)
        if self.job.cancel.is_set():
            self.job.state = "cancelled"


class ApiServer:
    def __init__(self, config: ApiConfig | None = None) -> None:
        self.config = config or ApiConfig()
        self.store = JobStore(limit=self.config.max_jobs)
        self.runner = ScanRunner(self.config, self.store)
        self.httpd: ThreadingHTTPServer | None = None
        self.thread: threading.Thread | None = None

    # ------------------------------------------------------------------
    def handler(self) -> type[BaseHTTPRequestHandler]:
        server = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"
            server_version = f"CandixApi/{VERSION}"
            sys_version = ""

            def log_message(self, fmt: str, *args: Any) -> None:  # pragma: no cover - noisy default
                return

            # -- helpers ---------------------------------------------------
            def _authorised(self) -> bool:
                if not server.config.token:
                    return server.config.allow_anonymous
                header = self.headers.get("Authorization", "")
                if header.startswith("Bearer "):
                    return _constant_time_equal(header[7:].strip(), server.config.token)
                return _constant_time_equal(self.headers.get("X-Candix-Token", ""), server.config.token)

            def _send(self, status: int, payload: Any, *, content_type: str = "application/json") -> None:
                if isinstance(payload, (dict, list)):
                    body = json.dumps(payload, default=str).encode("utf-8")
                else:
                    body = str(payload).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                if server.config.cors_origin:
                    self.send_header("Access-Control-Allow-Origin", server.config.cors_origin)
                    self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Candix-Token")
                    self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(body)

            def _error(self, status: int, message: str, **context: Any) -> None:
                self._send(status, {"error": message, "details": context})

            def _body(self) -> Any:
                length = int(self.headers.get("Content-Length") or 0)
                if length <= 0:
                    return {}
                if length > MAX_BODY_BYTES:
                    raise ApiError(413, "request body is too large")
                raw = self.rfile.read(length)
                try:
                    return json.loads(raw.decode("utf-8"))
                except json.JSONDecodeError as exc:
                    raise ApiError(400, f"invalid JSON: {exc}")

            def _parts(self) -> list[str]:
                return [part for part in urlparse(self.path).path.split("/") if part]

            # -- verbs -----------------------------------------------------
            def do_OPTIONS(self) -> None:  # noqa: N802
                self.send_response(204)
                if server.config.cors_origin:
                    self.send_header("Access-Control-Allow-Origin", server.config.cors_origin)
                    self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Candix-Token")
                    self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
                self.send_header("Content-Length", "0")
                self.end_headers()

            def do_HEAD(self) -> None:  # noqa: N802
                self.do_GET()

            def do_GET(self) -> None:  # noqa: N802
                try:
                    self._route_get()
                except ApiError as exc:
                    self._send(exc.status, exc.to_dict())
                except Exception as exc:  # pragma: no cover - defensive
                    self._error(500, f"internal error: {exc}")

            def do_POST(self) -> None:  # noqa: N802
                try:
                    self._route_post()
                except ApiError as exc:
                    self._send(exc.status, exc.to_dict())
                except CandixError as exc:
                    self._send(400, {"error": exc.message, "code": exc.code})
                except Exception as exc:  # pragma: no cover - defensive
                    self._error(500, f"internal error: {exc}")

            # -- routing ---------------------------------------------------
            def _route_get(self) -> None:
                parts = self._parts()
                query = parse_qs(urlparse(self.path).query)
                if not parts:
                    self._send(200, {
                        "name": "candix",
                        "version": VERSION,
                        "endpoints": [
                            "GET /health", "GET /version", "GET /detectors", "GET /scans",
                            "POST /scans", "GET /scans/<id>", "GET /scans/<id>/report",
                            "POST /scans/<id>/cancel", "GET /jobs/<id>/events",
                        ],
                    })
                    return
                if parts[0] == "health" and len(parts) == 1:
                    self._send(200, {"status": "ok", "jobs": server.store.counts(), "time": isoformat()})
                    return
                if parts[0] == "version":
                    self._send(200, {"version": VERSION, "api": 1, "formats": list(REPORT_FORMATS)})
                    return
                if not self._authorised():
                    raise ApiError(401, "missing or invalid bearer token")
                if parts[0] == "detectors" and len(parts) == 1:
                    from candix.detectors.base import detector_catalog, summarize_detectors

                    self._send(200, {"summary": summarize_detectors(), "detectors": detector_catalog()})
                    return
                if parts[0] == "scans" and len(parts) == 1:
                    state = (query.get("state") or [""])[0]
                    limit = int((query.get("limit") or ["50"])[0])
                    jobs = server.store.list(state=state, limit=limit)
                    self._send(200, {"jobs": [job.to_dict() for job in jobs], "counts": server.store.counts()})
                    return
                if parts[0] == "scans" and len(parts) >= 2:
                    job = server.store.get(parts[1])
                    if len(parts) == 2:
                        wait = float((query.get("wait") or ["0"])[0])
                        if wait:
                            job = server.store.wait(job.id, timeout=wait)
                        self._send(200, job.to_dict(include_report=bool(query.get("report"))))
                        return
                    if parts[2] == "report":
                        self._report(job, query)
                        return
                    if parts[2] == "events":
                        self._send(200, {"events": job.events, "state": job.state})
                        return
                if parts[0] == "jobs" and len(parts) == 3 and parts[2] == "events":
                    job = server.store.get(parts[1])
                    self._send(200, {"events": job.events, "state": job.state})
                    return
                raise ApiError(404, f"no route for GET {self.path}")

            def _report(self, job: ScanJob, query: dict[str, list[str]]) -> None:
                if job.state != "succeeded":
                    raise ApiError(409, f"job is {job.state}; the report is not available yet")
                fmt = (query.get("format") or ["json"])[0].lower()
                inline = (query.get("inline") or ["1"])[0] not in {"0", "false", "no"}
                if fmt == "json" and inline:
                    self._send(200, job.report)
                    return
                path = job.artifacts.get(fmt)
                if not path:
                    raise ApiError(404, f"report format {fmt} was not generated", available=sorted(job.artifacts))
                try:
                    with open(path, "rb") as handle:
                        payload = handle.read()
                except OSError as exc:
                    raise ApiError(500, f"cannot read report: {exc}")
                content_type = {
                    "json": "application/json",
                    "html": "text/html; charset=utf-8",
                    "markdown": "text/markdown; charset=utf-8",
                    "sarif": "application/sarif+json",
                    "csv": "text/csv; charset=utf-8",
                }.get(fmt, "application/octet-stream")
                self._send(200, payload.decode("utf-8", "replace"), content_type=content_type)

            def _route_post(self) -> None:
                parts = self._parts()
                if not self._authorised():
                    raise ApiError(401, "missing or invalid bearer token")
                if parts[:1] == ["scans"] and len(parts) == 1:
                    body = self._body()
                    request = ScanRequest.from_payload(body)
                    job = server.runner.submit(request)
                    self._send(202, {"id": job.id, "state": job.state, "status_url": f"/scans/{job.id}"})
                    return
                if parts[:1] == ["scans"] and len(parts) == 3 and parts[2] == "cancel":
                    job = server.store.get(parts[1])
                    if job.terminal:
                        self._send(200, {"id": job.id, "state": job.state})
                        return
                    job.cancel.set()
                    job.state = "cancelled"
                    job.finished_at = isoformat()
                    job.event("cancel-requested")
                    self._send(202, {"id": job.id, "state": job.state})
                    return
                if parts[:1] == ["prune"]:
                    removed = server.store.prune()
                    self._send(200, {"removed": removed, "counts": server.store.counts()})
                    return
                raise ApiError(404, f"no route for POST {self.path}")

        return Handler

    # ------------------------------------------------------------------
    def start(self) -> "ApiServer":
        self.config.validate()
        self.httpd = ThreadingHTTPServer((self.config.host, self.config.port), self.handler())
        self.httpd.daemon_threads = True
        self.config.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True, name="candix-api")
        self.thread.start()
        return self

    def stop(self) -> None:
        self.runner.shutdown()
        if self.httpd is not None:
            self.httpd.shutdown()
            self.httpd.server_close()
            self.httpd = None
        if self.thread is not None:
            self.thread.join(timeout=3.0)
            self.thread = None

    @property
    def base_url(self) -> str:
        return f"http://{self.config.host}:{self.config.port}"

    def __enter__(self) -> "ApiServer":
        return self.start()

    def __exit__(self, *exc: Any) -> None:
        self.stop()


def build_server(
    host: str = "127.0.0.1",
    port: int = 8088,
    *,
    token: str | None = None,
    allow_anonymous: bool = False,
    artifacts_dir: str = "artifacts/api",
    cors_origin: str = "",
) -> ApiServer:
    config = ApiConfig(
        host=host,
        port=port,
        token=os.environ.get("CANDIX_API_TOKEN", "") if token is None else token,
        allow_anonymous=allow_anonymous,
        artifacts_dir=artifacts_dir,
        cors_origin=cors_origin,
    )
    return ApiServer(config)


def _scope_entry_host(target: str) -> str:
    return target


def _scope_text(target: str) -> str:
    from candix.net.url import URL

    try:
        url = URL.parse(target if "://" in target else f"http://{target}")
    except ValueError:
        return target
    return f"{url.host}:{url.port or (443 if url.scheme == 'https' else 80)}"


def _constant_time_equal(left: str, right: str) -> bool:
    import hmac

    return hmac.compare_digest(left.encode("utf-8"), str(right).encode("utf-8"))


def serve_forever(server: ApiServer) -> None:
    if server.httpd is None:
        server.start()
    try:
        while server.thread is not None and server.thread.is_alive():
            server.thread.join(timeout=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        server.stop()
