"""HTTP/1.1 client built on ``http.client``.

Design goals, in order:

1. **Safety.** Every request passes through the scope guard, the budget and the
   rate limiter. Redirects that leave scope are not followed.
2. **Observability.** Each exchange keeps the exact bytes that were sent and
   received so a finding can quote a reproducible request.
3. **Fidelity.** Raw header order, duplicate headers, chunked responses,
   compression and TLS metadata are preserved; the harness must see the target
   the way an attacker does.

The client is dependency-free and thread-safe: connections are pooled per
origin and leased exclusively.
"""

from __future__ import annotations

import base64
import gzip
import http.client
import json as json_module
import queue
import socket
import ssl
import threading
import time
import zlib
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping
from urllib.parse import unquote, urlsplit

from candix.core.budget import Budget, BudgetLimits
from candix.core.clock import humanize_duration
from candix.core.config import Config
from candix.core.errors import (
    BudgetExceeded,
    ProtocolError,
    ScopeViolation,
    TargetUnreachable,
)
from candix.core.log import Logger, get_logger
from candix.core.redact import SecretRegistry
from candix.net.cookies import Cookie, CookieJar
from candix.net.ratelimit import Cooldown, HostRateLimiter
from candix.net.url import QueryParams, URL, join_url

_MAX_HEADER_BYTES = 256 * 1024
_DEFAULT_ACCEPT = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"


class Headers:
    """Case-insensitive header container preserving duplicates and order."""

    __slots__ = ("_items",)

    def __init__(self, items: Iterable[tuple[str, str]] | Mapping[str, str] | None = None) -> None:
        self._items: list[tuple[str, str]] = []
        if items is None:
            return
        source = items.items() if isinstance(items, Mapping) else items
        for name, value in source:
            self._items.append((str(name), str(value)))

    def __iter__(self):
        return iter(self._items)

    def __len__(self) -> int:
        return len(self._items)

    def __contains__(self, name: object) -> bool:
        lowered = str(name).lower()
        return any(key.lower() == lowered for key, _ in self._items)

    def __getitem__(self, name: str) -> str:
        value = self.get(name)
        if value is None:
            raise KeyError(name)
        return value

    def get(self, name: str, default: str | None = None) -> str | None:
        lowered = name.lower()
        for key, value in self._items:
            if key.lower() == lowered:
                return value
        return default

    def get_all(self, name: str) -> list[str]:
        lowered = name.lower()
        return [value for key, value in self._items if key.lower() == lowered]

    def set(self, name: str, value: str) -> None:
        lowered = name.lower()
        replaced = False
        result: list[tuple[str, str]] = []
        for key, existing in self._items:
            if key.lower() == lowered:
                if not replaced:
                    result.append((name, str(value)))
                    replaced = True
                continue
            result.append((key, existing))
        if not replaced:
            result.append((name, str(value)))
        self._items = result

    def add(self, name: str, value: str) -> None:
        self._items.append((str(name), str(value)))

    def remove(self, name: str) -> None:
        lowered = name.lower()
        self._items = [(key, value) for key, value in self._items if key.lower() != lowered]

    def items(self) -> list[tuple[str, str]]:
        return list(self._items)

    def keys(self) -> list[str]:
        return [key for key, _ in self._items]

    def to_dict(self) -> dict[str, str]:
        return dict(self._items)

    def copy(self) -> "Headers":
        return Headers(self._items)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"Headers({self._items!r})"


@dataclass
class TLSInfo:
    version: str = ""
    cipher: str = ""
    bits: int = 0
    subject: str = ""
    issuer: str = ""
    san: list[str] = field(default_factory=list)
    not_before: str = ""
    not_after: str = ""
    serial: str = ""
    fingerprint: str = ""
    verified: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "cipher": self.cipher,
            "bits": self.bits,
            "subject": self.subject,
            "issuer": self.issuer,
            "san": list(self.san),
            "not_before": self.not_before,
            "not_after": self.not_after,
            "serial": self.serial,
            "fingerprint": self.fingerprint,
            "verified": self.verified,
        }


@dataclass
class RequestRecord:
    method: str
    url: str
    headers: dict[str, str]
    body: str = ""


@dataclass
class Response:
    """A completed HTTP exchange."""

    status: int = 0
    reason: str = ""
    headers: Headers = field(default_factory=Headers)
    content: bytes = b""
    elapsed: float = 0.0
    url: str = ""
    method: str = "GET"
    request_headers: dict[str, str] = field(default_factory=dict)
    request_body: str = ""
    history: list["Response"] = field(default_factory=list)
    error: str = ""
    tls: TLSInfo | None = None
    http_version: str = "HTTP/1.1"
    truncated: bool = False

    # ------------------------------------------------------------------
    @property
    def text(self) -> str:
        return decode_body(self.content, self.headers.get("Content-Type", ""))

    @property
    def size(self) -> int:
        return len(self.content)

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 400

    @property
    def content_type(self) -> str:
        return (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()

    @property
    def charset(self) -> str:
        header = self.headers.get("Content-Type") or ""
        for part in header.split(";")[1:]:
            key, _, value = part.strip().partition("=")
            if key.lower() == "charset":
                return value.strip().strip('"')
        return "utf-8"

    @property
    def redirected(self) -> bool:
        return bool(self.history)

    @property
    def final_url(self) -> str:
        return self.url

    def header(self, name: str, default: str = "") -> str:
        return self.headers.get(name, default) or ""

    def json(self) -> Any:
        return json_module.loads(self.text)

    def try_json(self) -> Any:
        try:
            return self.json()
        except (ValueError, TypeError):
            return None

    def lines(self) -> list[str]:
        return self.text.splitlines()

    def contains(self, needle: str) -> bool:
        return needle in self.text

    def lower_text(self) -> str:
        return self.text.lower()

    def cookies(self) -> list[Cookie]:
        from candix.net.cookies import parse_set_cookie

        host = urlsplit(self.url).hostname or ""
        result: list[Cookie] = []
        for header in self.headers.get_all("Set-Cookie"):
            cookie = parse_set_cookie(header, host)
            if cookie:
                result.append(cookie)
        return result

    def request_record(self) -> RequestRecord:
        return RequestRecord(self.method, self.url, dict(self.request_headers), self.request_body)

    def to_curl(self) -> str:
        from candix.core.evidence import Exchange

        return Exchange(
            method=self.method,
            url=self.url,
            request_headers=self.request_headers,
            request_body=self.request_body,
            status=self.status,
            reason=self.reason,
            response_headers=self.headers.to_dict(),
            response_body=self.text,
            elapsed=self.elapsed,
        ).to_curl()

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<Response {self.status} {self.method} {self.url} {self.size}B>"


def decode_body(content: bytes, content_type: str) -> str:
    charset = "utf-8"
    for part in (content_type or "").split(";")[1:]:
        key, _, value = part.strip().partition("=")
        if key.lower() == "charset":
            charset = value.strip().strip('"') or "utf-8"
    candidates = [charset, "utf-8", "latin-1"]
    for encoding in candidates:
        try:
            return content.decode(encoding)
        except (LookupError, UnicodeDecodeError):
            continue
    return content.decode("utf-8", "replace")


class ConnectionPool:
    """LIFO pool of persistent connections per origin."""

    def __init__(self, max_per_origin: int = 8, timeout: float = 10.0) -> None:
        self.max_per_origin = max_per_origin
        self.timeout = timeout
        self._pools: dict[str, queue.LifoQueue] = {}
        self._lock = threading.Lock()
        self.created = 0
        self.reused = 0

    def _queue(self, key: str) -> queue.LifoQueue:
        with self._lock:
            pool = self._pools.get(key)
            if pool is None:
                pool = queue.LifoQueue(maxsize=self.max_per_origin)
                self._pools[key] = pool
            return pool

    def acquire(self, key: str, factory) -> http.client.HTTPConnection:
        pool = self._queue(key)
        try:
            connection = pool.get_nowait()
            self.reused += 1
            return connection
        except queue.Empty:
            self.created += 1
            return factory()

    def release(self, key: str, connection: http.client.HTTPConnection) -> None:
        pool = self._queue(key)
        try:
            pool.put_nowait(connection)
        except queue.Full:
            connection.close()

    def close(self) -> None:
        with self._lock:
            pools = list(self._pools.values())
        for pool in pools:
            while True:
                try:
                    pool.get_nowait().close()
                except queue.Empty:
                    break

    def stats(self) -> dict[str, int]:
        return {"created": self.created, "reused": self.reused, "origins": len(self._pools)}


class HttpClient:
    """Scope-aware HTTP client with retries, cookies and metrics."""

    def __init__(
        self,
        config: Config | None = None,
        *,
        scope: Any = None,
        budget: Budget | None = None,
        limiter: HostRateLimiter | None = None,
        logger: Logger | None = None,
        cookie_jar: CookieJar | None = None,
        registry: SecretRegistry | None = None,
    ) -> None:
        self.config = config or Config()
        self.scope = scope
        self.budget = budget or Budget(
            BudgetLimits(
                max_requests=int(self.config.get("scan.max_requests", 20000)),
                max_seconds=float(self.config.get("scan.deadline_seconds", 1800) or 0),
                max_bytes=int(self.config.get("http.max_body_bytes", 2_000_000)) * 512,
            )
        )
        self.limiter = limiter or HostRateLimiter(
            float(self.config.get("scan.max_rps", 5.0)),
            int(self.config.get("scan.burst", 5)),
        )
        self.logger = logger or get_logger("candix.http")
        self.cookies = cookie_jar or CookieJar()
        self.registry = registry
        self.pool = ConnectionPool(max_per_origin=8, timeout=float(self.config.get("http.timeout", 10.0)))
        self.cooldown = Cooldown(0.4, maximum=8.0)
        self.timeout = float(self.config.get("http.timeout", 10.0))
        self.connect_timeout = float(self.config.get("http.connect_timeout", 5.0))
        self.verify_tls = bool(self.config.get("http.verify_tls", True))
        self.user_agent = str(self.config.get("http.user_agent", "Candix/0.1"))
        self.max_redirects = int(self.config.get("http.max_redirects", 5))
        self.max_body = int(self.config.get("http.max_body_bytes", 2_000_000))
        self.retries = int(self.config.get("http.retries", 1))
        self.extra_headers = dict(self.config.get("http.headers", {}) or {})
        self.proxy = _parse_proxy(str(self.config.get("http.proxy", "") or ""))
        self._ssl_context = self._build_ssl_context()
        self.stats: dict[str, Any] = {
            "requests": 0,
            "bytes": 0,
            "errors": 0,
            "status": {},
            "redirects": 0,
            "retries": 0,
            "blocked": 0,
        }
        self._stats_lock = threading.Lock()
        self._closed = False

    # ------------------------------------------------------------------
    # setup
    # ------------------------------------------------------------------
    def _build_ssl_context(self) -> ssl.SSLContext:
        context = ssl.create_default_context()
        if not self.verify_tls:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        try:
            context.set_alpn_protocols(["http/1.1"])
        except NotImplementedError:  # pragma: no cover - old OpenSSL
            pass
        return context

    def set_cookies(self, pairs: dict[str, str], host: str = "") -> None:
        self.cookies.import_pairs(pairs, host)

    def set_header(self, name: str, value: str) -> None:
        self.extra_headers[name] = value

    # ------------------------------------------------------------------
    # public API
    # ------------------------------------------------------------------
    def get(self, url: str, **kwargs: Any) -> Response:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> Response:
        return self.request("POST", url, **kwargs)

    def head(self, url: str, **kwargs: Any) -> Response:
        return self.request("HEAD", url, **kwargs)

    def options(self, url: str, **kwargs: Any) -> Response:
        return self.request("OPTIONS", url, **kwargs)

    def request(
        self,
        method: str,
        url: str | URL,
        *,
        params: Mapping[str, Any] | QueryParams | None = None,
        data: str | bytes | Mapping[str, Any] | None = None,
        json_body: Any = None,
        headers: Mapping[str, str] | None = None,
        cookies: Mapping[str, str] | None = None,
        allow_redirects: bool | None = None,
        timeout: float | None = None,
        tag: str = "",
    ) -> Response:
        url_obj = URL.parse(url) if isinstance(url, str) else url.copy()
        if params:
            query = params if isinstance(params, QueryParams) else QueryParams.from_mapping(dict(params))
            for name, value in query:
                url_obj = url_obj.add_param(name, value)
        if self.scope is not None:
            try:
                self.scope.check_method(method)
                self.scope.assert_url(url_obj, method)
            except ScopeViolation:
                with self._stats_lock:
                    self.stats["blocked"] += 1
                raise
        if method.upper() in {"GET", "HEAD", "OPTIONS", "TRACE"} and (data is not None or json_body is not None):
            if data or json_body is not None:
                self.logger.debug("dropping body on body-less method", method=method, url=url_obj.render())
            data = None
            json_body = None
        body, body_headers = _prepare_body(data, json_body)
        merged_headers = self._default_headers(url_obj)
        merged_headers.update(self.extra_headers)
        for name, value in (headers or {}).items():
            merged_headers[name] = value
        for name, value in body_headers.items():
            merged_headers.setdefault(name, value)
        cookie_header = ""
        if cookies:
            cookie_header = "; ".join(f"{name}={value}" for name, value in cookies.items())
        elif self.cookies:
            cookie_header = self.cookies.header(url_obj.render())
        if cookie_header and not any(key.lower() == "cookie" for key in merged_headers):
            merged_headers["Cookie"] = cookie_header
        redirects = allow_redirects if allow_redirects is not None else bool(self.config.get("scan.follow_redirects", True))
        response = self._execute(
            method.upper(),
            url_obj,
            body,
            merged_headers,
            hops=self.max_redirects if redirects else 0,
            timeout=timeout,
            tag=tag,
        )
        return response

    def request_endpoint(
        self,
        endpoint: Any,
        *,
        overrides: Mapping[str, str] | None = None,
        method: str | None = None,
        headers: Mapping[str, str] | None = None,
        body_override: str | None = None,
        tag: str = "",
    ) -> Response:
        """Send an :class:`Endpoint` with optional parameter overrides."""

        from candix.core.endpoint import dump_body

        overrides = dict(overrides or {})
        url_obj = URL.parse(endpoint.url)
        merged_headers: dict[str, str] = dict(endpoint.headers)
        merged_headers.update(headers or {})
        body_text = body_override
        for param in endpoint.params:
            if param.name not in overrides:
                continue
            value = overrides[param.name]
            if param.location == "query":
                url_obj = url_obj.set_param(param.name, value)
            elif param.location in {"body", "json"}:
                if endpoint.body and endpoint.body.kind == "json" and isinstance(endpoint.body.json, dict):
                    endpoint.body.json[param.name] = value
                elif endpoint.body and endpoint.body.kind == "form":
                    endpoint.body.form[param.name] = value
                else:
                    body_text = value
            elif param.location == "header":
                merged_headers[param.name] = value
            elif param.location == "cookie":
                merged_headers["Cookie"] = _merge_cookie(merged_headers.get("Cookie", ""), param.name, value)
            elif param.location == "path":
                url_obj = url_obj.with_path(url_obj.path.replace(f"{{{param.name}}}", value))
        if body_text is None and endpoint.body is not None:
            body_text = dump_body(endpoint.body)
        verb = (method or endpoint.method).upper()
        if verb in {"GET", "HEAD", "OPTIONS", "TRACE"}:
            # Body-bearing parameters on a GET endpoint are represented in the
            # query string. Sending a body with GET breaks keep-alive framing on
            # servers that do not read it, which can corrupt later requests.
            body_text = None
            for param in endpoint.params:
                if param.location in {"body", "json"} and param.name in overrides:
                    url_obj = url_obj.set_param(param.name, overrides[param.name])
        return self.request(
            verb,
            url_obj,
            data=body_text,
            headers=merged_headers,
            cookies=endpoint.cookies or None,
            tag=tag,
        )

    def probe(
        self,
        url: str | URL,
        *,
        param: str | None = None,
        value: str | None = None,
        method: str = "GET",
        data: str | None = None,
        headers: Mapping[str, str] | None = None,
        tag: str = "",
        allow_redirects: bool | None = None,
    ) -> Response:
        """Convenience wrapper: set one query parameter and send."""

        url_obj = URL.parse(url) if isinstance(url, str) else url.copy()
        if param is not None and value is not None:
            url_obj = url_obj.set_param(param, value)
        if method.upper() in {"GET", "HEAD", "OPTIONS"}:
            return self.request(method, url_obj, headers=headers, tag=tag, allow_redirects=allow_redirects)
        return self.request(method, url_obj, data=data or "", headers=headers, tag=tag, allow_redirects=allow_redirects)

    # ------------------------------------------------------------------
    # execution
    # ------------------------------------------------------------------
    def _execute(
        self,
        method: str,
        url: URL,
        body: bytes,
        headers: dict[str, str],
        *,
        hops: int,
        timeout: float | None,
        tag: str,
        history: list[Response] | None = None,
    ) -> Response:
        history = history or []
        response = self._send_single(method, url, body, headers, timeout=timeout or self.timeout, tag=tag)
        if response.error or not (300 <= response.status < 400):
            response.history = history
            return response
        location = response.headers.get("Location")
        if not location or hops <= 0:
            response.history = history
            return response
        try:
            target = join_url(url, location)
        except ValueError:
            response.history = history
            return response
        if self.scope is not None and not self.scope.matches(target):
            response.error = "redirect target outside scope"
            response.history = history
            return response
        next_method = method
        next_body = body
        if response.status in {301, 302, 303} and method not in {"GET", "HEAD"}:
            next_method = "GET"
            next_body = b""
        next_headers = dict(headers)
        if target.host != url.host:
            next_headers.pop("Authorization", None)
            next_headers.pop("authorization", None)
        next_headers.pop("Host", None)
        if next_body == b"":
            for name in list(next_headers):
                if name.lower() == "content-type":
                    next_headers.pop(name, None)
        with self._stats_lock:
            self.stats["redirects"] += 1
        return self._execute(
            next_method,
            target,
            next_body,
            next_headers,
            hops=hops - 1,
            timeout=timeout,
            tag=tag,
            history=[*history, response],
        )

    def _send_single(
        self,
        method: str,
        url: URL,
        body: bytes,
        headers: dict[str, str],
        *,
        timeout: float,
        tag: str,
    ) -> Response:
        attempts = self.retries + 1
        last_error = ""
        for attempt in range(1, attempts + 1):
            try:
                self.budget.acquire_request(url.host)
                self.limiter.acquire(url.origin)
                return self._do_request(method, url, body, headers, timeout=timeout, tag=tag)
            except (TargetUnreachable, ProtocolError, socket.timeout, TimeoutError, OSError) as exc:
                last_error = str(exc)
                with self._stats_lock:
                    self.stats["errors"] += 1
                self.budget.record_error()
                if attempt >= attempts:
                    break
                delay = self.cooldown.delay(attempt)
                self.budget.record_retry()
                self.logger.debug(
                    "request failed, retrying",
                    url=url.render(),
                    attempt=attempt,
                    delay=round(delay, 3),
                    error=last_error,
                )
                time.sleep(delay)
            except ScopeViolation:
                raise
            except BudgetExceeded:
                raise
        return Response(
            status=0,
            reason="request failed",
            url=url.render(),
            method=method,
            request_headers=_redactable_headers(headers),
            error=last_error or "unknown transport error",
            elapsed=0.0,
        )

    def _do_request(
        self,
        method: str,
        url: URL,
        body: bytes,
        headers: dict[str, str],
        *,
        timeout: float,
        tag: str,
    ) -> Response:
        started = time.monotonic()
        host = url.host
        port = url.effective_port or (443 if url.scheme == "https" else 80)
        scheme = "https" if url.is_https() else "http"
        proxy = self.proxy if not _is_loopback_host(host) else None
        key = f"{scheme}|{host}|{port}|{proxy['host'] if proxy else ''}"
        connection: http.client.HTTPConnection

        if proxy and scheme == "http":
            factory = lambda: http.client.HTTPConnection(  # noqa: E731
                proxy["host"], proxy["port"], timeout=min(timeout, self.connect_timeout)
            )
            connection = self.pool.acquire(key, factory)
            target = url.render(include_fragment=False)
            if proxy.get("auth"):
                headers.setdefault("Proxy-Authorization", proxy["auth"])
        elif proxy and scheme == "https":
            factory = lambda: http.client.HTTPSConnection(  # noqa: E731
                proxy["host"], proxy["port"], timeout=min(timeout, self.connect_timeout), context=self._ssl_context
            )
            connection = self.pool.acquire(key, factory)
            connection.set_tunnel(host, port, headers={"Proxy-Authorization": proxy["auth"]} if proxy.get("auth") else None)
            target = url.path or "/"
            if url.query:
                target += "?" + url.query.render()
        elif scheme == "https":
            factory = lambda: http.client.HTTPSConnection(  # noqa: E731
                host, port, timeout=min(timeout, self.connect_timeout), context=self._ssl_context
            )
            connection = self.pool.acquire(key, factory)
            target = url.path or "/"
            if url.query:
                target += "?" + url.query.render()
        else:
            factory = lambda: http.client.HTTPConnection(  # noqa: E731
                host, port, timeout=min(timeout, self.connect_timeout)
            )
            connection = self.pool.acquire(key, factory)
            target = url.path or "/"
            if url.query:
                target += "?" + url.query.render()

        connection.timeout = timeout
        headers = dict(headers)
        if not any(key.lower() == "host" for key in headers):
            headers["Host"] = url.netloc
        if body:
            headers.setdefault("Content-Length", str(len(body)))
        elif method.upper() in {"POST", "PUT", "PATCH"}:
            headers.setdefault("Content-Length", "0")
        headers.setdefault("Accept-Encoding", "gzip, deflate")
        reusable = True
        raw_response: http.client.HTTPResponse | None = None
        try:
            connection.request(method, target, body=body or None, headers=headers)
            raw_response = connection.getresponse()
            content = self._read_body(raw_response)
            elapsed = time.monotonic() - started
            response_headers = Headers(raw_response.getheaders())
            reusable = not raw_response.will_close
            tls_info = _extract_tls(connection) if scheme == "https" else None
            response = Response(
                status=raw_response.status,
                reason=raw_response.reason,
                headers=response_headers,
                content=content,
                elapsed=elapsed,
                url=url.render(),
                method=method,
                request_headers=_redactable_headers(headers),
                request_body=body.decode("utf-8", "replace") if body else "",
                tls=tls_info,
                http_version={10: "HTTP/1.0", 11: "HTTP/1.1"}.get(raw_response.version, "HTTP/1.1"),
            )
        except (socket.timeout, TimeoutError) as exc:
            connection.close()
            raise TargetUnreachable(f"timeout after {humanize_duration(timeout)}", url=url.render()) from exc
        except (http.client.HTTPException, OSError, ssl.SSLError) as exc:
            reusable = False
            connection.close()
            raise TargetUnreachable(f"transport error: {exc}", url=url.render()) from exc
        finally:
            if raw_response is None:
                reusable = False
            if reusable:
                self.pool.release(key, connection)
            elif connection.sock is not None:
                connection.close()

        if response_headers:
            self.cookies.add_from_headers(url.render(), response_headers.get_all("Set-Cookie"))
        with self._stats_lock:
            self.stats["requests"] += 1
            self.stats["bytes"] += len(content)
            status_key = str(response.status)
            self.stats["status"][status_key] = self.stats["status"].get(status_key, 0) + 1
        self.budget.record_response(len(content))
        self.limiter.observe(url.origin, response.status, _retry_after(response.headers))
        if response.status in (429, 503):
            self.logger.warning("target is throttling requests", url=url.render(), status=response.status)
        if self.registry is not None:
            for header in response.headers.get_all("Set-Cookie"):
                self.registry.add_cookie(header)
            auth = response.headers.get("Authorization")
            if auth:
                self.registry.add(auth)
        self.logger.debug(
            "http",
            method=method,
            url=url.render(),
            status=response.status,
            size=len(content),
            ms=round(response.elapsed * 1000, 1),
            tag=tag,
        )
        return response

    def _read_body(self, response: http.client.HTTPResponse) -> bytes:
        chunks: list[bytes] = []
        remaining = self.max_body
        truncated = False
        while remaining > 0:
            chunk = response.read(min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        if remaining <= 0:
            truncated = True
        raw = b"".join(chunks)
        encoding = (response.headers.get("Content-Encoding") or "").lower()
        if "gzip" in encoding:
            raw = _safe_decompress(raw, gzip.decompress)
        elif "deflate" in encoding:
            raw = _safe_decompress(raw, zlib.decompress)
        if truncated:
            self.logger.debug("response body truncated at limit", limit=self.max_body)
        return raw

    # ------------------------------------------------------------------
    # raw socket helper (request smuggling and protocol research)
    # ------------------------------------------------------------------
    def send_raw(self, host: str, port: int, payload: bytes, *, timeout: float = 5.0, use_tls: bool = False) -> bytes:
        """Send raw bytes and read the response.

        Used only by protocol detectors that need control over framing. The
        destination is checked against scope before the socket is opened.
        """

        if self.scope is not None:
            scheme = "https" if use_tls else "http"
            self.scope.assert_url(f"{scheme}://{host}:{port}/", "GET")
        self.budget.acquire_request(host)
        sock = socket.create_connection((host, port), timeout=timeout)
        try:
            if use_tls:
                sock = self._ssl_context.wrap_socket(sock, server_hostname=host)
            sock.sendall(payload)
            sock.shutdown(socket.SHUT_WR)
            chunks: list[bytes] = []
            total = 0
            while total < 65536:
                data = sock.recv(4096)
                if not data:
                    break
                chunks.append(data)
                total += len(data)
            return b"".join(chunks)
        finally:
            try:
                sock.close()
            except OSError:
                pass

    # ------------------------------------------------------------------
    def _default_headers(self, url: URL) -> dict[str, str]:
        headers = {
            "User-Agent": self.user_agent,
            "Accept": _DEFAULT_ACCEPT,
            "Accept-Language": "en-US,en;q=0.9",
            "Connection": "keep-alive",
        }
        return headers

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self.pool.close()

    def __enter__(self) -> "HttpClient":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def snapshot(self) -> dict[str, Any]:
        return {
            "stats": dict(self.stats),
            "pool": self.pool.stats(),
            "rate_limiter": self.limiter.snapshot(),
            "budget": self.budget.snapshot(),
            "cookies": len(self.cookies),
        }


def _prepare_body(
    data: str | bytes | Mapping[str, Any] | None,
    json_body: Any,
) -> tuple[bytes, dict[str, str]]:
    if json_body is not None:
        payload = json_module.dumps(json_body).encode("utf-8")
        return payload, {"Content-Type": "application/json"}
    if data is None:
        return b"", {}
    if isinstance(data, bytes):
        return data, {}
    if isinstance(data, str):
        return data.encode("utf-8"), {"Content-Type": "application/x-www-form-urlencoded"}
    query = QueryParams.from_mapping(dict(data))
    return query.render().encode("utf-8"), {"Content-Type": "application/x-www-form-urlencoded"}


def _redactable_headers(headers: Mapping[str, str]) -> dict[str, str]:
    return {str(name): str(value) for name, value in headers.items()}


def _merge_cookie(existing: str, name: str, value: str) -> str:
    pairs: dict[str, str] = {}
    for chunk in existing.split(";"):
        key, _, item = chunk.strip().partition("=")
        if key:
            pairs[key] = item
    pairs[name] = value
    return "; ".join(f"{key}={item}" for key, item in pairs.items())


def _safe_decompress(payload: bytes, function) -> bytes:
    try:
        return function(payload)
    except (OSError, zlib.error, EOFError):
        return payload


def _retry_after(headers: Headers) -> float:
    value = headers.get("Retry-After")
    if not value:
        return 0.0
    try:
        return min(120.0, float(value.strip()))
    except ValueError:
        return 5.0


def _parse_proxy(raw: str) -> dict[str, Any] | None:
    if not raw:
        return None
    if "://" not in raw:
        raw = "http://" + raw
    parts = urlsplit(raw)
    if not parts.hostname:
        return None
    auth = ""
    if parts.username:
        credentials = f"{unquote(parts.username)}:{unquote(parts.password or '')}"
        auth = "Basic " + base64.b64encode(credentials.encode()).decode()
    return {
        "host": parts.hostname,
        "port": parts.port or 8080,
        "auth": auth,
    }


def _is_loopback_host(host: str) -> bool:
    from candix.net.url import is_loopback

    return is_loopback(host)


def _extract_tls(connection: http.client.HTTPConnection) -> TLSInfo | None:
    sock = getattr(connection, "sock", None)
    if sock is None:
        return None
    try:
        version = sock.version() if hasattr(sock, "version") else ""
        cipher = sock.cipher() if hasattr(sock, "cipher") else None
        info = TLSInfo(
            version=version or "",
            cipher=cipher[0] if cipher else "",
            bits=cipher[2] if cipher and len(cipher) > 2 else 0,
            verified=bool(getattr(sock, "getpeercert", lambda **_: None)()),
        )
        cert = sock.getpeercert() if hasattr(sock, "getpeercert") else None
        if cert:
            info.subject = _flatten_name(cert.get("subject", ()))
            info.issuer = _flatten_name(cert.get("issuer", ()))
            info.san = [value for kind, value in cert.get("subjectAltName", ()) if kind.lower() == "dns"]
            info.not_before = cert.get("notBefore", "")
            info.not_after = cert.get("notAfter", "")
            info.serial = cert.get("serialNumber", "")
        binary = sock.getpeercert(binary_form=True) if hasattr(sock, "getpeercert") else None
        if binary:
            import hashlib

            info.fingerprint = hashlib.sha256(binary).hexdigest()
        return info
    except (ValueError, OSError, AttributeError):  # pragma: no cover - defensive
        return None


def _flatten_name(name: Any) -> str:
    if not name:
        return ""
    parts: list[str] = []
    for rdn in name:
        for key, value in rdn:
            parts.append(f"{key}={value}")
    return ", ".join(parts)


__all__ = [
    "ConnectionPool",
    "Headers",
    "HttpClient",
    "RequestRecord",
    "Response",
    "TLSInfo",
    "decode_body",
]
