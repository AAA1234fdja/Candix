"""Enrich adapter — engine/enrich asset auto-completion en Python.

Resuelve DNS y hace probe HTTP de assets, espejo de engine/enrich/enrich.go
pero usando stdlib + httpx en lugar de dnsx/go-mitmproxy.
"""

from __future__ import annotations

import asyncio
import re
import socket
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

try:
    import httpx  # type: ignore
    HAS_HTTPX = True
except ImportError:
    httpx = None  # type: ignore
    HAS_HTTPX = False


@dataclass
class EnrichJob:
    kind: str  # dns|http
    asset_id: int
    arg: str  # host or URL
    enqueued_at: float = field(default_factory=time.time)


class EnrichEngine:
    """Worker pool que enriquece assets — DNS resolve + HTTP probe."""

    def __init__(self, workers: int = 4, proxy: str = "", timeout: float = 12.0):
        self.workers = max(1, workers)
        self.proxy = proxy
        self.timeout = timeout
        self._queue: asyncio.Queue[EnrichJob] = asyncio.Queue(maxsize=1024)
        self._cooldown: dict[str, float] = {}
        self._results: list[dict[str, Any]] = []
        self._running = False

    async def start(self) -> None:
        self._running = True
        for _ in range(self.workers):
            asyncio.create_task(self._worker())

    async def stop(self) -> None:
        self._running = False

    def resolve_domain(self, asset_id: int, host: str) -> None:
        try:
            self._queue.put_nowait(EnrichJob("dns", asset_id, host))
        except asyncio.QueueFull:
            pass

    def probe_site(self, asset_id: int, url: str) -> None:
        try:
            self._queue.put_nowait(EnrichJob("http", asset_id, url))
        except asyncio.QueueFull:
            pass

    # sync wrappers for non-async callers
    def resolve_domain_sync(self, asset_id: int, host: str) -> dict[str, Any]:
        return self._do_dns(asset_id, host)

    def probe_site_sync(self, asset_id: int, url: str) -> dict[str, Any]:
        return self._do_http(asset_id, url)

    async def _worker(self) -> None:
        while self._running:
            try:
                job = await asyncio.wait_for(self._queue.get(), timeout=1.0)
            except asyncio.TimeoutError:
                continue
            key = f"{job.kind}:{job.asset_id}"
            last = self._cooldown.get(key, 0)
            if time.time() - last < 300:  # 5 min cooldown
                continue
            self._cooldown[key] = time.time()
            if job.kind == "dns":
                self._do_dns(job.asset_id, job.arg)
            else:
                self._do_http(job.asset_id, job.arg)

    def _do_dns(self, asset_id: int, host: str) -> dict[str, Any]:
        result: dict[str, Any] = {"asset_id": asset_id, "host": host, "ips": [], "cnames": []}
        try:
            infos = socket.getaddrinfo(host, None)
            ips = sorted({info[4][0] for info in infos})
            result["ips"] = ips
        except Exception:
            pass
        self._results.append(result)
        return result

    def _do_http(self, asset_id: int, url: str) -> dict[str, Any]:
        host = urlparse(url).hostname or ""
        result: dict[str, Any] = {"asset_id": asset_id, "url": url, "host": host, "status": 0, "title": "", "length": 0}
        if not HAS_HTTPX:
            # fallback stdlib
            try:
                import urllib.request
                with urllib.request.urlopen(url, timeout=self.timeout) as resp:  # type: ignore
                    body = resp.read(1 << 20)
                    result["status"] = resp.status
                    result["length"] = len(body)
                    m = re.search(rb"<title[^>]*>(.*?)</title>", body, re.I | re.S)
                    if m:
                        result["title"] = m.group(1).decode(errors="replace").strip()
            except Exception:
                pass
        else:
            try:
                with httpx.Client(timeout=self.timeout, verify=False, follow_redirects=False) as client:  # type: ignore
                    proxies = self.proxy or None
                    # httpx mounts proxy via transport - simplified
                    resp = client.get(url)
                    result["status"] = resp.status_code
                    result["length"] = len(resp.content)
                    m = re.search(rb"<title[^>]*>(.*?)</title>", resp.content, re.I | re.S)
                    if m:
                        result["title"] = m.group(1).decode(errors="replace").strip()
            except Exception:
                pass
        self._results.append(result)
        return result

    def results(self) -> list[dict[str, Any]]:
        return list(self._results)

    def close(self) -> None:
        self._running = False
