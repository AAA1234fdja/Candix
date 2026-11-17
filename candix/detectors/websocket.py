"""WebSocket handshake and origin validation."""

from __future__ import annotations

import base64
import os
import re
from typing import Iterable

from candix.core.finding import Finding
from candix.core.severity import Confidence, Severity
from candix.detectors.base import BaseDetector, DetectorMeta, register_detector
from candix.net.url import URL, join_url


@register_detector
class WebSocketDetector(BaseDetector):
    meta = DetectorMeta(
        id="websocket",
        name="WebSocket handshake and origin checks",
        category="websocket",
        description="Discovers WebSocket endpoints and tests whether the upgrade is accepted without authentication or origin validation.",
        severity=Severity.MEDIUM,
        cwe=("CWE-1385",),
        owasp=("A01:2021 Broken Access Control",),
        intrusive=True,
        tags=("websocket",),
        order=190,
        remediation_key="websocket",
    )

    def run(self) -> Iterable[Finding]:
        endpoints: set[str] = set()
        for target in self.ctx.targets:
            try:
                page = self.http.get(target.url, tag="ws-page")
            except Exception:
                continue
            for match in re.finditer(r"""["'](wss?://[^"']+)["']|new\s+WebSocket\(\s*["']([^"']+)["']""", page.text):
                candidate = match.group(1) or match.group(2)
                if candidate:
                    endpoints.add(candidate)
            for path in ("/ws", "/websocket", "/socket", "/socket.io/", "/api/ws"):
                try:
                    endpoints.add(join_url(target.url, path).render().replace("http", "ws", 1))
                except ValueError:
                    continue
        for endpoint in list(endpoints)[:6]:
            if not endpoint.startswith(("ws://", "wss://")):
                continue
            finding = self._check(endpoint)
            if finding is not None:
                yield self.emit(finding)

    def _check(self, endpoint: str) -> Finding | None:
        parsed = URL.parse(endpoint.replace("ws://", "http://", 1).replace("wss://", "https://", 1))
        if self.ctx.scope is not None and not self.ctx.scope.matches(parsed):
            return None
        port = parsed.effective_port or (443 if parsed.scheme == "https" else 80)
        key = base64.b64encode(os.urandom(16)).decode()
        origin = "https://candix-ws-origin.test"
        request = (
            f"GET {parsed.path or '/'} HTTP/1.1\r\n"
            f"Host: {parsed.netloc}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            f"Origin: {origin}\r\n"
            "\r\n"
        ).encode()
        try:
            raw = self.http.send_raw(parsed.host, port, request, timeout=5.0, use_tls=parsed.scheme == "https")
        except Exception:
            return None
        if not raw:
            return None
        head = raw.split(b"\r\n\r\n", 1)[0].decode("latin-1", "replace")
        if "101" not in head.split("\r\n")[0]:
            return None
        if "sec-websocket-accept" not in head.lower():
            return None
        try:
            response = self.http.get(parsed.render(), tag="ws-evidence")
        except Exception:
            response = None
        return self.build_finding(
            title="WebSocket endpoint accepts cross-origin upgrades",
            severity=Severity.MEDIUM,
            url=parsed.render(),
            location="header",
            description=(
                f"The WebSocket endpoint completed a handshake with Origin {origin} and no authentication "
                "material was required during the upgrade."
            ),
            impact=(
                "A malicious site can open an authenticated socket in the victim's browser and read or "
                "send messages if the application relies on cookies without checking Origin."
            ),
            confidence=Confidence.LIKELY,
            cwe=("CWE-1385",),
            tags=("websocket", "origin"),
            evidence=[
                self.capture(response, summary="Handshake evidence", kind="artifact", data={"response_head": head[:2000], "origin": origin})
            ]
            if response is not None
            else [],
            metadata={"origin": origin, "handshake": head[:1000]},
        )
