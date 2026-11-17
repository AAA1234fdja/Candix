"""WebSocket exposure: origin checks, authentication and protocol upgrades."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from candix.core.log import get_logger
from candix.net.websocket import WebSocketError, probe

log = get_logger("candix.agent.ws")

DEFAULT_PATHS = ("/ws", "/websocket", "/socket", "/socket.io/", "/graphql", "/live", "/notifications")

ATTACKER_ORIGINS = ("https://evil.example", "http://localhost", "null")


@dataclass
class Attempt:
    url: str
    origin: str
    ok: bool = False
    status: int = 0
    accepted: bool = False
    error: str = ""
    frames: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "origin": self.origin,
            "ok": self.ok,
            "status": self.status,
            "accepted": self.accepted,
            "frames": self.frames,
            "error": self.error,
        }


@dataclass
class Result:
    attempts: list[Attempt] = field(default_factory=list)
    endpoint: str = ""

    @property
    def reachable(self) -> bool:
        return any(attempt.ok for attempt in self.attempts)

    @property
    def origin_vulnerable(self) -> bool:
        return any(attempt.ok and attempt.origin in ATTACKER_ORIGINS for attempt in self.attempts)

    def summary(self) -> str:
        if not self.attempts:
            return "no websocket endpoint answered"
        state = "reachable" if self.reachable else "closed"
        origin = ", origin check missing" if self.origin_vulnerable else ""
        return f"{len(self.attempts)} attempt(s), {state}{origin}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "endpoint": self.endpoint,
            "reachable": self.reachable,
            "origin_vulnerable": self.origin_vulnerable,
            "attempts": [attempt.to_dict() for attempt in self.attempts],
        }


def ws_url(base: str) -> str:
    parts = urlsplit(base)
    scheme = "wss" if parts.scheme == "https" else "ws"
    return urlunsplit((scheme, parts.netloc, parts.path, parts.query, ""))


def check(ctx: Any, base: str, *, paths: tuple[str, ...] = DEFAULT_PATHS, timeout: float = 4.0) -> Result:
    result = Result()
    root = base.rstrip("/")
    for path in paths:
        candidate = ws_url(root + path)
        try:
            ctx.guard.enforce(root + path, method="GET")
        except Exception:
            continue
        try:
            info = probe(candidate, timeout=timeout)
        except (WebSocketError, OSError) as error:
            result.attempts.append(Attempt(candidate, "", error=str(error)[:160]))
            continue
        except Exception as error:  # a closed port is not a finding
            result.attempts.append(Attempt(candidate, "", error=str(error)[:160]))
            continue
        status = int(info.get("status", 0) or 0)
        accepted = bool(info.get("accepted", status == 101))
        attempt = Attempt(candidate, "", ok=accepted, status=status, accepted=accepted, frames=int(info.get("frames", 0) or 0))
        result.attempts.append(attempt)
        if not accepted:
            continue
        result.endpoint = candidate
        for origin in ATTACKER_ORIGINS:
            try:
                hostile = probe(candidate, origin=origin, timeout=timeout)
            except Exception as error:
                result.attempts.append(Attempt(candidate, origin, error=str(error)[:160]))
                continue
            hostile_status = int(hostile.get("status", 0) or 0)
            result.attempts.append(
                Attempt(
                    candidate,
                    origin,
                    ok=bool(hostile.get("accepted", hostile_status == 101)),
                    status=hostile_status,
                    accepted=bool(hostile.get("accepted", hostile_status == 101)),
                )
            )
        ctx.telemetry.increment("ws.endpoints")
        break
    return result


def findings_for(result: Result) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    if result.origin_vulnerable and result.endpoint:
        findings.append(
            {
                "title": "WebSocket accepts cross-origin handshakes",
                "severity": "medium",
                "category": "websocket",
                "detector": "agent.websocket",
                "url": result.endpoint.replace("wss://", "https://").replace("ws://", "http://"),
                "description": "The handshake succeeded with an Origin header the application does not own.",
                "impact": "A malicious page can open a socket with the victim's cookies and read or send messages.",
                "remediation": "Validate the Origin header during the handshake and require a per-connection token.",
                "confidence": "confirmed",
                "verified": True,
                "tags": ["websocket", "cors"],
            }
        )
    unauthenticated = [attempt for attempt in result.attempts if attempt.accepted and not attempt.origin]
    if result.endpoint and unauthenticated:
        findings.append(
            {
                "title": "WebSocket endpoint accepts unauthenticated connections",
                "severity": "low",
                "category": "websocket",
                "detector": "agent.websocket",
                "url": result.endpoint.replace("wss://", "https://").replace("ws://", "http://"),
                "description": "The handshake completed without credentials.",
                "impact": "Depends on the messages the socket accepts; verify authorization per message.",
                "remediation": "Require authentication during the handshake and authorize every message.",
                "confidence": "observed",
                "verified": False,
                "tags": ["websocket", "authentication"],
            }
        )
    return findings


def tool_ws_probe(ctx: Any, arguments: dict[str, Any]) -> dict[str, Any]:
    base = str(arguments.get("url", "")).rstrip("/")
    if not base:
        targets = list(ctx.state.get("targets") or [])
        base = targets[0] if targets else ""
    result = check(ctx, base, timeout=float(arguments.get("timeout", 4.0)))
    assets = ctx.state.get("assets")
    if assets is not None and result.endpoint:
        try:
            assets.add_endpoint("GET", result.endpoint.replace("ws://", "http://").replace("wss://", "https://"), source="websocket")
        except Exception:
            pass
    return {"summary": result.summary(), "result": result.to_dict(), "findings": findings_for(result)}
