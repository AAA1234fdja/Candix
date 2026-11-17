"""Egress governor: noise profiles, token bucket, jitter, concurrency, coalescing, cache.

Ported from engine/egress/egress.go — governs platform-owned HTTP requests (WebFetch,
http custom tools, enrich probe). Default profile off is strict passthrough.
"""

from __future__ import annotations

import os
import random
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable
from urllib.parse import urlparse

MAX_JITTER = 0.25  # seconds
MAX_SHARED_BODY = 2 * 1024 * 1024


@dataclass(frozen=True)
class Profile:
    name: str = "off"
    rps: float = 0.0  # requests per second per host; 0 = off
    burst: int = 0
    max_per_host: int = 0
    max_global: int = 0
    jitter: float = 0.0
    cache_ttl: float = 0.0
    max_retries: int = 0
    base_delay: float = 0.0
    max_delay: float = 0.0
    user_agent: str = ""


PROFILES: dict[str, Profile] = {
    "quiet": Profile(name="quiet", rps=2, burst=4, max_per_host=1, max_global=8, jitter=0.5, cache_ttl=60, max_retries=3, base_delay=2.0, max_delay=60.0),
    "balanced": Profile(name="balanced", rps=5, burst=10, max_per_host=2, max_global=16, jitter=0.2, cache_ttl=30, max_retries=3, base_delay=1.0, max_delay=30.0),
    "aggressive": Profile(name="aggressive", rps=20, burst=40, max_per_host=4, max_global=32, jitter=0.1, cache_ttl=10, max_retries=2, base_delay=0.5, max_delay=10.0),
}


def profile_by_name(name: str) -> tuple[Profile, bool]:
    n = name.strip().lower()
    if n == "off":
        return Profile(name="off"), True
    if n in PROFILES:
        p = PROFILES[n]
        ua = os.getenv("CANDIX_ENGINE_TARGET_USER_AGENT", "").strip()
        if ua and not any(ord(c) < 32 for c in ua):
            p = Profile(**{**p.__dict__, "user_agent": ua})
        return p, True
    return Profile(name="off"), False


def profile_from_env() -> Profile:
    name = os.getenv("CANDIX_ENGINE_NOISE_PROFILE", "").strip()
    p, ok = profile_by_name(name)
    if not ok and name != "":
        import logging as _log
        _log.getLogger(__name__).warning("CANDIX_ENGINE_NOISE_PROFILE=%r is not off/quiet/balanced/aggressive; using off", name)
    return p


def host_key(url: str) -> str:
    try:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        port = parsed.port
        # default ports
        if port is None or (parsed.scheme == "http" and port == 80) or (parsed.scheme == "https" and port == 443):
            return host
        return f"{host}:{port}"
    except Exception:
        return url.lower()


@dataclass
class _HostState:
    tokens: float = 0.0
    last: float = field(default_factory=time.monotonic)
    not_before: float = 0.0
    sent: int = 0
    dupes: int = 0
    inflight: int = 0
    peak_inflight: int = 0
    peak_rpm: int = 0
    sem: threading.Semaphore | None = None
    mu: threading.Lock = field(default_factory=threading.Lock)


@dataclass
class HostNoise:
    host: str
    rpm: int
    peak_rpm: int
    peak_inflight: int
    inflight: int
    duplicates_avoided: int


class Governor:
    """Per-host token bucket + jitter + concurrency + coalescing + short cache."""

    def __init__(self, profile: Profile) -> None:
        self.p = profile
        self._mu = threading.Lock()
        self._hosts: dict[str, _HostState] = {}
        self._flights: dict[str, dict[str, Any]] = {}  # key -> {done: Event, val, err, exp}
        self._global_sem = threading.Semaphore(max(profile.max_global, 1))

    def off(self) -> bool:
        return self.p.rps <= 0

    def profile(self) -> Profile:
        return self.p

    def _host(self, key: str) -> _HostState:
        with self._mu:
            h = self._hosts.get(key)
            if h is None:
                h = _HostState(tokens=float(self.p.burst), last=time.monotonic(), sem=threading.Semaphore(max(self.p.max_per_host, 1)))
                self._hosts[key] = h
            return h

    def jitter_bound(self) -> float:
        if self.p.rps <= 0:
            return 0.0
        return min(self.p.jitter / self.p.rps, MAX_JITTER)

    def jitter(self) -> float:
        b = self.jitter_bound()
        return random.random() * b if b > 0 else 0.0

    def _reserve(self, h: _HostState) -> float:
        with self._mu:
            now = time.monotonic()
            h.tokens = min(float(self.p.burst), h.tokens + (now - h.last) * self.p.rps) - 1
            h.last = now
            wait = max(-h.tokens / self.p.rps, h.not_before - now, 0.0) if self.p.rps > 0 else 0.0
            return wait

    def acquire(self, key: str, timeout: float | None = None) -> Callable[[], None] | None:
        if self.off():
            return lambda: None
        h = self._host(key)
        # per-host slot
        assert h.sem is not None
        if not h.sem.acquire(timeout=timeout):
            return None
        # token + backoff + jitter
        delay = self._reserve(h) + self.jitter()
        if delay > 0:
            time.sleep(delay)
        if not self._global_sem.acquire(timeout=timeout):
            h.sem.release()
            return None
        with self._mu:
            h.sent += 1
            h.inflight += 1
            h.peak_inflight = max(h.peak_inflight, h.inflight)
        released = False
        lock = threading.Lock()

        def release() -> None:
            nonlocal released
            with lock:
                if released:
                    return
                released = True
            with self._mu:
                h.inflight -= 1
            try:
                self._global_sem.release()
            except Exception:
                pass
            try:
                h.sem.release()
            except Exception:
                pass

        return release

    def share(self, host: str, key: str, fn: Callable[[], tuple[Any, float]], cache_ttl: float | None = None) -> Any:
        """Coalesce concurrent callers of key; cache for ttl seconds."""
        ttl = self.p.cache_ttl if cache_ttl is None else cache_ttl
        now = time.monotonic()
        with self._mu:
            f = self._flights.get(key)
            if f is not None and f.get("exp") and now > f["exp"]:
                f = None
            if f is not None:
                # follower
                done: threading.Event = f["done"]
            else:
                # leader
                done = threading.Event()
                f = {"done": done, "val": None, "err": None, "exp": 0.0}
                self._flights[key] = f
                # evict expired
                for k, v in list(self._flights.items()):
                    if v.get("exp") and now > v["exp"]:
                        self._flights.pop(k, None)
        # if we are follower, wait
        if f["done"] is not done:
            done.wait()
            with self._mu:
                if isinstance(f.get("err"), Exception) and f["err"].__class__.__name__ in {"_NotShared"}:
                    # leader said not shareable — run ourselves
                    pass
                else:
                    h = self._hosts.get(host)
                    if h is not None:
                        with self._mu:
                            h.dupes += 1
                    if f.get("err"):
                        raise f["err"]  # type: ignore
                    return f.get("val")
        # leader path
        try:
            val, extra_ttl = fn()
            err = None
        except Exception as exc:
            val, err, extra_ttl = None, exc, 0.0
        with self._mu:
            f["val"], f["err"] = val, err
            if err is None and extra_ttl > 0:
                f["exp"] = time.monotonic() + extra_ttl
            elif self._flights.get(key) is f:
                self._flights.pop(key, None)
            f["done"].set()
        if err is not None:
            raise err
        return val

    def snapshot(self) -> list[HostNoise]:
        with self._mu:
            out: list[HostNoise] = []
            for key, h in sorted(self._hosts.items()):
                if h.sent == 0 and h.dupes == 0 and h.inflight == 0 and h.peak_rpm == 0:
                    continue
                out.append(HostNoise(host=key, rpm=h.sent, peak_rpm=max(h.peak_rpm, h.sent),
                                     peak_inflight=h.peak_inflight, inflight=h.inflight, duplicates_avoided=h.dupes))
            return out

    def report(self) -> list[str]:
        with self._mu:
            out: list[str] = []
            for key, h in sorted(self._hosts.items()):
                if h.sent == 0 and h.dupes == 0:
                    continue
                h.peak_rpm = max(h.peak_rpm, h.sent)
                out.append(f"[egress] noise profile={self.p.name} host={key} rpm={h.sent} peak_rpm={h.peak_rpm} peak_inflight={h.peak_inflight} duplicates_avoided={h.dupes}")
                h.sent, h.dupes, h.peak_inflight = 0, 0, h.inflight
            return out


# Process-wide current governor (SetProfile replaces it; in-flight keeps previous)
_current: Governor | None = None
_current_lock = threading.Lock()
_reporter_started = False


def current_governor() -> Governor:
    global _current, _reporter_started
    if _current is not None:
        return _current
    with _current_lock:
        if _current is None:
            g = Governor(profile_from_env())
            _current = g
            _start_reporter()
    return _current  # type: ignore


def current_profile() -> Profile:
    return current_governor().p


def set_profile(p: Profile) -> Governor:
    global _current
    g = Governor(p)
    with _current_lock:
        _current = g
        _start_reporter()
    return g


def _start_reporter() -> None:
    global _reporter_started
    if _reporter_started:
        return
    _reporter_started = True

    def loop() -> None:
        while True:
            time.sleep(60)
            try:
                for line in current_governor().report():
                    import logging as _log
                    _log.getLogger(__name__).info(line)
            except Exception:
                pass
    t = threading.Thread(target=loop, daemon=True, name="egress-reporter")
    t.start()
