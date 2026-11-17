"""Rate limiting and adaptive throttling.

Static delays waste time on fast targets and still hammer slow ones. Candix
uses a token bucket per host plus an adaptive multiplier: a 429 or 503 with a
``Retry-After`` header slows the host down immediately, and successful requests
slowly recover the rate.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Any


@dataclass
class BucketState:
    tokens: float
    updated: float
    penalty: float = 1.0
    consecutive_errors: int = 0
    retry_after: float = 0.0
    requests: int = 0
    limited: int = 0


class TokenBucket:
    """Single-host token bucket with a dynamic rate."""

    def __init__(self, rate: float, burst: int | None = None) -> None:
        if rate <= 0:
            raise ValueError("rate must be positive")
        self.base_rate = rate
        self.burst = max(1, burst or int(max(1, rate)))
        self.state = BucketState(tokens=float(self.burst), updated=time.monotonic())

    def _refill(self, now: float) -> None:
        elapsed = max(0.0, now - self.state.updated)
        rate = max(0.1, self.base_rate / max(1.0, self.state.penalty))
        self.state.tokens = min(self.burst, self.state.tokens + elapsed * rate)
        self.state.updated = now

    def take(self, tokens: float = 1.0, *, block: bool = True) -> float:
        """Consume tokens, returning the seconds spent waiting."""

        waited = 0.0
        while True:
            now = time.monotonic()
            self._refill(now)
            if self.state.retry_after > now:
                delay = self.state.retry_after - now
                time.sleep(min(delay, 30.0))
                waited += delay
                continue
            if self.state.tokens >= tokens:
                self.state.tokens -= tokens
                self.state.requests += 1
                return waited
            if not block:
                return waited
            rate = max(0.1, self.base_rate / max(1.0, self.state.penalty))
            delay = (tokens - self.state.tokens) / rate
            time.sleep(min(max(delay, 0.001), 5.0))
            waited += delay

    def penalize(self, factor: float = 2.0, *, retry_after: float = 0.0, reason: str = "") -> None:
        self.state.penalty = min(32.0, self.state.penalty * factor)
        self.state.limited += 1
        self.state.consecutive_errors += 1
        self.state.tokens = 0.0
        self.state.updated = time.monotonic()
        if retry_after:
            self.state.retry_after = time.monotonic() + min(retry_after, 120.0)

    def reward(self) -> None:
        self.state.consecutive_errors = 0
        if self.state.penalty > 1.0:
            self.state.penalty = max(1.0, self.state.penalty * 0.95)

    def snapshot(self) -> dict[str, Any]:
        return {
            "rate": self.base_rate,
            "penalty": round(self.state.penalty, 2),
            "requests": self.state.requests,
            "limited": self.state.limited,
            "tokens": round(self.state.tokens, 2),
        }


class HostRateLimiter:
    """Token bucket registry keyed by origin."""

    def __init__(self, rate: float, burst: int | None = None, *, max_hosts: int = 256) -> None:
        self.rate = rate
        self.burst = burst
        self.max_hosts = max_hosts
        self._buckets: dict[str, TokenBucket] = {}
        self._lock = threading.Lock()

    def bucket(self, host: str) -> TokenBucket:
        with self._lock:
            bucket = self._buckets.get(host)
            if bucket is None:
                if len(self._buckets) >= self.max_hosts:
                    oldest = next(iter(self._buckets))
                    self._buckets.pop(oldest, None)
                bucket = TokenBucket(self.rate, self.burst)
                self._buckets[host] = bucket
            return bucket

    def acquire(self, host: str, tokens: float = 1.0) -> float:
        return self.bucket(host).take(tokens)

    def observe(self, host: str, status: int, retry_after: float = 0.0) -> None:
        bucket = self.bucket(host)
        if status == 429:
            bucket.penalize(2.0, retry_after=retry_after or 5.0, reason="429")
        elif status == 503:
            bucket.penalize(1.5, retry_after=retry_after or 3.0, reason="503")
        elif 200 <= status < 400:
            bucket.reward()

    def set_rate(self, rate: float) -> None:
        self.rate = rate
        with self._lock:
            for bucket in self._buckets.values():
                bucket.base_rate = rate

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {host: bucket.snapshot() for host, bucket in self._buckets.items()}

    @property
    def total_requests(self) -> int:
        with self._lock:
            return sum(bucket.state.requests for bucket in self._buckets.values())


class Cooldown:
    """Simple exponential cooldown used between retries."""

    def __init__(self, initial: float = 0.5, *, maximum: float = 20.0, factor: float = 2.0, jitter: float = 0.25) -> None:
        import random

        self.initial = initial
        self.maximum = maximum
        self.factor = factor
        self.jitter = jitter
        self._random = random.Random()

    def delay(self, attempt: int) -> float:
        base = min(self.maximum, self.initial * (self.factor ** max(0, attempt - 1)))
        return base * (1.0 + self._random.random() * self.jitter)


class ConcurrencyGate:
    """Semaphore wrapper with statistics."""

    def __init__(self, limit: int) -> None:
        self.limit = max(1, limit)
        self._semaphore = threading.BoundedSemaphore(self.limit)
        self._active = 0
        self._peak = 0
        self._total = 0
        self._lock = threading.Lock()

    def __enter__(self) -> "ConcurrencyGate":
        self._semaphore.acquire()
        with self._lock:
            self._active += 1
            self._total += 1
            self._peak = max(self._peak, self._active)
        return self

    def __exit__(self, *exc: object) -> None:
        with self._lock:
            self._active -= 1
        self._semaphore.release()

    def snapshot(self) -> dict[str, int]:
        with self._lock:
            return {"limit": self.limit, "active": self._active, "peak": self._peak, "total": self._total}
