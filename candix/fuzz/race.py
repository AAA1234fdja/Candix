"""Concurrency testing for race conditions and TOCTOU windows."""

from __future__ import annotations

import threading
import time
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Callable, Sequence


@dataclass
class RaceSample:
    index: int
    status: int
    length: int
    body: str
    elapsed: float
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "status": self.status,
            "length": self.length,
            "elapsed": round(self.elapsed, 4),
            "error": self.error,
            "fingerprint": self.fingerprint,
        }

    @property
    def fingerprint(self) -> str:
        import hashlib

        return hashlib.sha256(f"{self.status}:{self.body[:2048]}".encode("utf-8", "replace")).hexdigest()[:16]


@dataclass
class RaceResult:
    url: str
    method: str
    concurrency: int
    samples: list[RaceSample] = field(default_factory=list)
    distinct_outcomes: int = 0
    success_variants: int = 0
    duration: float = 0.0
    suspect: bool = False
    notes: list[str] = field(default_factory=list)

    def counts(self) -> dict[int, int]:
        return dict(Counter(sample.status for sample in self.samples))

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "method": self.method,
            "concurrency": self.concurrency,
            "samples": [sample.to_dict() for sample in self.samples],
            "distinct_outcomes": self.distinct_outcomes,
            "success_variants": self.success_variants,
            "duration": round(self.duration, 3),
            "suspect": self.suspect,
            "notes": list(self.notes),
            "statuses": self.counts(),
        }

    def summary(self) -> str:
        return (
            f"{self.method} {self.url}: {len(self.samples)} requests, "
            f"{self.distinct_outcomes} distinct outcomes, suspect={self.suspect}"
        )


def run_race(
    request: Callable[[], Any],
    *,
    url: str = "",
    method: str = "POST",
    concurrency: int = 10,
    barrier_timeout: float = 5.0,
) -> RaceResult:
    """Fire ``request`` simultaneously from several threads and compare outcomes."""

    result = RaceResult(url=url, method=method.upper(), concurrency=concurrency)
    barrier = threading.Barrier(concurrency, timeout=barrier_timeout)
    samples: list[RaceSample] = []
    lock = threading.Lock()

    def worker(index: int) -> None:
        started = time.monotonic()
        try:
            barrier.wait()
        except threading.BrokenBarrierError:
            pass
        try:
            response = request()
            sample = RaceSample(
                index=index,
                status=int(getattr(response, "status", 0) or 0),
                length=len(getattr(response, "content", b"") or b""),
                body=str(getattr(response, "text", "") or ""),
                elapsed=time.monotonic() - started,
            )
        except Exception as exc:
            sample = RaceSample(index=index, status=0, length=0, body="", elapsed=time.monotonic() - started, error=str(exc))
        with lock:
            samples.append(sample)

    started = time.monotonic()
    threads = [threading.Thread(target=worker, args=(index,), daemon=True) for index in range(max(2, concurrency))]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=barrier_timeout + 30)
    result.duration = time.monotonic() - started
    result.samples = sorted(samples, key=lambda sample: sample.index)
    fingerprints = {sample.fingerprint for sample in result.samples if not sample.error}
    result.distinct_outcomes = len(fingerprints)
    successes = [sample for sample in result.samples if 200 <= sample.status < 300]
    result.success_variants = len({sample.fingerprint for sample in successes})
    if result.distinct_outcomes > 1 and result.success_variants > 1:
        result.suspect = True
        result.notes.append("concurrent requests produced different successful responses")
    if any(sample.status == 0 for sample in result.samples):
        result.notes.append("some requests failed entirely; retry with lower concurrency")
    if result.suspect:
        result.notes.append("verify the business invariant (balance, coupon, quota) before reporting")
    return result


def compare_sequential(request: Callable[[], Any], *, repeats: int = 3) -> list[Any]:
    responses = []
    for _ in range(max(1, repeats)):
        try:
            responses.append(request())
        except Exception as exc:
            responses.append(exc)
    return responses


def stable_outcomes(responses: Sequence[Any]) -> bool:
    fingerprints = set()
    for response in responses:
        if isinstance(response, Exception):
            fingerprints.add(f"error:{response}")
            continue
        body = str(getattr(response, "text", "") or "")
        fingerprints.add(f"{getattr(response, 'status', 0)}:{body[:512]}")
    return len(fingerprints) <= 1
