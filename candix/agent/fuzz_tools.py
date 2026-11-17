"""Bounded fuzzing from inside the agent loop."""

from __future__ import annotations

import time
from typing import Any

from candix.core.log import get_logger

log = get_logger("candix.agent.fuzz")


def _engagement(ctx: Any) -> Any:
    scan = ctx.state.get("scan")
    return getattr(scan, "engagement", None) if scan is not None else None


def tool_fuzz_run(ctx: Any, arguments: dict[str, Any]) -> dict[str, Any]:
    scan = ctx.state.get("scan")
    if scan is None:
        raise ValueError("fuzzing needs the scan context")
    engagement = _engagement(ctx)
    if engagement is None:
        raise ValueError("fuzzing needs an engagement document")
    iterations = max(10, min(400, int(arguments.get("iterations", 80))))
    strategy = str(arguments.get("strategy", "balanced"))
    params = [str(item) for item in arguments.get("params") or []][:8]
    targets = [str(item) for item in arguments.get("targets") or []] or list(getattr(scan, "targets", []) or [])
    target_urls = [getattr(target, "url", str(target)) for target in targets]

    from candix.fuzz.runner import run_fuzz

    started = time.monotonic()
    result = run_fuzz(
        target_urls,
        config=scan.config,
        engagement=engagement,
        iterations=iterations,
        strategy=strategy,
        params=tuple(params),
        stop_on_finding=bool(arguments.get("stop_on_finding", False)),
    )
    elapsed = time.monotonic() - started
    findings = []
    for finding in result.findings:
        payload = finding.to_dict() if hasattr(finding, "to_dict") else {"title": str(finding)}
        payload.setdefault("category", "fuzz")
        findings.append(payload)
    signals = [signal.kind for signal in result.signals][:40]
    ctx.telemetry.increment("fuzz.runs")
    ctx.telemetry.observe("fuzz.seconds", elapsed)
    ctx.telemetry.increment("fuzz.requests", result.requests)
    return {
        "summary": (
            f"{iterations} iteration(s) in {elapsed:.1f}s: {result.requests} request(s), "
            f"{len(findings)} finding(s), {len(signals)} signal(s)"
        ),
        "requests": result.requests,
        "errors": result.errors,
        "signals": signals,
        "counts": result.counts() if hasattr(result, "counts") else {},
        "findings": findings,
    }
