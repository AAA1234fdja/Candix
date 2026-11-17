"""Fuzzing run orchestration."""

from __future__ import annotations

import random
import time
from typing import Any, Callable, Iterable, Sequence
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from candix.core.clock import humanize_duration, isoformat
from candix.core.context import ScanContext
from candix.fuzz import analysis
from candix.fuzz.corpus import Corpus
from candix.fuzz.model import FuzzCase, FuzzObservation, FuzzResult, FuzzSignal
from candix.fuzz.mutators import FAMILIES, mutations_for
from candix.fuzz.scheduler import Scheduler
from candix.recon.crawler import Crawler

ProgressCallback = Callable[[str, dict[str, Any]], None]


def _log(progress: ProgressCallback | None, event: str, payload: dict[str, Any]) -> None:
    if progress is None:
        return
    try:
        progress(event, payload)
    except Exception:
        pass


def harvest_targets(
    ctx: ScanContext,
    *,
    max_pages: int = 25,
    wanted_params: Sequence[str] = (),
    on_progress: ProgressCallback | None = None,
) -> list[tuple[Any, Any]]:
    """Crawl the targets and return (endpoint, parameter) pairs worth fuzzing."""

    crawler = Crawler(ctx, max_pages=max_pages)
    crawler.crawl()
    wanted = {name.lower() for name in wanted_params}
    pairs: list[tuple[Any, Any]] = []
    for endpoint in ctx.endpoints:
        for param in endpoint.params:
            if param.location not in {"query", "body", "json", "path"}:
                continue
            if not param.injectable:
                continue
            if wanted and param.name.lower() not in wanted:
                continue
            pairs.append((endpoint, param))
    _log(on_progress, "fuzz_targets", {"pairs": len(pairs), "endpoints": len(ctx.endpoints)})
    return pairs


def _apply_case(endpoint: Any, param: Any, value: str) -> tuple[str, str, dict[str, str] | None, Any]:
    method = (endpoint.method or "GET").upper()
    if param.location == "query" or method in {"GET", "HEAD", "DELETE", "OPTIONS"}:
        parts = urlsplit(endpoint.url)
        query = [(name, current) for name, current in parse_qsl(parts.query, keep_blank_values=True)]
        replaced = [(name, value if name == param.name else current) for name, current in query]
        if not any(name == param.name for name, _ in replaced):
            replaced.append((param.name, value))
        url = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(replaced), parts.fragment))
        return method, url, None, None
    if param.location == "json":
        payload = {}
        for item in endpoint.params:
            payload[item.name] = item.value
        payload[param.name] = value
        return method, endpoint.url, None, payload
    body = {}
    for item in endpoint.params:
        if item.location == "body":
            body[item.name] = item.value
    body[param.name] = value
    return method, endpoint.url, body, None


def _send(ctx: ScanContext, method: str, url: str, data: dict[str, str] | None, json_body: Any, *, tag: str) -> Any:
    return ctx.http.request(method, url, data=data, json_body=json_body, tag=tag)


def _baseline(
    ctx: ScanContext,
    endpoint: Any,
    param: Any,
    *,
    on_progress: ProgressCallback | None = None,
) -> tuple[Any, Any, Any]:
    probe = type(param)(name=param.name, value=param.value or "1", location=param.location, kind=param.kind)
    method, url, data, json_body = _apply_case(endpoint, probe, probe.value)
    response = _send(ctx, method, url, data, json_body, tag="fuzz-baseline")
    control = None
    if param.value != "1":
        try:
            control_method, control_url, control_data, control_json = _apply_case(endpoint, probe, "1")
            control = _send(ctx, control_method, control_url, control_data, control_json, tag="fuzz-control")
        except Exception:
            control = None
    return response, control, probe


def run_fuzz(
    targets: Iterable[str],
    *,
    config: Any,
    engagement: Any,
    iterations: int = 500,
    strategy: str = "balanced",
    seed: int | None = None,
    params: Sequence[str] = (),
    save_corpus: str | None = None,
    stop_on_finding: bool = False,
    on_progress: ProgressCallback | None = None,
    artifacts_dir: str | None = None,
) -> FuzzResult:
    """Run a bounded mutation campaign and return findings plus observations."""

    started_at = isoformat()
    started = time.monotonic()
    chosen_seed = seed if seed is not None else random.randrange(1, 1_000_000)
    rng = random.Random(chosen_seed)
    ctx = ScanContext.create(targets, config=config, engagement=engagement, artifacts_dir=artifacts_dir)
    corpus = Corpus(save_corpus, limit=max(50, iterations // 4))
    scheduler = Scheduler(strategy=strategy, rng=random.Random(chosen_seed ^ 0x5F3759DF))
    pairs = harvest_targets(ctx, max_pages=int(config.get("recon.max_crawl_pages", 25)), wanted_params=params, on_progress=on_progress)
    if not pairs:
        raise RuntimeError("fuzzing needs at least one parameter; the crawl found none")
    if len(pairs) > 120:
        pairs = pairs[:120]
    plans: dict[str, list[Any]] = {}
    seeds_by_key: dict[str, Any] = {}
    for endpoint, param in pairs:
        item = corpus.add_seed(endpoint, param)
        seeds_by_key[item.key] = item
    baselines: dict[str, Any] = {}
    _log(on_progress, "fuzz_baseline_start", {"count": len(pairs)})
    for endpoint, param in pairs:
        key = f"{endpoint.method.upper()} {endpoint.url} {param.location}:{param.name}"
        try:
            response, control, probe = _baseline(ctx, endpoint, param, on_progress=on_progress)
        except Exception:
            continue
        corpus.record_baseline(seeds_by_key[key], status=response.status, length=len(response.content or b""), body=response.text)
        baselines[key] = (response, control, probe, endpoint, param)
        plans[key] = mutations_for(param.value or "1", strategy, rng=rng, limit=max(8, iterations // max(1, len(pairs))))
    if not plans:
        raise RuntimeError("no baseline could be established for the discovered parameters")
    keys = list(plans)
    cases: list[FuzzCase] = []
    observations: list[FuzzObservation] = []
    findings: list[Any] = []
    seen_findings: set[str] = set()
    index = 0
    errors = 0
    _log(on_progress, "fuzz_started", {"iterations": iterations, "parameters": len(keys), "strategy": strategy})
    while index < iterations:
        try:
            ctx.budget.check()
        except Exception:
            ctx.warn("fuzzing stopped by request budget")
            break
        key = keys[index % len(keys)]
        mutations = plans[key]
        if not mutations:
            index += 1
            continue
        family = scheduler.pick()
        candidates = [item for item in mutations if item.family == family] or mutations
        mutation = candidates[(index // len(keys)) % len(candidates)]
        response, control, probe, endpoint, param = baselines[key]
        method, url, data, json_body = _apply_case(endpoint, probe, mutation.value)
        case = FuzzCase(
            index=index,
            method=method,
            url=url,
            parameter=param.name,
            location=param.location,
            original=probe.value,
            value=mutation.value,
            family=mutation.family,
            label=mutation.label,
            strategy=strategy,
        )
        try:
            fuzzed = _send(ctx, method, url, data, json_body, tag="fuzz")
        except Exception as exc:
            errors += 1
            scheduler.penalise(family)
            _log(on_progress, "fuzz_error", {"case": index, "error": str(exc)[:200]})
            index += 1
            continue
        signal = analysis.classify(
            family=mutation.family,
            payload=mutation.value,
            baseline_status=response.status,
            baseline_body=response.text,
            response=fuzzed,
            control=control,
        )
        observation = FuzzObservation(
            case=case,
            status=fuzzed.status,
            length=len(fuzzed.content or b""),
            elapsed=fuzzed.elapsed,
            signal=FuzzSignal(
                family=signal.family,
                kind=signal.kind,
                score=signal.score,
                severity=signal.severity,
                reasons=signal.reasons,
                evidence=signal.evidence,
            ) if signal else None,
            baseline_status=response.status,
            baseline_length=len(response.content or b""),
        )
        cases.append(case)
        observations.append(observation)
        if signal is not None:
            scheduler.reward(mutation.family, signal.score)
            corpus.keep(case.to_dict(), body=fuzzed.text, label=signal.kind)
            if signal.score >= 0.55:
                finding = analysis.signal_to_finding(
                    signal,
                    title_prefix=f"Fuzzing anomaly on {param.name}",
                    url=url,
                    method=method,
                    parameter=param.name,
                    location=param.location,
                    payload=mutation.value,
                )
                dedupe = f"{signal.kind}:{method}:{endpoint.url.split('?')[0]}:{param.name}"
                if dedupe not in seen_findings:
                    seen_findings.add(dedupe)
                    ctx.register_finding(finding)
                    findings.append(finding)
                    _log(on_progress, "fuzz_finding", {"severity": finding.severity.value, "title": finding.title, "url": url})
                    if stop_on_finding:
                        index += 1
                        break
        else:
            scheduler.penalise(mutation.family)
        index += 1
        if index % 25 == 0:
            _log(on_progress, "fuzz_progress", {"done": index, "total": iterations, "signals": len(seen_findings)})
    corpus.save_index()
    finished_at = isoformat()
    duration = time.monotonic() - started
    result = FuzzResult(
        scan_id=ctx.id,
        started_at=started_at,
        finished_at=finished_at,
        duration=duration,
        strategy=strategy,
        seed=chosen_seed,
        iterations=iterations,
        requests=int((ctx.http.snapshot().get("stats") or {}).get("requests", 0)),
        errors=errors,
        cases=cases,
        observations=observations,
        findings=findings,
        corpus_dir=str(corpus.directory or ""),
        stats={
            "parameters": len(keys),
            "mutation_families": {family: sum(1 for case in cases if case.family == family) for family in FAMILIES},
            "signals": analysis.summarise_signals([obs.signal for obs in observations if obs.signal]),
            "scheduler": scheduler.stats(),
            "corpus": corpus.to_dict(),
            "duration_human": humanize_duration(duration),
            "evidence": ctx.evidence.count,
        },
    )
    _log(on_progress, "fuzz_finished", {"findings": len(findings), "signals": len(result.signals)})
    return result
