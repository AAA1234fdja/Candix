"""Implementations of the Candix subcommands."""

from __future__ import annotations

import json
import os
import shlex
import shutil
import socket
import sys
import time
import webbrowser
from pathlib import Path
from typing import Any, Sequence

from candix import VERSION, AUTHORIZATION_NOTICE
from candix.cli import output as out
from candix.cli.args import parse_headers, parse_overrides, split_csv
from candix.cli.progress import ScanProgress, Spinner
from candix.core.clock import humanize_duration
from candix.core.config import PROFILES, Config
from candix.core.context import ScanOptions
from candix.core.errors import AuthorizationError, CandixError, ConfigError
from candix.core.log import configure as configure_logging
from candix.core.scope import Engagement, build_authorization, write_engagement
from candix.core.severity import Severity

EXIT_OK = 0
EXIT_FINDINGS = 10
EXIT_ERROR = 1
EXIT_USAGE = 2


def echo(text: str = "") -> None:
    sys.stdout.write(text + "\n")


def load_config(args: Any) -> Config:
    overrides = parse_overrides(getattr(args, "overrides", []) or [])
    config = Config.load(
        getattr(args, "config", None),
        profile=getattr(args, "profile", None),
        overrides=overrides or None,
    )
    _apply_cli_controls(config, args)
    configure_logging(
        level="debug" if getattr(args, "log_level", "info") == "debug" or getattr(args, "verbose", False) else getattr(args, "log_level", "info"),
        log_file=getattr(args, "log_file", None),
        jsonl=bool(getattr(args, "json_log", False)),
        quiet=bool(getattr(args, "quiet", False)) or bool(getattr(args, "json_output", False)),
    )
    return config


def _apply_cli_controls(config: Config, args: Any) -> None:
    mappings = {
        "max_rps": "scan.max_rps",
        "concurrency": "scan.concurrency",
        "max_pages": "recon.max_crawl_pages",
        "max_endpoints": "scan.max_endpoints",
        "timeout": "http.timeout",
    }
    for attribute, key in mappings.items():
        value = getattr(args, attribute, None)
        if value is not None:
            config.set(key, value)
    if getattr(args, "header", None):
        headers = dict(config.get("http.headers") or {})
        headers.update(parse_headers(args.header))
        config.set("http.headers", headers)
    if getattr(args, "cookie", ""):
        config.set("http.cookies", args.cookie)
    if getattr(args, "proxy", ""):
        config.set("http.proxy", args.proxy)
    if getattr(args, "insecure", False):
        config.set("http.verify_tls", False)
    if getattr(args, "no_intrusive", False):
        config.set("detect.intrusive", False)
    if getattr(args, "no_subdomains", False):
        config.set("scan.include_subdomains", False)
    if getattr(args, "max_proofs", None) is not None:
        config.set("exploit.max_proofs", args.max_proofs)
    if getattr(args, "min_severity", None):
        config.set("detect.min_severity", args.min_severity)
        config.set("report.min_severity", args.min_severity)
    config.validate()


def load_engagement(args: Any, targets: Sequence[str], *, allow_exploit: bool) -> Engagement:
    path = getattr(args, "engagement", None)
    if path:
        engagement = Engagement.load(path)
        for target in targets:
            if not engagement.scope.matches(target):
                raise AuthorizationError(
                    f"{target} is outside the scope of {path}",
                    scope=[entry.text for entry in engagement.scope.include],
                )
        if allow_exploit and not engagement.scope.allow_exploit:
            raise AuthorizationError(
                "the authorization document does not permit exploitation",
                hint="re-issue it with --allow-exploit after approval",
            )
        return engagement
    operator = getattr(args, "authorized", None)
    if operator:
        document = build_authorization(
            engagement=f"adhoc-{int(time.time())}",
            client="self-declared",
            operator=operator,
            authorized_by=getattr(args, "authorized_by", "self"),
            include=[_scope_text(target) for target in targets],
            allow_exploit=allow_exploit or bool(getattr(args, "allow_exploit", False)),
            allow_intrusive=not getattr(args, "no_intrusive", False),
            max_rps=float(getattr(args, "max_rps", None) or 5.0),
        )
        return Engagement.from_document(document)
    raise AuthorizationError(
        "no authorization document supplied",
        hint="use --engagement FILE or --authorized OPERATOR for assets you own",
        notice=AUTHORIZATION_NOTICE.strip().splitlines()[0],
    )


def _scope_text(target: str) -> str:
    from candix.net.url import URL

    try:
        url = URL.parse(target if "://" in target else f"http://{target}")
    except ValueError:
        return target
    return f"{url.host}:{url.port or (443 if url.scheme == 'https' else 80)}"


def _build_options(args: Any, *, exploit: bool) -> ScanOptions:
    options = ScanOptions()
    options.detectors = split_csv(getattr(args, "detectors", ""))
    options.exclude_detectors = split_csv(getattr(args, "exclude_detectors", ""))
    options.categories = split_csv(getattr(args, "categories", ""))
    if getattr(args, "min_severity", None):
        options.min_severity = Severity.parse(args.min_severity)
    options.intrusive = not getattr(args, "no_intrusive", False)
    options.exploit = exploit
    options.max_endpoints = int(getattr(args, "max_endpoints", None) or 2000)
    options.verbose = bool(getattr(args, "verbose", False))
    options.no_evidence = False
    return options


def _summarise(result: Any, *, json_output: bool) -> None:
    summary = result.summary()
    counts = summary.get("findings") or {}
    if json_output:
        out.print_json({"summary": summary, "findings": [f.to_dict(include_evidence=False) for f in result.findings.sorted()]})
        return
    echo("")
    echo(out.rule("results"))
    rows = [
        ("targets", ", ".join(target.base_url for target in result.context.targets)),
        ("profile", summary.get("profile", "")),
        ("duration", humanize_duration(result.duration)),
        ("endpoints", summary.get("endpoint_stats", {}).get("total", 0)),
        ("evidence", result.context.evidence.count),
        ("risk score", f"{summary.get('risk_score', 0):.1f}"),
        ("findings", out.counts_bar(counts)),
    ]
    echo(out.kv_table(rows, indent=2))
    findings = result.findings.sorted()
    if findings:
        echo("")
        echo(out.table(
            ["SEVERITY", "TITLE", "ENDPOINT", "VERIFIED"],
            [
                [finding.severity.value, finding.title, f"{finding.method} {finding.url}", "yes" if finding.verified else "no"]
                for finding in findings[:40]
            ],
        ))
        if len(findings) > 40:
            echo(out.paint(f"  … {len(findings) - 40} more findings in the report", "grey"))
    warnings = summary.get("warnings") or []
    if warnings:
        echo("")
        for warning in warnings[:5]:
            echo(f"  {out.paint('warning', 'yellow')} {warning}")


def _write_reports(result: Any, args: Any, *, scan_id: str) -> dict[str, Any] | None:
    from candix.report import build_report

    formats = getattr(args, "formats", "") or ""
    if getattr(args, "no_report", False) or not formats:
        return None
    outdir = getattr(args, "out", None) or str(Path("reports") / scan_id)
    with Spinner("rendering reports"):
        bundle = build_report(
            result,
            outdir=outdir,
            formats=formats,
            min_severity=getattr(args, "min_severity", None) or Severity.INFO,
            include_evidence=True,
            archive=bool(getattr(args, "archive", False)),
        )
    if getattr(args, "json_output", False):
        return bundle.to_dict()
    echo("")
    echo(out.rule("reports"))
    rows = [(artifact.format, f"{artifact.path}  ({out.format_bytes(artifact.size)})") for artifact in bundle.artifacts]
    echo(out.kv_table(rows, indent=2))
    if bundle.archive_path:
        echo(out.kv_table([("archive", str(bundle.archive_path))], indent=2))
    echo(out.kv_table([("manifest", str(bundle.manifest_path))], indent=2))
    return bundle.to_dict()


def cmd_scan(args: Any) -> int:
    from candix.engine import scan

    config = load_config(args)
    targets = list(args.targets)
    engagement = load_engagement(args, targets, allow_exploit=bool(args.exploit))
    options = _build_options(args, exploit=bool(args.exploit))
    progress = ScanProgress(verbose=bool(args.verbose), quiet=bool(args.quiet or args.json_output))
    if not args.quiet and not args.json_output:
        echo(out.banner(VERSION, subtitle="authorized assessment"))
        echo("")
        echo(out.kv_table([
            ("targets", ", ".join(targets)),
            ("policy", engagement.authorization.engagement),
            ("exploit", "enabled" if args.exploit else "disabled"),
            ("profile", config.get("profile")),
        ], indent=2))
    started = time.monotonic()
    result = scan(
        targets,
        config=config,
        engagement=engagement,
        options=options,
        artifacts_dir=getattr(args, "artifacts", None),
        crawl=not args.no_crawl,
        discover=not args.no_discover,
        exploit=bool(args.exploit),
        on_progress=progress.handle,
    )
    elapsed = time.monotonic() - started
    _summarise(result, json_output=bool(args.json_output))
    reports = _write_reports(result, args, scan_id=result.context.id)
    _emit_findings_event(result)
    if not args.json_output:
        echo("")
        echo(f"  {out.paint('scan complete', 'green')} in {humanize_duration(elapsed)}")
        if reports:
            echo(f"  {out.paint('report', 'grey')} {out.paint(reports['artifacts'][0]['path'], 'cyan')}")
    threshold = getattr(args, "fail_on", "none")
    if threshold and threshold != "none":
        limit = Severity.parse(threshold)
        if any(finding.severity.rank >= limit.rank for finding in result.findings):
            return EXIT_FINDINGS
    return EXIT_OK


def _emit_findings_event(result: Any) -> None:
    for finding in result.findings.sorted()[:10]:
        sys.stdout.write("")


def cmd_exploit(args: Any) -> int:
    from candix.engine import scan

    config = load_config(args)
    targets = list(args.targets)
    engagement = load_engagement(args, targets, allow_exploit=True)
    if not engagement.scope.allow_exploit:
        raise AuthorizationError("exploitation is not permitted by this engagement")
    config.set("exploit.enabled", True)
    if getattr(args, "max_proofs", None) is not None:
        config.set("exploit.max_proofs", args.max_proofs)
    techniques = split_csv(getattr(args, "techniques", ""))
    if techniques:
        config.set("exploit.techniques", techniques)
    options = _build_options(args, exploit=True)
    progress = ScanProgress(verbose=bool(args.verbose), quiet=bool(args.quiet or args.json_output))
    if not args.quiet and not args.json_output:
        echo(out.banner(VERSION, subtitle="exploitation run"))
        echo("")
        echo(out.paint("  Only permitted techniques are attempted; every proof is stored as evidence.", "grey"))
    result = scan(
        targets,
        config=config,
        engagement=engagement,
        options=options,
        artifacts_dir=getattr(args, "output_dir", None),
        crawl=not args.no_crawl,
        discover=not args.no_discover,
        exploit=True,
        on_progress=progress.handle,
    )
    _summarise(result, json_output=bool(args.json_output))
    proofs = _proof_section(result)
    if getattr(args, "formats", ""):
        (args.__dict__.__setitem__("formats", args.formats))
        _write_reports(result, args, scan_id=result.context.id)
    if proofs and not args.json_output:
        echo("")
        echo(out.rule("proofs"))
        for proof in proofs:
            echo(out.box(
                [
                    f"{out.paint('technique', 'grey')} {proof.get('technique')}",
                    f"{out.paint('target', 'grey')}    {proof.get('url', proof.get('endpoint', ''))}",
                    f"{out.paint('impact', 'grey')}    {proof.get('impact', 'demonstrated')}",
                ],
                title=str(proof.get("title") or "proof")[:60],
                color="green",
            ))
    return EXIT_OK


def _proof_section(result: Any) -> list[dict[str, Any]]:
    proofs = getattr(result.context, "metadata", {}).get("proofs", []) or []
    if proofs and not any(isinstance(item, dict) for item in proofs):
        proofs = [proof.to_dict() if hasattr(proof, "to_dict") else {"title": str(proof)} for proof in proofs]
    if proofs:
        return proofs
    return [
        {
            "title": finding.title,
            "technique": finding.metadata.get("technique", finding.detector),
            "url": finding.url,
            "impact": finding.impact,
        }
        for finding in result.findings.sorted()
        if finding.exploited
    ]


def cmd_report(args: Any) -> int:
    from candix.report.builder import parse_formats
    from candix.report.model import ReportModel, select_min_severity
    from candix.report.builder import ReportBuilder

    inputs = [Path(item) for item in args.inputs]
    for path in inputs:
        if not path.exists():
            raise CandixError(f"report input not found: {path}")
    written: list[dict[str, Any]] = []
    for path in inputs:
        payload = json.loads(path.read_text(encoding="utf-8"))
        model = ReportModel.from_snapshot(payload, min_severity=select_min_severity(args.min_severity))
        if args.title:
            model.title = args.title
        builder = ReportBuilder(model, include_evidence=not args.no_evidence)
        bundle = builder.write(
            args.out,
            parse_formats(args.formats),
            archive=args.archive,
        )
        written.append(bundle.to_dict())
    if len(inputs) == 2 and args.compare:
        from candix.report.compare import compare_snapshots, render_comparison_markdown

        comparison = compare_snapshots(
            json.loads(inputs[0].read_text(encoding="utf-8")),
            json.loads(inputs[1].read_text(encoding="utf-8")),
        )
        document = render_comparison_markdown(comparison)
        target = Path(args.out) / "comparison.md"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(document, encoding="utf-8")
        if not args.json_output:
            echo(document)
            echo(out.kv_table([("written", str(target))], indent=2))
    if args.json_output:
        out.print_json({"bundles": written})
        return EXIT_OK
    for bundle in written:
        echo(out.rule(Path(bundle["artifacts"][0]["path"]).stem))
        echo(out.kv_table([(item["format"], item["path"]) for item in bundle["artifacts"]], indent=2))
    return EXIT_OK


def cmd_authorize(args: Any) -> int:
    document = build_authorization(
        engagement=args.engagement,
        client=args.client,
        operator=args.operator,
        authorized_by=args.authorized_by,
        include=args.include,
        exclude=args.exclude,
        expires_in_days=args.expires_in_days,
        allow_exploit=args.allow_exploit,
        allow_intrusive=not args.no_intrusive,
        max_rps=args.max_rps,
    )
    if args.contact:
        document["authorization"]["contact"] = args.contact
    if args.reference:
        document["authorization"]["reference"] = args.reference
    path = Path(args.out or Path("engagements") / f"{args.engagement}.json")
    write_engagement(path, document)
    if args.json_output:
        out.print_json({"path": str(path), "document": document})
        return EXIT_OK
    echo(out.rule("authorization written"))
    echo(out.kv_table([
        ("file", str(path)),
        ("engagement", args.engagement),
        ("client", args.client),
        ("approved by", args.authorized_by),
        ("in scope", ", ".join(args.include)),
        ("excluded", ", ".join(args.exclude) or "none"),
        ("exploitation", "permitted" if args.allow_exploit else "not permitted"),
        ("valid for", f"{args.expires_in_days} days"),
    ], indent=2))
    echo("")
    echo(out.paint("  Share this file with the scan operator; it is the only thing that unlocks active testing.", "grey"))
    return EXIT_OK


def cmd_detectors(args: Any) -> int:
    from candix.detectors.base import detector_catalog, summarize_detectors

    catalog = detector_catalog()
    if args.category:
        catalog = [item for item in catalog if item["category"] == args.category]
    if args.json_output:
        out.print_json({"summary": summarize_detectors(), "detectors": catalog})
        return EXIT_OK
    summary = summarize_detectors()
    echo(out.rule("detectors"))
    echo(out.kv_table([
        ("total", summary.get("total", len(catalog))),
        ("categories", ", ".join(f"{name} ({count})" for name, count in (summary.get("categories") or {}).items())),
    ], indent=2))
    echo("")
    rows = []
    for item in sorted(catalog, key=lambda entry: (entry["category"], entry["id"])):
        rows.append([
            item["id"],
            item["category"],
            item["severity"],
            "yes" if item.get("intrusive") else "no",
            ", ".join(item.get("cwe", [])[:2]),
        ])
    echo(out.table(["ID", "CATEGORY", "SEVERITY", "INTRUSIVE", "CWE"], rows))
    if args.verbose:
        echo("")
        for item in sorted(catalog, key=lambda entry: entry["id"]):
            echo(f"  {out.paint(item['id'], 'cyan', bold=True)} — {item['name']}")
            echo(out.wrap(item.get("description", ""), indent="    "))
    return EXIT_OK


def cmd_payloads(args: Any) -> int:
    from candix.catalog.payloads import families, get_payloads, payload_count

    names = families()
    if args.json_output:
        payload: dict[str, Any] = {"families": names, "count": payload_count()}
        if args.family:
            payload["payloads"] = get_payloads(args.family)[: args.limit]
        out.print_json(payload)
        return EXIT_OK
    echo(out.rule("payload catalogue"))
    echo(out.kv_table([("families", len(names)), ("payloads", payload_count())], indent=2))
    if not args.family:
        echo("")
        echo(out.table(["FAMILY", "PAYLOADS"], [[name, len(get_payloads(name))] for name in names]))
        echo("")
        echo(out.paint("  candix payloads <family> --limit 10", "grey"))
        return EXIT_OK
    if args.family not in names:
        raise ConfigError(f"unknown payload family: {args.family}", available=", ".join(names))
    echo("")
    for index, payload in enumerate(get_payloads(args.family)[: args.limit], start=1):
        echo(f"  {index:>3}. {payload}")
    return EXIT_OK


def cmd_lab(args: Any) -> int:
    from candix.lab import build_server
    from candix.engine import scan

    server = build_server(args.host, args.port)
    server.start()
    base = server.base_url
    echo(out.rule("lab running"))
    echo(out.kv_table([("url", base), ("host", args.host), ("port", str(server.port))], indent=2))
    echo(out.paint("  This application is intentionally vulnerable. It binds to loopback only.", "yellow"))
    try:
        if args.scan:
            echo("")
            config = load_config(args)
            config.set("scan.max_rps", max(200.0, float(config.get("scan.max_rps") or 0)))
            config.set("exploit.enabled", True)
            config.set("exploit.max_proofs", args.max_proofs)
            document = build_authorization(
                engagement="lab",
                client="candix",
                operator="candix-cli",
                authorized_by="candix-cli",
                include=[f"{args.host}:{server.port}"],
                allow_exploit=True,
                max_rps=200.0,
            )
            engagement = Engagement.from_document(document)
            progress = ScanProgress(verbose=bool(getattr(args, "verbose", False)), quiet=bool(getattr(args, "quiet", False)))
            result = scan([base], config=config, engagement=engagement, exploit=True, on_progress=progress.handle)
            _summarise(result, json_output=bool(getattr(args, "json_output", False)))
            args.__dict__["formats"] = args.formats
            _write_reports(result, args, scan_id=result.context.id)
        if args.serve:
            echo("")
            echo(out.paint("  serving until interrupted (Ctrl-C)", "grey"))
            while True:
                time.sleep(0.5)
    except KeyboardInterrupt:
        echo("")
        echo(out.paint("  stopping lab", "grey"))
    finally:
        server.stop()
    return EXIT_OK


def cmd_fuzz(args: Any) -> int:
    from candix.fuzz.runner import run_fuzz
    from candix.fuzz.report import render_fuzz_summary

    config = load_config(args)
    engagement = load_engagement(args, list(args.targets), allow_exploit=False)
    result = run_fuzz(
        list(args.targets),
        config=config,
        engagement=engagement,
        iterations=args.iterations,
        strategy=args.strategy,
        seed=args.seed,
        params=split_csv(",".join(args.param)),
        save_corpus=args.save_corpus,
        stop_on_finding=args.stop_on_finding,
    )
    if args.json_output:
        out.print_json(result.to_dict())
        return EXIT_OK
    echo(render_fuzz_summary(result))
    if result.findings:
        return EXIT_FINDINGS
    return EXIT_OK


def cmd_tui(args: Any) -> int:
    from candix.tui.app import run_tui

    config = load_config(args)
    targets = list(args.targets)
    engagement = load_engagement(args, targets, allow_exploit=bool(args.exploit)) if targets else None
    return run_tui(
        targets,
        config=config,
        engagement=engagement,
        exploit=bool(args.exploit),
        max_proofs=args.max_proofs,
    )


def cmd_doctor(args: Any) -> int:
    checks: list[dict[str, Any]] = []

    def record(name: str, status: str, detail: str) -> None:
        checks.append({"check": name, "status": status, "detail": detail})

    record("python", "ok" if sys.version_info >= (3, 11) else "error", f"{sys.version.split()[0]} (requires 3.11+)")
    try:
        from candix import build_context  # noqa: F401

        record("package", "ok", f"candix {VERSION} importable")
    except Exception as exc:
        record("package", "error", str(exc))
    try:
        config = Config.defaults()
        config.validate()
        record("config", "ok", f"{len(config.to_dict())} sections, {len(PROFILES)} profiles")
    except Exception as exc:
        record("config", "error", str(exc))
    try:
        from candix.detectors.base import summarize_detectors

        summary = summarize_detectors()
        total = summary.get("total", 0)
        record("detectors", "ok" if total else "warn", f"{total} detectors across {len(summary.get('categories') or {})} categories")
    except Exception as exc:
        record("detectors", "error", str(exc))
    try:
        from candix.lab import build_server

        server = build_server("127.0.0.1", 0).start()
        try:
            probe = socket.create_connection(("127.0.0.1", server.port), timeout=2)
            probe.close()
            record("loopback", "ok", f"lab responded on 127.0.0.1:{server.port}")
        finally:
            server.stop()
    except Exception as exc:
        record("loopback", "error", str(exc))
    artifacts = Path(os.environ.get("CANDIX_HOME", "artifacts"))
    try:
        artifacts.mkdir(parents=True, exist_ok=True)
        probe_file = artifacts / ".write-test"
        probe_file.write_text("ok", encoding="utf-8")
        probe_file.unlink()
        record("artifacts", "ok", str(artifacts.resolve()))
    except Exception as exc:
        record("artifacts", "error", str(exc))
    try:
        from candix.net.dns import resolve

        addresses = resolve("example.com")
        record("dns", "ok" if addresses else "warn", ", ".join(addresses[:2]) or "no answer")
    except Exception as exc:
        record("dns", "warn", str(exc))
    if args.json_output:
        out.print_json({"checks": checks, "version": VERSION})
        return EXIT_OK
    echo(out.rule("doctor"))
    for item in checks:
        color = {"ok": "green", "warn": "yellow", "error": "red"}.get(item["status"], "grey")
        echo(f"  {out.paint(item['status'].upper().ljust(5), color)} {item['check'].ljust(12)} {item['detail']}")
    failures = [item for item in checks if item["status"] == "error"]
    echo("")
    echo(out.paint(f"  {len(checks) - len(failures)}/{len(checks)} checks passed", "green" if not failures else "red"))
    return EXIT_OK if not failures else EXIT_ERROR


def cmd_config(args: Any) -> int:
    config = Config.load(args.config, profile=args.profile)
    payload = config.to_dict()
    if args.section:
        payload = {args.section: payload.get(args.section, {})}
    if args.json_output:
        out.print_json(payload)
        return EXIT_OK
    echo(out.rule("configuration"))
    for section, values in payload.items():
        echo("")
        echo(out.paint(f"  [{section}]", "cyan", bold=True))
        if isinstance(values, dict):
            for key, value in values.items():
                if isinstance(value, dict):
                    continue
                echo(f"    {key.ljust(24)} {value}")
        else:
            echo(f"    {values}")
    return EXIT_OK


def cmd_api(args: Any) -> int:
    from candix.api.server import ApiConfig, ApiServer

    config = ApiConfig(
        host=args.host,
        port=args.port,
        token=args.token if args.token is not None else os.environ.get("CANDIX_API_TOKEN", ""),
        allow_anonymous=bool(args.allow_anonymous),
        artifacts_dir=args.artifacts,
        cors_origin=args.cors_origin,
    )
    server = ApiServer(config)
    server.start()
    if args.json_output:
        out.print_json({"url": server.base_url, "authenticated": bool(config.token), "artifacts": config.artifacts_dir})
        return EXIT_OK
    echo(out.rule("candix api"))
    echo(out.kv_table([
        ("url", server.base_url),
        ("auth", "bearer token" if config.token else "anonymous (local only)"),
        ("artifacts", config.artifacts_dir),
        ("workers", config.max_workers),
    ], indent=2))
    echo("")
    echo(out.paint("  POST /scans with {\"targets\": [...], \"authorized\": \"name\"} to queue a scan.", "grey"))
    echo(out.paint("  Ctrl-C stops the server.", "grey"))
    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        echo("")
        echo(out.paint("  stopping api", "grey"))
    finally:
        server.stop()
    return EXIT_OK


def _agent_client(args: Any) -> Any:
    """Build a model client from flags + environment, or return None."""

    from candix.llm.client import LLMClient, RetryPolicy
    from candix.llm.providers import AnthropicProvider, OllamaProvider, OpenAICompatibleProvider

    if getattr(args, "no_llm", False):
        return None
    kind = str(getattr(args, "provider", "") or os.environ.get("CANDIX_LLM_PROVIDER", "")).strip().lower()
    model = str(getattr(args, "model", "") or os.environ.get("CANDIX_LLM_MODEL", "")).strip()
    api_key = os.environ.get("CANDIX_LLM_API_KEY", "")
    base_url = os.environ.get("CANDIX_LLM_BASE_URL", "")
    if not kind:
        if os.environ.get("ANTHROPIC_API_KEY"):
            kind = "anthropic"
        elif os.environ.get("OPENAI_API_KEY") or base_url:
            kind = "openai"
        else:
            return None
    try:
        if kind == "anthropic":
            provider = AnthropicProvider(
                model=model or "claude-sonnet-4-5",
                base_url=base_url or "https://api.anthropic.com",
                api_key=api_key or os.environ.get("ANTHROPIC_API_KEY", ""),
            )
        elif kind == "ollama":
            provider = OllamaProvider(model=model or "llama3.1", base_url=base_url or "http://127.0.0.1:11434")
        else:
            provider = OpenAICompatibleProvider(
                model=model or "gpt-4.1-mini",
                base_url=base_url or os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1"),
                api_key=api_key or os.environ.get("OPENAI_API_KEY", ""),
            )
    except Exception as error:
        echo(out.paint(f"  model provider unavailable: {error}", "yellow"))
        return None
    return LLMClient([provider], retry=RetryPolicy(attempts=2))


def _notify_config(args: Any) -> dict[str, Any]:
    """Turn the notify flags into the dict the harness router expects."""

    config: dict[str, Any] = {}
    if getattr(args, "notify_file", ""):
        config["file"] = args.notify_file
    if getattr(args, "notify_webhook", ""):
        config["webhook"] = args.notify_webhook
    if getattr(args, "notify_slack", ""):
        config["slack"] = args.notify_slack
    commands = [str(item) for item in (getattr(args, "notify_command", []) or []) if str(item).strip()]
    if commands:
        config["command"] = shlex.split(commands[0])
        config["allowed_prefixes"] = list(getattr(args, "allow_command", []) or [])
    if config:
        config.setdefault("console", False)
    return config


def cmd_agent(args: Any) -> int:
    from candix.agent import AgentSession, AgentSettings, AutonomyLevel, BudgetLimits
    from candix.agent.reporting import render_json, render_markdown, summary_line

    if getattr(args, "list_playbooks", False):
        from candix.agent.playbooks import default_registry

        registry = default_registry()
        if args.json_output:
            out.print_json({"playbooks": registry.catalogue()})
            return EXIT_OK
        echo(out.rule("playbooks"))
        echo(out.table(
            ["NAME", "STEPS", "WHAT IT DOES"],
            [(item.name, str(len(item.steps)), item.description[:60]) for item in registry.playbooks.values()],
        ))
        echo("")
        return EXIT_OK

    if not args.targets:
        echo(out.paint("  agent needs at least one target", "red"))
        return EXIT_USAGE

    config = load_config(args)
    if args.exploit:
        config.set("exploit.enabled", True)
    engagement = load_engagement(args, list(args.targets), allow_exploit=bool(args.exploit))
    run_id = time.strftime("%Y%m%d-%H%M%S")
    artifacts = Path(args.artifacts) if args.artifacts else Path(args.out) / run_id
    artifacts.mkdir(parents=True, exist_ok=True)
    journal_path = args.journal or str(artifacts / "journal.jsonl")
    settings = AgentSettings(
        goal=args.goal,
        autonomy=AutonomyLevel.parse(args.autonomy),
        exploit=bool(args.exploit),
        limits=BudgetLimits(
            turns=int(args.turns),
            intents=int(args.intents),
            tool_calls=int(args.tool_calls),
            tokens=int(args.tokens),
            seconds=float(args.seconds),
            cost_usd=float(args.cost),
        ),
        artifacts_dir=str(artifacts),
        journal_path=journal_path,
        memory_path=args.memory,
        skills_dir=args.skills,
        max_turns=int(args.turns),
        use_llm=not args.no_llm,
        approve_mode=args.approvals,
        verify=True,
        dry_run=bool(args.dry_run),
        playbook=str(getattr(args, "playbook", "") or ""),
        playbook_limit=int(getattr(args, "playbook_limit", 0) or 0),
        adaptive=bool(getattr(args, "adaptive", False)),
        adaptive_strategy=str(getattr(args, "adaptive_strategy", "ucb") or "ucb"),
        explore_ratio=float(getattr(args, "explore_ratio", 0.3) or 0.3),
        priors_path=str(getattr(args, "priors", "") or ""),
        use_priors=not bool(getattr(args, "no_priors", False)),
        gate=not bool(getattr(args, "no_gate", False)),
        gate_max_risk=int(getattr(args, "gate_max_risk", 70) or 70),
        allow_commands=tuple(getattr(args, "allow_command", []) or ()),
        allow_private=bool(getattr(args, "allow_private", False)),
        notify_config=_notify_config(args),
        notify_min_severity=str(getattr(args, "notify_min_severity", "high") or "high"),
        poc=not bool(getattr(args, "no_poc", False)),
        review=not bool(getattr(args, "no_review", False)),
        todos=not bool(getattr(args, "no_todos", False)),
        targeting=not bool(getattr(args, "no_targeting", False)),
    )
    client = _agent_client(args)

    def on_event(kind: str, payload: dict[str, Any]) -> None:
        if args.json_output or args.quiet:
            return
        if kind == "plan":
            echo(out.paint(f"  plan  {payload.get('reasoning', '')[:100]}", "cyan"))
        elif kind == "intent.start":
            echo(f"    → {payload.get('title', '')[:70]} [{payload.get('tool', '')}]")
        elif kind == "intent.finish":
            mark = "ok" if payload.get("ok") else "fail"
            echo(out.paint(f"    {mark} {payload.get('summary', '')[:100]}", "grey"))
        elif kind == "intent.blocked":
            echo(out.paint(f"    blocked: {payload.get('title', '')} — {payload.get('reason', '')[:90]}", "yellow"))
        elif kind == "intent.awaiting_approval":
            echo(out.paint(f"    approval needed: {payload.get('title', '')} (risk {payload.get('risk')})", "yellow"))
        elif kind == "finding":
            echo(out.paint(f"    ! {payload.get('severity', '')} {payload.get('title', '')}", "red"))

    session = AgentSession.create(
        list(args.targets),
        config=config,
        engagement=engagement,
        settings=settings,
        client=client,
        skills_dir=args.skills,
        on_event=on_event,
    )

    if args.resume:
        from candix.agent.state_io import SessionState, restore

        try:
            restored = restore(session, SessionState.load(args.resume))
            echo(out.paint(f"  resumed: {restored}", "grey"))
        except Exception as error:
            echo(out.paint(f"  cannot resume: {error}", "red"))
            return EXIT_ERROR

    if args.dry_run:
        return _agent_dry_run(session, settings, args, out)

    echo(out.rule("agent"))
    echo(out.kv_table(
        [
            ("targets", ", ".join(args.targets)),
            ("goal", settings.goal[:80]),
            ("autonomy", settings.autonomy.value),
            ("planner", ", ".join(filter(None, ["llm" if client is not None else "heuristic", settings.playbook, "adaptive" if settings.adaptive else ""]))),
            ("budget", f"{args.turns} turns · {args.tool_calls} tool calls · {args.seconds:.0f}s"),
            ("artifacts", str(artifacts)),
        ],
        indent=2,
    ))
    echo("")
    try:
        result = session.run()
    except KeyboardInterrupt:
        echo(out.paint("  interrupted", "yellow"))
        return 130
    except CandixError as error:
        echo(out.paint(f"  error: {error}", "red"))
        return EXIT_ERROR

    snapshot = session.snapshot(result)
    formats = [item.strip().lower() for item in str(args.formats or "").split(",") if item.strip()]
    written: dict[str, str] = {}
    from candix.agent.report_bridge import render as render_format
    from candix.report.builder import RENDERERS, normalize_format

    for fmt in formats:
        name = normalize_format(fmt)
        if name not in RENDERERS:
            if name == "markdown":
                path = artifacts / f"agent-{run_id}.md"
                path.write_text(render_markdown(result, snapshot=snapshot), encoding="utf-8")
                written["markdown"] = str(path)
            elif name == "json":
                path = artifacts / f"agent-{run_id}.json"
                path.write_text(render_json(result, snapshot=snapshot), encoding="utf-8")
                written["json"] = str(path)
            continue
        try:
            body = render_format(result, name, snapshot)
        except Exception as error:
            echo(out.paint(f"  {name}: renderer failed ({error})", "yellow"))
            continue
        path = artifacts / f"agent-{run_id}.{RENDERERS[name].extension}"
        path.write_text(body, encoding="utf-8")
        written[name] = str(path)
    session.save(artifacts / "session.json", result)
    try:
        from candix.agent.audit import markdown as audit_markdown
        from candix.agent.compliance import ComplianceReport, ControlStatus, Control
        from candix.agent.insights import export_markdown as insights_markdown
        from candix.agent.insights import collect
        from candix.agent.scorecard import Scorecard, CategoryScore

        insight_report = collect(result, session.telemetry, budget=session.budget)
        (artifacts / "insights.md").write_text(insights_markdown(insight_report), encoding="utf-8")
        written["insights"] = str(artifacts / "insights.md")
        adaptive = getattr(session, "_adaptive", None)
        if adaptive is not None:
            (artifacts / "adaptive.md").write_text(adaptive.markdown(), encoding="utf-8")
            written["adaptive"] = str(artifacts / "adaptive.md")
    except Exception as error:
        echo(out.paint(f"  insights unavailable: {error}", "yellow"))
    try:
        from candix.agent.evidence_chain import build_chain

        chain = build_chain(result, session.assets)
        chain_path = artifacts / "evidence-chain.json"
        chain.save(chain_path)
        written["evidence"] = str(chain_path)
    except Exception as error:
        echo(out.paint(f"  evidence chain unavailable: {error}", "yellow"))
    if getattr(args, "metrics", ""):
        try:
            from candix.agent.metrics_export import from_result as metrics_from_result

            metrics = metrics_from_result(result, telemetry=session.telemetry, budget=session.budget, extra_labels={"run": run_id})
            written["metrics"] = metrics.save(args.metrics)
        except Exception as error:
            echo(out.paint(f"  metrics unavailable: {error}", "yellow"))
    for kind, path in ((snapshot.get("harness", {}) or {}).get("artifacts") or {}).items():
        written[f"harness/{kind}"] = str(path)
    if result.proofs:
        try:
            from candix.agent.replay_kit import (checkout_script, from_result, index, write as write_replay)

            bundles = from_result(result)
            if bundles:
                replay_dir = artifacts / "replay"
                write_replay(bundles, replay_dir)
                (replay_dir / "README.md").write_text(index(bundles), encoding="utf-8")
                script = replay_dir / "run-all.sh"
                script.write_text(checkout_script(bundles, str(replay_dir)), encoding="utf-8")
                script.chmod(0o755)
                written["replay"] = str(replay_dir)
        except Exception as error:
            echo(out.paint(f"  replay kit unavailable: {error}", "yellow"))

    counts = result.counts()
    if args.json_output:
        payload = {
            "stop_reason": result.stop_reason,
            "counts": counts,
            "findings": len(result.findings),
            "proofs": len(result.proofs),
            "triage": snapshot.get("triage", {}),
            "duration": round(result.duration, 2),
            "budget": snapshot["budget"],
            "journal": snapshot["journal"],
            "artifacts": {**written, "session": str(artifacts / "session.json")},
            "lessons": result.lessons,
            "harness": snapshot.get("harness", {}),
        }
        out.print_json(payload)
        return EXIT_FINDINGS if result.findings else EXIT_OK

    echo("")
    echo(out.rule("run summary"))
    echo(summary_line(result))
    echo(out.kv_table(
        [
            ("stop reason", result.stop_reason[:90]),
            ("intents", ", ".join(f"{name}={count}" for name, count in sorted(counts.items())) or "none"),
            ("findings", str(len(result.findings))),
            ("proofs", str(len(result.proofs))),
            ("triage", str(snapshot.get("triage", {}).get("summary", ""))[:70] or "n/a"),
            ("scorecard", str(snapshot.get("scorecard", {}).get("summary", ""))[:70] or "n/a"),
            ("asvs", str(snapshot.get("compliance", {}).get("summary", ""))[:70] or "n/a"),
            (
                "gate",
                f"{snapshot.get('harness', {}).get('gate', {}).get('tool_checks', 0)} checked, "
                f"{snapshot.get('harness', {}).get('gate', {}).get('blocked', 0)} blocked",
            ),
            ("review", str(snapshot.get("harness", {}).get("review", {}).get("total", 0)) + " under review"),
            ("todos", str((snapshot.get("harness", {}) or {}).get("todos", "") or "none")[:60]),
            ("approvals", str(snapshot["approvals"]["pending"]) + " pending"),
            ("journal", str(snapshot["journal"].get("entries", 0)) + " entries"),
        ],
        indent=2,
    ))
    if result.findings:
        echo("")
        from candix.agent.report_bridge import finding_rows

        ordered = {str(item.get("id", "")): item for item in result.findings}
        prioritized = []
        seen: set[str] = set()
        for ranked in snapshot.get("triage", {}).get("ranked", []):
            key = str(ranked.get("id", ""))
            item = ordered.get(key)
            if item is not None and key not in seen:
                prioritized.append(item)
                seen.add(key)
        for key, item in ordered.items():
            if key not in seen:
                prioritized.append(item)
                seen.add(key)
        rows = [
            (str(item.get("severity", "")), str(item.get("title", ""))[:60], str(item.get("url", ""))[:50])
            for item in prioritized[:15]
        ]
        echo(out.table(["SEVERITY", "FINDING", "ENDPOINT"], rows))
    blocked_calls = (snapshot.get("harness", {}) or {}).get("gate", {}).get("entries", [])
    blocked_calls = [entry for entry in blocked_calls if not entry.get("allowed")]
    if blocked_calls:
        echo("")
        echo(out.paint("  refused by the gate:", "yellow"))
        for entry in blocked_calls[:5]:
            echo(f"    · {entry.get('subject', '')[:70]} — {entry.get('reason', '')[:80]}")
    if result.lessons:
        echo("")
        echo(out.paint("  lessons for the next run:", "grey"))
        for lesson in result.lessons[:5]:
            echo(f"    · {lesson.get('text', '')[:110]}")
    if written:
        echo("")
        echo(out.kv_table([(key, value) for key, value in written.items()], indent=2))
    echo("")
    return EXIT_FINDINGS if result.findings else EXIT_OK


def _agent_dry_run(session: Any, settings: Any, args: Any, out: Any) -> int:
    """Plan one turn and show what would run, executing nothing."""

    from candix.agent.planner import PlannerState

    planner = session.build_planner()
    extras = session.harness.plan_extras(session.assets, [])
    state = PlannerState(
        goal=settings.goal,
        targets=session.targets,
        coverage=session.assets.coverage(),
        remaining_turns=settings.max_turns,
        exploit_enabled=settings.exploit,
        next_targets=extras.get("next_targets", []),
        todos=extras.get("todos", ""),
    )
    decision = planner.decide(state)
    from candix.agent.simulator import simulate

    simulation = simulate(decision.intents, policy=session.policy, registry=session.registry, budget=session.budget)
    payload = {
        "action": decision.action,
        "reasoning": decision.reasoning,
        "source": decision.source,
        "intents": [],
    }
    if args.json_output:
        estimates = {item.intent: item.to_dict() for item in simulation.estimates}
        for intent in decision.intents:
            gate = session.policy.gate(intent)
            payload["intents"].append(
                {**intent.to_dict(), "gate": gate.to_dict(), "estimate": estimates.get(intent.title, {})}
            )
        payload["simulation"] = simulation.to_dict()
        out.print_json(payload)
        return EXIT_OK
    echo(out.rule("dry run"))
    echo(f"planner: {decision.source} · action: {decision.action}")
    echo(f"reason: {decision.reasoning}")
    echo("")
    rows = []
    for intent in decision.intents:
        gate = session.policy.gate(intent)
        allowed = "yes" if gate.allowed else "no"
        approval = "approve" if gate.requires_approval else "-"
        rows.append((intent.phase.value, intent.title[:50], intent.tool, allowed, approval, f"{gate.risk:.2f}"))
    if rows:
        echo(out.table(["PHASE", "INTENT", "TOOL", "ALLOWED", "GATE", "RISK"], rows))
    else:
        echo("no intents planned")
    echo("")
    echo(f"simulation: {simulation.summary()}")
    for note in simulation.notes:
        echo(out.paint(f"  note: {note}", "yellow"))
    return EXIT_OK


def cmd_notify(args: Any) -> int:
    from candix.integrations.base import Notification, build, load_plugins
    from candix.integrations.siem import render as render_siem

    load_plugins()
    payload = json.loads(Path(args.report).read_text(encoding="utf-8"))
    notification = Notification.from_report(payload, link=args.link)
    results: list[dict[str, Any]] = []
    if args.siem_format:
        rendered = render_siem(payload, args.siem_format, min_severity=args.min_severity)
        if args.json_output:
            results.append({"siem": args.siem_format, "events": rendered.count("\n") + 1})
        else:
            echo(out.rule(f"siem export · {args.siem_format}"))
            echo(rendered)
    for name in args.integration:
        integration = build(
            name,
            endpoint=args.endpoint,
            token=args.token,
            secret=args.secret,
            project=args.project,
            dry_run=not args.endpoint,
        )
        result = integration.send(notification)
        results.append(result.to_dict())
        if not args.json_output:
            status = out.paint("sent", "green") if result.ok else out.paint("failed", "red")
            echo(f"  {name.ljust(12)} {status} {result.reference or result.message}")
    if args.json_output:
        out.print_json({"results": results})
    return EXIT_OK if all(item.get("ok", True) for item in results) else EXIT_ERROR


def cmd_gate(args: Any) -> int:
    from candix.agent.intercept import CommandGate, level_of, score_command
    command = " ".join(str(item) for item in args.argv).strip()
    config = None
    try:
        config = load_config(args)
    except Exception:
        pass
    try:
        from candix.engine_bridge.config import BridgeConfig
        bc = BridgeConfig.from_config(config) if config is not None else BridgeConfig.from_env()
    except Exception:
        bc = None
    if bc is not None and getattr(bc, "enabled", False):
        try:
            from candix.engine_bridge.intercept_proxy import InterceptProxy
            proxy = InterceptProxy(bc)
            decision = proxy.check_command_gate(command, targets=tuple(args.target), allowed_prefixes=tuple(args.allow_prefix), max_risk=int(args.max_risk))
            risk_data = getattr(decision, "dual", None) or {}
            score = int(risk_data.get("score", decision.risk.score if getattr(decision, "risk", None) else 0))
            level = risk_data.get("level", level_of(score))
            risk_dict = {"score": score, "level": level, "reasons": risk_data.get("reasons", [])}
            if args.json_output:
                out.print_json({"command": command, "allowed": decision.allowed, "rule": decision.rule, "reason": decision.reason, "prefix": decision.prefix, "risk": risk_dict, "level": level, "dual": risk_data, "engine": bc.to_dict()})
                return EXIT_OK if decision.allowed else EXIT_FINDINGS
            echo(out.rule("gate"))
            echo(out.kv_table([("command", command[:100]), ("prefix", decision.prefix or "n/a"), ("risk", f"{score}/100 ({level})"), ("decision", "allow" if decision.allowed else "block"), ("rule", decision.rule or "-"), ("reason", decision.reason[:110]), ("engine", f"{bc.url} ({risk_data.get('source', '')})")], indent=2))
            for reason in (risk_data.get("reasons") or [])[:5]:
                echo(out.paint(f"  \u00b7 {reason}", "grey"))
            if risk_data.get("discrepancy"):
                echo(out.paint(f"  discrepancy: {risk_data['discrepancy']}", "yellow"))
            if risk_data.get("go_error"):
                echo(out.paint(f"  go_error: {risk_data['go_error']}", "red"))
            return EXIT_OK if decision.allowed else EXIT_FINDINGS
        except Exception:
            pass
    gate = CommandGate(allowed_prefixes=tuple(args.allow_prefix), max_risk=int(args.max_risk), targets=tuple(args.target), allow_private=bool(getattr(args, "allow_private", False)))
    decision = gate.check(command, targets=args.target)
    risk = score_command(command)
    if args.json_output:
        out.print_json({"command": command, "allowed": decision.allowed, "rule": decision.rule, "reason": decision.reason, "prefix": decision.prefix, "risk": risk.to_dict(), "level": level_of(risk.score)})
        return EXIT_OK if decision.allowed else EXIT_FINDINGS
    echo(out.rule("gate"))
    echo(out.kv_table([("command", command[:100]), ("prefix", decision.prefix or "n/a"), ("risk", f"{risk.score}/100 ({level_of(risk.score)})"), ("decision", "allow" if decision.allowed else "block"), ("rule", decision.rule or "-"), ("reason", decision.reason[:110])], indent=2))
    for reason in risk.reasons[:5]:
        echo(out.paint(f"  \u00b7 {reason}", "grey"))
    return EXIT_OK if decision.allowed else EXIT_FINDINGS


def cmd_harness(args: Any) -> int:
    """Show what a run actually gets, and check targets against the gate."""

    from candix.agent.harness import HarnessSettings, status
    from candix.agent.intercept import TargetGate

    rows = status()
    report: dict[str, Any] = {"capabilities": rows}
    if args.run:
        session_path = Path(args.run)
        if session_path.is_dir():
            session_path = session_path / "session.json"
        try:
            payload = json.loads(session_path.read_text(encoding="utf-8"))
            report["run"] = payload.get("harness", {})
        except (OSError, ValueError) as error:
            echo(out.paint(f"  cannot read {session_path}: {error}", "red"))
            return EXIT_ERROR
    if args.target:
        gate = TargetGate(allow=tuple(args.target))
        report["targets"] = [
            {"target": item, **gate.check(item).to_dict()} for item in args.target
        ]
    report["settings"] = HarnessSettings().to_dict()
    if args.json_output:
        out.print_json(report)
        return EXIT_OK
    echo(out.rule("harness"))
    echo(out.table(
        ["CAPABILITY", "MODULE", "STATE"],
        [(row["capability"], row["module"], row["state"]) for row in rows],
    ))
    echo("")
    echo(out.paint("  defaults: gate on, poc/review/todos/targeting on, notify off", "grey"))
    for item in report.get("targets", []):
        mark = "allow" if item["allowed"] else "block"
        echo(f"  {mark:5} {item['target']} — {item['reason'][:80]}")
    if "run" in report:
        harness_block = report["run"] or {}
        echo(out.kv_table(
            [
                (
                    "run gate",
                    f"{harness_block.get('gate', {}).get('tool_checks', 0)} tool call(s) checked, "
                    f"{harness_block.get('gate', {}).get('blocked', 0)} blocked",
                ),
                ("poc", str(harness_block.get("poc", "n/a"))),
                ("review", _review_line(harness_block.get("review"))),
                ("todos", str(harness_block.get("todos", "n/a"))[:70]),
                ("notify", str(harness_block.get("notify", {}).get("summary", "n/a"))[:70]),
            ],
            indent=2,
        ))
    echo("")
    return EXIT_OK


def _review_line(block: Any) -> str:
    if not isinstance(block, dict):
        return "n/a"
    counts = block.get("counts") or {}
    return f"{block.get('total', 0)} finding(s), {counts.get('pending', 0)} pending"


def cmd_review(args: Any) -> int:
    """Read, print and (optionally) approve a run's reviewer board."""

    from candix.agent.review import ReviewBoard, block_release

    source = Path(args.path)
    if source.is_dir():
        source = source / "review.json"
    if not source.is_file():
        echo(out.paint(f"  no review board at {source}", "red"))
        return EXIT_ERROR
    board = ReviewBoard.load(source)
    approved = 0
    if args.approve:
        approved = board.approve_all(args.reviewer)
        board.save(source)
    summary = board.summary()
    ready, reason = block_release(board)
    if args.json_output:
        out.print_json({"summary": summary, "approved_now": approved, "release": {"ready": ready, "reason": reason}})
        return EXIT_OK if approved or not args.approve else EXIT_FINDINGS
    if args.markdown:
        echo(board.markdown())
        return EXIT_OK
    echo(out.rule("review"))
    echo(out.kv_table(
        [
            ("board", str(source)),
            ("findings", str(summary["total"])),
            ("approved", str(summary["counts"].get("approved", 0))),
            ("pending", str(len(board.pending()))),
            ("rejected", str(len(board.blocked()))),
            ("release", "ready" if ready else reason[:70]),
        ],
        indent=2,
    ))
    if args.approve:
        echo(out.paint(f"  approved {approved} finding(s) as {args.reviewer}", "grey"))
    for item in board.pending()[:10]:
        echo(f"  · {item.title[:70]} — {item.progress:.0%} of the checklist")
    echo("")
    return EXIT_OK


def cmd_playbooks(args: Any) -> int:
    from candix.playbooks import for_report, playbook as lookup, playbook_ids, render_playbook_markdown
    from candix.playbooks.engine import PlaybookMatch

    if args.for_report:
        payload = json.loads(Path(args.for_report).read_text(encoding="utf-8"))
        matches = for_report(payload)
        if args.json_output:
            out.print_json({"matches": [match.to_dict() for match in matches]})
            return EXIT_OK
        echo(out.rule("playbooks for report"))
        for match in matches:
            echo(render_playbook_markdown(match))
            echo("")
        return EXIT_OK
    ids = args.ids or playbook_ids()
    selected = []
    for identifier in ids:
        book = lookup(identifier)
        if book is None:
            sys.stderr.write(f"unknown playbook: {identifier}\n")
            continue
        selected.append(PlaybookMatch(playbook=book, finding_ids=[], severity=book.severity_hint, reason="manual selection"))
    if args.json_output:
        out.print_json({"playbooks": [match.to_dict() for match in selected]})
        return EXIT_OK
    for match in selected:
        echo(render_playbook_markdown(match))
        echo("")
    return EXIT_OK


def cmd_shell(args: Any) -> int:
    from candix.cli.repl import run_shell

    config = load_config(args)
    return run_shell(list(args.targets), config=config, authorized=args.authorized)


def cmd_export(args: Any) -> int:
    from candix.report.export import export_bundle, remediation_tracker
    from candix.report.junit import junit_summary, render_junit
    from candix.report.model import ReportModel
    from candix.report.notebook import render_notebook
    from candix.report.slides import render_slides
    from candix.integrations.siem import render as render_siem
    from candix.exploit.replay import package_from_proof

    payload = json.loads(Path(args.report).read_text(encoding="utf-8"))
    model = ReportModel.from_snapshot(payload)
    outdir = Path(args.out)
    outdir.mkdir(parents=True, exist_ok=True)
    written: dict[str, str] = {}
    any_selected = any([args.tracker, args.junit, args.notebook, args.slides, args.replay, args.siem])
    if args.tracker or not any_selected:
        written.update(export_bundle(model, str(outdir)))
    if args.junit:
        path = outdir / f"junit-{model.scan_id}.xml"
        path.write_text(render_junit(model, fail_on=args.fail_on), encoding="utf-8")
        written["junit"] = str(path)
    if args.notebook:
        path = outdir / f"notebook-{model.scan_id}.ipynb"
        path.write_text(render_notebook(model), encoding="utf-8")
        written["notebook"] = str(path)
    if args.slides:
        path = outdir / f"slides-{model.scan_id}.md"
        path.write_text(render_slides(model), encoding="utf-8")
        written["slides"] = str(path)
    if args.siem:
        path = outdir / f"siem-{model.scan_id}.{args.siem}"
        path.write_text(render_siem(payload, args.siem), encoding="utf-8")
        written["siem"] = str(path)
    if args.replay:
        replay_dir = outdir / "replay"
        replay_dir.mkdir(exist_ok=True)
        count = 0
        for proof in payload.get("proofs") or []:
            package = package_from_proof(proof)
            if not package.steps or not package.steps[0].url:
                continue
            for kind, path in package.write(replay_dir).items():
                written[f"replay_{count}_{kind}"] = path
            count += 1
    summary = junit_summary(model, fail_on=args.fail_on) if args.fail_on != "none" else {"exit_code": 0, "failures": 0}
    if args.json_output:
        out.print_json({"written": written, "exit_code": summary["exit_code"], "rows": len(remediation_tracker(model))})
        return int(summary["exit_code"])
    echo(out.rule("export"))
    echo(out.kv_table([(key, str(value)) for key, value in written.items()], indent=2))
    echo("")
    echo(out.paint(f"  {len(remediation_tracker(model))} tracker rows · {summary.get('failures', 0)} CI failures", "grey"))
    return int(summary["exit_code"])


def cmd_compare(args: Any) -> int:
    from candix.report.compare import compare_snapshots, render_comparison_markdown

    before = json.loads(Path(args.before).read_text(encoding="utf-8"))
    after = json.loads(Path(args.after).read_text(encoding="utf-8"))
    comparison = compare_snapshots(before, after)
    if args.json_output:
        out.print_json(comparison)
    else:
        document = render_comparison_markdown(comparison)
        echo(document)
        if args.out:
            Path(args.out).write_text(document, encoding="utf-8")
            echo(out.kv_table([("written", args.out)], indent=2))
    return EXIT_FINDINGS if comparison["counts"]["new"] else EXIT_OK


def cmd_version(args: Any) -> int:
    info = {
        "version": VERSION,
        "python": sys.version.split()[0],
        "platform": sys.platform,
        "executable": sys.executable,
        "authorization_notice": AUTHORIZATION_NOTICE.strip(),
    }
    if args.json_output:
        out.print_json(info)
        return EXIT_OK
    echo(out.banner(VERSION))
    echo("")
    echo(out.kv_table([
        ("version", VERSION),
        ("python", info["python"]),
        ("platform", info["platform"]),
        ("executable", info["executable"]),
    ], indent=2))
    return EXIT_OK


def cmd_bundle(args: Any) -> int:
    from candix.agent.reports_bundle import build, prune, verify

    if args.verify:
        ok, problems = verify(args.path)
        if args.json_output:
            out.print_json({"ok": ok, "problems": problems, "path": args.path})
        else:
            echo(out.rule("bundle verify"))
            echo(out.kv_table([("path", args.path), ("ok", str(ok))], indent=2))
            for problem in problems:
                echo(out.paint(f"  {problem}", "red"))
        return EXIT_OK if ok else EXIT_ERROR

    bundle = build(args.path, destination=args.zip or None)
    removed = prune(args.path) if args.prune else []
    if args.json_output:
        out.print_json({"files": len(bundle.entries), "bytes": bundle.size, "zip": args.zip, "pruned": removed})
    else:
        echo(out.rule("bundle"))
        echo(out.kv_table([("files", str(len(bundle.entries))), ("bytes", str(bundle.size)), ("zip", args.zip or "-")], indent=2))
        for name in removed:
            echo(out.paint(f"  pruned {name}", "grey"))
    return EXIT_OK


def cmd_agent_diff(args: Any) -> int:
    from candix.agent.diffing import from_files, regression_gate, summary_table

    diff = from_files(args.before, args.after)
    ok, reason = regression_gate(diff, fail_on=args.fail_on, allow_new=args.allow_new)
    if args.json_output:
        out.print_json({"counts": diff.counts(), "gate": {"ok": ok, "reason": reason}, "summary": diff.summary()})
    else:
        echo(out.rule("agent diff"))
        echo(diff.summary())
        echo("")
        echo(diff.markdown())
        if args.out:
            Path(args.out).write_text(diff.markdown(), encoding="utf-8")
            echo(out.kv_table([("written", args.out)], indent=2))
    if not ok:
        echo(out.paint(f"  gate: {reason}", "red"))
    return EXIT_OK if ok else EXIT_FINDINGS


COMMANDS = {
    "scan": cmd_scan,
    "exploit": cmd_exploit,
    "report": cmd_report,
    "authorize": cmd_authorize,
    "detectors": cmd_detectors,
    "payloads": cmd_payloads,
    "lab": cmd_lab,
    "fuzz": cmd_fuzz,
    "tui": cmd_tui,
    "doctor": cmd_doctor,
    "config": cmd_config,
    "compare": cmd_compare,
    "shell": cmd_shell,
    "export": cmd_export,
    "api": cmd_api,
    "notify": cmd_notify,
    "agent": cmd_agent,
    "gate": cmd_gate,
    "harness": cmd_harness,
    "review": cmd_review,
    "playbooks": cmd_playbooks,
    "bundle": cmd_bundle,
    "agent-diff": cmd_agent_diff,
    "version": cmd_version,
}
