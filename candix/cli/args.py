"""Argument parsing for the Candix command line."""

from __future__ import annotations

import argparse
import os
from typing import Any, Sequence

from candix import VERSION

PROGRAM = "candix"

EPILOG = (
    "Every active technique requires an authorization document. Create one with\n"
    "  candix authorize --engagement NAME --client CLIENT --by NAME --include HOST:PORT\n"
    "then pass it to a scan with --engagement FILE. Use --authorized NAME only for\n"
    "targets you own or have written permission to test."
)

FORMATS = "html,json,markdown,sarif,csv,jsonl,summary"


class Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:  # pragma: no cover - argparse exits
        self.print_usage()
        raise SystemExit(f"{self.prog}: error: {message}")


def _add_common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--config", "-c", help="configuration file (JSON or INI-like key=value)")
    parser.add_argument("--profile", choices=["safe", "standard", "lab", "deep", "ctf"], default=None)
    parser.add_argument("--set", dest="overrides", action="append", default=[], metavar="KEY=VALUE",
                        help="override any configuration value, e.g. --set scan.max_rps=10")
    parser.add_argument("--log-file", help="write a plain-text log to this file")
    parser.add_argument("--json-log", action="store_true", help="write the log file as JSON lines")
    parser.add_argument("--log-level", default="info", choices=["debug", "info", "warning", "error"])
    parser.add_argument("--quiet", "-q", action="store_true", help="suppress informational output")
    parser.add_argument("--verbose", "-v", action="store_true", help="show detector-level detail")
    parser.add_argument("--json", dest="json_output", action="store_true", help="print machine-readable JSON")


def _add_scope(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--engagement", "-e", metavar="FILE", help="authorization document created by 'candix authorize'")
    parser.add_argument("--authorized", metavar="OPERATOR", help="generate a temporary authorization for these targets")
    parser.add_argument("--authorized-by", metavar="NAME", default=os.environ.get("CANDIX_AUTHORIZED_BY", "self"),
                        help="name of the person approving a temporary authorization")
    parser.add_argument("--allow-exploit", action="store_true", help="permit exploitation when generating a document")


def _add_scan_controls(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--max-rps", type=float, default=None, help="requests per second ceiling")
    parser.add_argument("--concurrency", type=int, default=None, help="parallel workers")
    parser.add_argument("--max-pages", type=int, default=None, help="crawl page ceiling")
    parser.add_argument("--max-endpoints", type=int, default=None, help="endpoint ceiling")
    parser.add_argument("--timeout", type=float, default=None, help="per-request timeout in seconds")
    parser.add_argument("--detectors", default="", help="comma separated detector ids to run")
    parser.add_argument("--exclude-detectors", default="", help="comma separated detector ids to skip")
    parser.add_argument("--categories", default="", help="comma separated categories to run")
    parser.add_argument("--min-severity", default=None, choices=["info", "low", "medium", "high", "critical"])
    parser.add_argument("--no-crawl", action="store_true", help="skip crawling")
    parser.add_argument("--no-discover", action="store_true", help="skip content discovery")
    parser.add_argument("--no-intrusive", action="store_true", help="use only passive detectors")
    parser.add_argument("--no-subdomains", action="store_true", help="skip subdomain enumeration")
    parser.add_argument("--header", action="append", default=[], metavar="NAME:VALUE", help="extra request header")
    parser.add_argument("--cookie", default="", help="cookie header value")
    parser.add_argument("--proxy", default="", help="HTTP proxy URL")
    parser.add_argument("--insecure", action="store_true", help="do not verify TLS certificates")


def build_parser() -> Parser:
    parser = Parser(
        prog=PROGRAM,
        description="Candix — offensive security harness: discovery, exploitation and reporting.",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"{PROGRAM} {VERSION}")
    subparsers = parser.add_subparsers(dest="command", metavar="COMMAND", parser_class=Parser)

    scan = subparsers.add_parser("scan", help="recon, detect and report findings", formatter_class=argparse.RawDescriptionHelpFormatter)
    scan.add_argument("targets", nargs="+", help="base URLs or hosts to assess")
    _add_common(scan)
    _add_scope(scan)
    _add_scan_controls(scan)
    scan.add_argument("--exploit", action="store_true", help="exploit confirmed findings after detection")
    scan.add_argument("--max-proofs", type=int, default=None, help="maximum number of exploitation proofs")
    scan.add_argument("--formats", default=FORMATS, help=f"report formats (default: {FORMATS})")
    scan.add_argument("--out", "-o", default=None, help="report directory (default: reports/<scan id>)")
    scan.add_argument("--artifacts", default=None, help="artifact directory for evidence")
    scan.add_argument("--archive", action="store_true", help="package the report bundle as a zip archive")
    scan.add_argument("--fail-on", default="none", choices=["none", "low", "medium", "high", "critical"],
                      help="exit non-zero when a finding at or above this severity exists")
    scan.add_argument("--no-report", action="store_true", help="skip report generation")

    exploit = subparsers.add_parser("exploit", help="detect and exploit, printing proofs as they succeed")
    exploit.add_argument("targets", nargs="+", help="base URLs or hosts to assess")
    _add_common(exploit)
    _add_scope(exploit)
    _add_scan_controls(exploit)
    exploit.add_argument("--max-proofs", type=int, default=None)
    exploit.add_argument("--output-dir", default=None, help="directory for extracted proof artifacts")
    exploit.add_argument("--techniques", default="", help="comma separated techniques to attempt")
    exploit.add_argument("--formats", default="", help="also write reports in these formats")
    exploit.add_argument("--out", "-o", default=None, help="report directory")

    report = subparsers.add_parser("report", help="render reports from a saved scan JSON")
    report.add_argument("inputs", nargs="+", help="scan JSON files produced by 'candix scan --formats json'")
    report.add_argument("--formats", default=FORMATS, help="output formats")
    report.add_argument("--out", "-o", default="reports", help="output directory")
    report.add_argument("--min-severity", default="info", choices=["info", "low", "medium", "high", "critical"])
    report.add_argument("--title", default=None)
    report.add_argument("--archive", action="store_true")
    report.add_argument("--no-evidence", action="store_true", help="omit request/response bodies")
    report.add_argument("--compare", action="store_true", help="produce a trend comparison when two inputs are given")
    report.add_argument("--json", dest="json_output", action="store_true", help="print a machine-readable summary")

    agent = subparsers.add_parser("agent", help="run the autonomous agent against a goal")
    agent.add_argument("targets", nargs="*", help="target URLs or host:port pairs")
    agent.add_argument("--goal", "-g", default="assess the target and prove the most severe issue")
    agent.add_argument("--autonomy", default="assist", choices=["observe", "assist", "bounded", "auto"])
    agent.add_argument("--exploit", action="store_true", help="allow exploitation intents inside the budget")
    agent.add_argument("--turns", type=int, default=12, help="maximum plan/act turns")
    agent.add_argument("--intents", type=int, default=40, help="maximum intents executed")
    agent.add_argument("--tool-calls", type=int, default=80, help="maximum tool invocations")
    agent.add_argument("--seconds", type=float, default=900.0, help="wall-clock budget")
    agent.add_argument("--tokens", type=int, default=200000, help="model token budget")
    agent.add_argument("--cost", type=float, default=0.0, help="model cost budget in USD (0 = unlimited)")
    agent.add_argument("--approvals", default="ask", choices=["ask", "auto"], help="how approvals are resolved")
    agent.add_argument("--model", default="", help="model name for the planner/worker (default: provider default)")
    agent.add_argument("--provider", default="", choices=["", "openai", "anthropic", "ollama"], help="LLM provider")
    agent.add_argument("--no-llm", action="store_true", help="plan with the deterministic planner only")
    agent.add_argument("--skills", default="", help="directory with SKILL.md files")
    agent.add_argument("--memory", default="", help="lesson store (JSON) to read and update")
    agent.add_argument("--journal", default="", help="append-only run journal path")
    agent.add_argument("--artifacts", default="", help="directory for evidence and approvals")
    agent.add_argument("--formats", default="markdown,json", help="run report formats")
    agent.add_argument("--out", "-o", default="agent-runs", help="report directory")
    agent.add_argument("--playbook", default="", help="seed the run with a named playbook (see --list-playbooks)")
    agent.add_argument("--playbook-limit", type=int, default=0, help="stop seeding after N playbook steps")
    agent.add_argument("--list-playbooks", action="store_true", help="print the playbooks and exit")
    agent.add_argument("--adaptive", action="store_true", help="let the planner choose tests by evidence value and bandit feedback")
    agent.add_argument("--adaptive-strategy", default="ucb", choices=["ucb", "thompson"], help="exploration rule for the adaptive planner")
    agent.add_argument("--explore-ratio", type=float, default=0.3, help="share of turns reserved for exploration")
    agent.add_argument("--priors", default="", help="path to the cross-run priors file")
    agent.add_argument("--no-priors", action="store_true", help="do not read or write cross-run priors")
    agent.add_argument("--metrics", default="", help="write Prometheus metrics to this path")
    agent.add_argument("--resume", default="", help="resume from a saved session state (JSON)")
    agent.add_argument("--dry-run", action="store_true", help="plan and gate only; execute nothing")
    agent.add_argument("--no-gate", action="store_true", help="disable the intercept gate (risk and target checks)")
    agent.add_argument("--gate-max-risk", type=int, default=70, help="risk at or above which a tool call is refused")
    agent.add_argument("--allow-command", action="append", default=[], metavar="PREFIX",
                       help="argv prefix the gate may allow for command tools (repeatable)")
    agent.add_argument("--allow-private", action="store_true", help="permit private and loopback targets outside the engagement")
    agent.add_argument("--notify-webhook", default="", help="POST the run summary to this webhook")
    agent.add_argument("--notify-slack", default="", help="Slack incoming webhook for the run summary")
    agent.add_argument("--notify-file", default="", help="append the run summary to this file")
    agent.add_argument("--notify-command", action="append", default=[], metavar="CMD",
                       help="run this command with the summary on stdin (gated, repeatable)")
    agent.add_argument("--notify-min-severity", default="high",
                       choices=["info", "low", "medium", "high", "critical"],
                       help="only notify when a finding reaches this severity")
    agent.add_argument("--no-poc", action="store_true", help="skip the proof-of-concept bundle")
    agent.add_argument("--no-review", action="store_true", help="skip the reviewer board")
    agent.add_argument("--no-todos", action="store_true", help="do not keep a todo list")
    agent.add_argument("--no-targeting", action="store_true", help="do not rank endpoints for the planner")
    _add_common(agent)
    _add_scope(agent)

    authorize = subparsers.add_parser("authorize", help="create an authorization and scope document")
    authorize.add_argument("--engagement", required=True, help="engagement name, e.g. q4-external")
    authorize.add_argument("--client", required=True, help="client or asset owner")
    authorize.add_argument("--operator", default=os.environ.get("USER", "operator"))
    authorize.add_argument("--by", dest="authorized_by", required=True, help="person who approved the work")
    authorize.add_argument("--include", action="append", required=True, help="in-scope host, CIDR or URL (repeatable)")
    authorize.add_argument("--exclude", action="append", default=[], help="explicitly excluded host or URL")
    authorize.add_argument("--expires-in-days", type=int, default=30)
    authorize.add_argument("--contact", default="")
    authorize.add_argument("--reference", default="", help="ticket or contract reference")
    authorize.add_argument("--allow-exploit", action="store_true")
    authorize.add_argument("--no-intrusive", action="store_true")
    authorize.add_argument("--max-rps", type=float, default=5.0)
    authorize.add_argument("--out", "-o", default=None, help="output path (default: engagements/<name>.json)")

    detectors = subparsers.add_parser("detectors", help="list detectors and their metadata")
    detectors.add_argument("--category", default="", help="filter by category")
    detectors.add_argument("--json", dest="json_output", action="store_true")
    detectors.add_argument("--verbose", "-v", action="store_true")

    payloads = subparsers.add_parser("payloads", help="inspect the payload catalogue")
    payloads.add_argument("family", nargs="?", default="", help="payload family to print")
    payloads.add_argument("--limit", type=int, default=25)
    payloads.add_argument("--json", dest="json_output", action="store_true")

    lab = subparsers.add_parser("lab", help="run the deliberately vulnerable lab application")
    lab.add_argument("--host", default="127.0.0.1")
    lab.add_argument("--port", type=int, default=8099)
    lab.add_argument("--scan", action="store_true", help="immediately assess the lab with exploitation enabled")
    lab.add_argument("--serve", action="store_true", help="keep serving until interrupted")
    lab.add_argument("--formats", default="html,json,markdown")
    lab.add_argument("--out", "-o", default=None)
    lab.add_argument("--max-proofs", type=int, default=8)
    _add_common(lab)

    fuzz = subparsers.add_parser("fuzz", help="mutation fuzzing of parameters and payload locations")
    fuzz.add_argument("targets", nargs="+")
    _add_common(fuzz)
    _add_scope(fuzz)
    _add_scan_controls(fuzz)
    fuzz.add_argument("--iterations", type=int, default=500, help="total requests to send")
    fuzz.add_argument("--seed", type=int, default=None, help="deterministic random seed")
    fuzz.add_argument("--strategy", default="balanced",
                      choices=["balanced", "boundary", "injection", "encoding", "structural", "chaos"])
    fuzz.add_argument("--param", action="append", default=[], help="restrict to this parameter name")
    fuzz.add_argument("--save-corpus", default=None, help="write the interesting responses to this directory")
    fuzz.add_argument("--stop-on-finding", action="store_true")

    tui = subparsers.add_parser("tui", help="interactive terminal dashboard")
    tui.add_argument("targets", nargs="*", help="targets to assess (optional: can be entered interactively)")
    _add_common(tui)
    _add_scope(tui)
    tui.add_argument("--exploit", action="store_true")
    tui.add_argument("--max-proofs", type=int, default=6)

    doctor = subparsers.add_parser("doctor", help="check the environment and configuration")
    doctor.add_argument("--json", dest="json_output", action="store_true")

    config = subparsers.add_parser("config", help="show the resolved configuration")
    config.add_argument("--config", "-c", default=None)
    config.add_argument("--profile", default=None)
    config.add_argument("--section", default="", help="only show one section")
    config.add_argument("--json", dest="json_output", action="store_true")

    export = subparsers.add_parser("export", help="produce operational artefacts from a saved scan")
    export.add_argument("report", help="scan JSON produced by 'candix scan --formats json'")
    export.add_argument("--out", "-o", default="exports")
    export.add_argument("--tracker", action="store_true", help="write the remediation tracker CSV")
    export.add_argument("--junit", action="store_true", help="write JUnit XML for CI dashboards")
    export.add_argument("--notebook", action="store_true", help="write a Jupyter notebook")
    export.add_argument("--slides", action="store_true", help="write a markdown slide deck")
    export.add_argument("--replay", action="store_true", help="write curl replay scripts for proofs")
    export.add_argument("--siem", default="", choices=["", "cef", "leef", "syslog", "ndjson"])
    export.add_argument("--fail-on", default="high", choices=["none", "low", "medium", "high", "critical"])
    export.add_argument("--json", dest="json_output", action="store_true")

    shell = subparsers.add_parser("shell", help="interactive shell for exploratory work")
    shell.add_argument("targets", nargs="*", help="targets to preload")
    _add_common(shell)
    shell.add_argument("--authorized", default="", help="operator name used for temporary authorizations")

    api = subparsers.add_parser("api", help="serve the HTTP API used by CI pipelines")
    api.add_argument("--host", default="127.0.0.1")
    api.add_argument("--port", type=int, default=8088)
    api.add_argument("--token", default=None, help="bearer token (default: CANDIX_API_TOKEN)")
    api.add_argument("--allow-anonymous", action="store_true", help="serve without authentication (local only)")
    api.add_argument("--artifacts", default="artifacts/api")
    api.add_argument("--cors-origin", default="")

    notify = subparsers.add_parser("notify", help="send a saved report to chat, ticketing or SIEM targets")
    notify.add_argument("report", help="scan JSON produced by 'candix scan --formats json'")
    notify.add_argument("--integration", action="append", required=True, help="integration name (repeatable)")
    notify.add_argument("--endpoint", default="", help="webhook or API endpoint")
    notify.add_argument("--token", default="", help="bearer/basic token for the target")
    notify.add_argument("--secret", default="", help="HMAC secret for signed webhooks")
    notify.add_argument("--project", default="", help="project key or id (Jira, GitHub, GitLab)")
    notify.add_argument("--link", default="", help="report URL included in the message")
    notify.add_argument("--min-severity", default="info", choices=["info", "low", "medium", "high", "critical"])
    notify.add_argument("--siem-format", default="", choices=["", "cef", "leef", "syslog", "ndjson"])
    notify.add_argument("--json", dest="json_output", action="store_true")

    playbooks = subparsers.add_parser("playbooks", help="show the exploitation and verification playbooks")
    playbooks.add_argument("ids", nargs="*", help="playbook ids to print (default: all)")
    playbooks.add_argument("--for-report", default="", help="select playbooks matching a saved scan JSON")
    playbooks.add_argument("--json", dest="json_output", action="store_true")

    compare = subparsers.add_parser("compare", help="compare two saved scans and show what changed")
    compare.add_argument("before")
    compare.add_argument("after")
    compare.add_argument("--json", dest="json_output", action="store_true")
    compare.add_argument("--out", "-o", default=None, help="write a markdown comparison")

    bundle = subparsers.add_parser("bundle", help="package an agent run for delivery")
    bundle.add_argument("path", help="run directory produced with --out")
    bundle.add_argument("--verify", action="store_true", help="verify hashes instead of packaging")
    bundle.add_argument("--zip", default="", help="also write a zip archive here")
    bundle.add_argument("--prune", action="store_true", help="drop logs and metrics after packaging")
    bundle.add_argument("--json", dest="json_output", action="store_true", help="machine-readable output")

    agent_diff = subparsers.add_parser("agent-diff", help="compare two agent run JSON documents")
    agent_diff.add_argument("before", help="earlier agent JSON")
    agent_diff.add_argument("after", help="later agent JSON")
    agent_diff.add_argument("--fail-on", default="high", choices=["low", "medium", "high", "critical"], help="severity that fails the gate")
    agent_diff.add_argument("--allow-new", type=int, default=0, help="how many new findings of that severity are tolerated")
    agent_diff.add_argument("--out", default="", help="write the markdown table here")
    agent_diff.add_argument("--json", dest="json_output", action="store_true", help="machine-readable output")

    gate = subparsers.add_parser("gate", help="ask the intercept gate what it would do with a command")
    gate.add_argument("argv", nargs="+", help="command to score (quote it or pass tokens)")
    gate.add_argument("--target", action="append", default=[], help="target the command would touch (repeatable)")
    gate.add_argument("--allow-prefix", action="append", default=[], metavar="PREFIX",
                      help="argv prefix rule to try (repeatable)")
    gate.add_argument("--max-risk", type=int, default=70, help="risk at or above which the command is refused")
    gate.add_argument("--allow-private", action="store_true", help="permit private, loopback and link-local targets")
    gate.add_argument("--json", dest="json_output", action="store_true", help="machine-readable output")

    harness = subparsers.add_parser("harness", help="show every capability wired to a run")
    harness.add_argument("--json", dest="json_output", action="store_true", help="machine-readable output")
    harness.add_argument("--target", action="append", default=[], help="check this target against a fresh target gate")
    harness.add_argument("--run", default="", help="read the harness block from a saved run session.json")

    review = subparsers.add_parser("review", help="work with the reviewer board of a finished run")
    review.add_argument("path", help="run directory or review.json")
    review.add_argument("--approve", action="store_true", help="approve every review whose checklist is complete")
    review.add_argument("--reviewer", default=os.environ.get("USER", "operator"), help="name recorded on approval")
    review.add_argument("--markdown", action="store_true", help="print the board as markdown")
    review.add_argument("--json", dest="json_output", action="store_true", help="machine-readable output")

    version = subparsers.add_parser("version", help="print the version and build information")
    version.add_argument("--json", dest="json_output", action="store_true")

    for sub in (scan, exploit, report, fuzz, lab, tui):
        sub.epilog = EPILOG
    return parser


def split_csv(value: str | None) -> list[str]:
    if not value:
        return []
    return [part.strip() for part in str(value).replace(";", ",").split(",") if part.strip()]


def parse_headers(values: Sequence[str]) -> dict[str, str]:
    headers: dict[str, str] = {}
    for item in values:
        if ":" not in item:
            raise SystemExit(f"invalid header {item!r}: expected NAME:VALUE")
        name, _, value = item.partition(":")
        headers[name.strip()] = value.strip()
    return headers


def parse_overrides(values: Sequence[str]) -> dict[str, Any]:
    overrides: dict[str, Any] = {}
    for item in values:
        if "=" not in item:
            raise SystemExit(f"invalid override {item!r}: expected key=value")
        key, _, raw = item.partition("=")
        key = key.strip()
        if not key:
            raise SystemExit(f"invalid override {item!r}: empty key")
        overrides[key] = _coerce(raw.strip())
    return overrides


def _coerce(value: str) -> Any:
    lowered = value.lower()
    if lowered in {"true", "yes", "on"}:
        return True
    if lowered in {"false", "no", "off"}:
        return False
    if lowered in {"none", "null"}:
        return None
    try:
        return int(value)
    except ValueError:
        pass
    try:
        return float(value)
    except ValueError:
        return value
