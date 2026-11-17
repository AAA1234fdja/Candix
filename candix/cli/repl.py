"""Interactive shell for exploratory use."""

from __future__ import annotations

import cmd
import json
import shlex
import sys
import time
from pathlib import Path
from typing import Any

from candix import VERSION
from candix.cli import output as out
from candix.core.errors import CandixError
from candix.exploit.session import Session

HELP = """
Commands
  target <url> [url ...]   add targets to the session
  scope                    show the current targets and authorization state
  authorize                create a temporary authorization for the targets
  set <key> <value>        override a configuration value
  config                   show overrides
  scan [--exploit]         run an assessment against the session targets
  findings [filter]        list findings (filter: severity)
  show <index>             print one finding in full
  report [formats]         write reports for the last scan
  payloads <family>        print catalogue payloads
  playbook <id>            print a playbook
  save <file>              save the session (targets, overrides, findings)
  load <file>              load a saved session
  quit                     leave the shell
"""


class Shell(cmd.Cmd):
    intro = out.banner(VERSION, subtitle="interactive shell · type help for commands")
    prompt = out.paint("candix> ", "cyan")

    def __init__(self, targets: list[str] | None = None, *, config: Any = None, authorized: str = "") -> None:
        super().__init__()
        self.targets = list(targets or [])
        self.config = config
        self.overrides: dict[str, str] = {}
        self.authorized = authorized
        self.findings: list[Any] = []
        self.last_scan_id = ""
        self.report_paths: dict[str, str] = {}
        self.session: Session | None = None
        self.context: Any = None
        self.started = time.time()

    # ------------------------------------------------------------------
    def emptyline(self) -> bool:
        return False

    def default(self, line: str) -> None:
        self.stdout.write(f"unknown command: {line.split()[0] if line.split() else line}\n")

    def do_help(self, arg: str) -> None:
        self.stdout.write(HELP)

    def do_target(self, arg: str) -> None:
        if not arg.strip():
            self.stdout.write("usage: target <url> [url ...]\n")
            return
        added = 0
        for target in shlex.split(arg):
            if target not in self.targets:
                self.targets.append(target)
                added += 1
        self.stdout.write(f"added {added} target(s); {len(self.targets)} in session\n")

    def do_scope(self, arg: str) -> None:
        rows = [("targets", len(self.targets))]
        for index, target in enumerate(self.targets, start=1):
            rows.append((f"  #{index}", target))
        rows.append(("authorization", self.authorized or "none (use authorize)"))
        self.stdout.write(out.kv_table(rows, indent=2) + "\n")

    def do_authorize(self, arg: str) -> None:
        operator = arg.strip() or "operator"
        if not self.targets:
            self.stdout.write("add targets first\n")
            return
        self.authorized = operator
        self.stdout.write(f"temporary authorization recorded for {operator}\n")

    def do_set(self, arg: str) -> None:
        parts = arg.split(maxsplit=1)
        if len(parts) != 2:
            self.stdout.write("usage: set <dotted.key> <value>\n")
            return
        key, value = parts
        self.overrides[key] = value
        try:
            self.config.set(key, _coerce(value))
        except CandixError as exc:
            self.stdout.write(f"{out.paint('error', 'red')} {exc}\n")
            return
        self.stdout.write(f"{key} = {value}\n")

    def do_config(self, arg: str) -> None:
        if not self.overrides:
            self.stdout.write("no overrides\n")
            return
        self.stdout.write(out.kv_table(sorted(self.overrides.items()), indent=2) + "\n")

    # ------------------------------------------------------------------
    def _bootstrap(self) -> Any:
        """Build a minimal context so ad-hoc requests share the engagement client."""

        from candix import build_context
        from candix.core.scope import Engagement, build_authorization

        if self.context is None:
            document = build_authorization(
                engagement=f"shell-{int(self.started)}",
                client="shell",
                operator=self.authorized or "shell",
                authorized_by=self.authorized or "shell",
                include=[_scope(target) for target in self.targets],
                allow_exploit=False,
                max_rps=float(self.config.get("scan.max_rps") or 5.0),
            )
            self.context = build_context(self.targets, config=self.config, engagement=Engagement.from_document(document))
        return self.context

    def _ensure_session(self, context: Any) -> Session:
        if self.session is None:
            base = ""
            if getattr(context, "targets", None):
                base = context.targets[0].base_url
            self.session = Session(context.http, base)
        return self.session

    def do_scan(self, arg: str) -> None:
        from candix.engine import scan

        if not self.targets:
            self.stdout.write("add targets first (target <url>)\n")
            return
        exploit = "--exploit" in arg.split()
        if not self.authorized:
            self.stdout.write("run 'authorize <operator>' before scanning\n")
            return
        from candix.core.scope import Engagement, build_authorization
        from candix.cli.progress import ScanProgress

        document = build_authorization(
            engagement=f"shell-{int(self.started)}",
            client="shell",
            operator=self.authorized,
            authorized_by=self.authorized,
            include=[_scope(target) for target in self.targets],
            allow_exploit=exploit,
            max_rps=float(self.config.get("scan.max_rps") or 5.0),
        )
        progress = ScanProgress(verbose=False)
        try:
            result = scan(self.targets, config=self.config, engagement=Engagement.from_document(document), exploit=exploit, on_progress=progress.handle)
        except CandixError as exc:
            self.stdout.write(f"{out.paint('error', 'red')} {exc}\n")
            return
        self.findings = result.findings.sorted()
        self.last_scan_id = result.context.id
        counts = result.summary().get("findings") or {}
        self.stdout.write(f"\n{out.counts_bar(counts)} in {result.duration:.1f}s\n")

    def do_findings(self, arg: str) -> None:
        if not self.findings:
            self.stdout.write("no findings yet (run scan)\n")
            return
        severity = arg.strip().lower()
        selected = [item for item in self.findings if not severity or item.severity.value == severity]
        for index, finding in enumerate(selected, start=1):
            self.stdout.write(f"{str(index).rjust(3)}. {out.finding_line(finding)}\n")
        self.stdout.write(f"{len(selected)} of {len(self.findings)} findings\n")

    def do_show(self, arg: str) -> None:
        try:
            index = int(arg.strip()) - 1
        except ValueError:
            self.stdout.write("usage: show <index>\n")
            return
        if not 0 <= index < len(self.findings):
            self.stdout.write("index out of range\n")
            return
        self.stdout.write(out.finding_block(self.findings[index]) + "\n")

    def do_report(self, arg: str) -> None:
        if not self.findings:
            self.stdout.write("nothing to report yet\n")
            return
        self.stdout.write("reports are produced by the scan command; use 'candix report' on the saved JSON\n")

    def do_payloads(self, arg: str) -> None:
        from candix.catalog.payloads import families, get_payloads

        family = arg.strip()
        if not family:
            self.stdout.write(", ".join(families()) + "\n")
            return
        for payload in get_payloads(family)[:20]:
            self.stdout.write(f"  {payload}\n")

    def do_playbook(self, arg: str) -> None:
        from candix.playbooks import playbook
        from candix.playbooks.engine import PlaybookMatch, render_playbook_markdown

        book = playbook(arg.strip())
        if book is None:
            self.stdout.write("unknown playbook\n")
            return
        match = PlaybookMatch(playbook=book, finding_ids=[], severity=book.severity_hint, reason="manual")
        self.stdout.write(render_playbook_markdown(match) + "\n")

    # ------------------------------------------------------------------
    def do_save(self, arg: str) -> None:
        target = Path(arg.strip() or f"session-{self.last_scan_id or int(self.started)}.json")
        payload = {
            "version": VERSION,
            "targets": list(self.targets),
            "authorized": self.authorized,
            "overrides": dict(self.overrides),
            "last_scan_id": self.last_scan_id,
            "findings": [finding.to_dict(include_evidence=False) for finding in self.findings],
        }
        target.write_text(json.dumps(payload, indent=2, sort_keys=True, default=str), encoding="utf-8")
        self.stdout.write(f"saved to {target}\n")

    def do_load(self, arg: str) -> None:
        path = Path(arg.strip())
        if not path.exists():
            self.stdout.write("file not found\n")
            return
        payload = json.loads(path.read_text(encoding="utf-8"))
        self.targets = list(payload.get("targets") or [])
        self.authorized = str(payload.get("authorized") or "")
        self.overrides = dict(payload.get("overrides") or {})
        self.last_scan_id = str(payload.get("last_scan_id") or "")
        self.stdout.write(f"loaded {len(self.targets)} target(s) from {path}\n")

    def do_request(self, arg: str) -> None:
        """request METHOD PATH [-H 'Name: value'] [-d body] — send a raw HTTP request."""

        if not arg.strip():
            self.stdout.write("usage: request GET /path\n")
            return
        if not self.targets:
            self.stdout.write("add a target first (target <url>)\n")
            return
        try:
            session = self._ensure_session(self._bootstrap())
            exchange = session.run(arg)
        except Exception as error:  # pragma: no cover - interactive path
            self.stdout.write(f"request failed: {error}\n")
            return
        self.stdout.write(out.paint(exchange.summary(), "bold") + "\n")
        self.stdout.write(exchange.preview() + "\n")

    def do_history(self, arg: str) -> None:
        """history — show recent requests from this shell."""

        if self.session is None:
            self.stdout.write("no requests yet\n")
            return
        self.stdout.write(self.session.history_text() + "\n")

    def do_header(self, arg: str) -> None:
        """header NAME VALUE — add a header to every subsequent request."""

        if self.session is None or not arg.strip():
            self.stdout.write("usage: header Authorization 'Bearer …'\n")
            return
        name, _, value = arg.partition(" ")
        self.session.set_header(name, value.strip().strip("'\""))
        self.stdout.write(f"header {name} updated\n")

    def do_quit(self, arg: str) -> bool:
        self.stdout.write("bye\n")
        return True

    do_exit = do_quit
    do_EOF = do_quit


def _coerce(value: str) -> Any:
    if value.lower() in {"true", "false"}:
        return value.lower() == "true"
    try:
        return int(value)
    except ValueError:
        pass
    try:
        return float(value)
    except ValueError:
        return value


def _scope(target: str) -> str:
    from candix.net.url import URL

    try:
        url = URL.parse(target if "://" in target else f"http://{target}")
    except ValueError:
        return target
    return f"{url.host}:{url.port or (443 if url.scheme == 'https' else 80)}"


def run_shell(targets: list[str] | None = None, *, config: Any, authorized: str = "") -> int:
    shell = Shell(targets, config=config, authorized=authorized)
    try:
        shell.cmdloop()
    except KeyboardInterrupt:
        sys.stdout.write("\n")
    return 0
