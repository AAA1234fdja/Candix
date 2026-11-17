from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from candix.agent import intercept, notify, poc, review, targeting, todolist

TARGET_ARGS = ("url", "target", "host", "endpoint", "base_url")
TARGET_LIST_ARGS = ("targets", "urls", "hosts")

CAPABILITIES: tuple[tuple[str, str, str], ...] = (
    ("gate", "candix.agent.intercept", "risk gate on every tool call and argv prefix rules"),
    ("targets", "candix.agent.intercept", "target normalisation and dial-time scope check"),
    ("policy", "candix.agent.policy", "intent risk, autonomy and approval decisions"),
    ("guard", "candix.agent.guard", "scope guard, deny lists, red lines, untrusted framing"),
    ("budget", "candix.agent.budget", "task, intent, tool-call and token budgets"),
    ("adaptive", "candix.agent.adaptive", "hypotheses, anomaly scores and bandit choice"),
    ("priors", "candix.agent.learning", "cross-run priors that survive the process"),
    ("targeting", "candix.agent.targeting", "ranked next targets for the planner"),
    ("todos", "candix.agent.todolist", "durable todo list the planner reads back"),
    ("poc", "candix.agent.poc", "curl/python/js reproductions for each finding"),
    ("review", "candix.agent.review", "reviewer checklist per finding"),
    ("notify", "candix.agent.notify", "webhook, file and gated command channels"),
    ("evidence", "candix.agent.evidence_chain", "hash-chained evidence record"),
    ("audit", "candix.agent.audit", "who was allowed to do what, and why"),
    ("scorecard", "candix.agent.scorecard", "coverage and quality scored per run"),
    ("triage", "candix.agent.triage", "findings ranked by exploitability"),
    ("compliance", "candix.agent.compliance", "ASVS and control mapping"),
    ("insights", "candix.agent.insights", "per-tool yield and cost per finding"),
    ("bundle", "candix.agent.reports_bundle", "self-verifying delivery package"),
)


@dataclass
class HarnessSettings:
    gate: bool = True
    allowed_prefixes: tuple[str, ...] = ()
    max_risk: int = intercept.RISK_HIGH
    allow_private: bool = False
    notify: dict[str, Any] = field(default_factory=dict)
    notify_min_severity: str = "high"
    poc: bool = True
    review: bool = True
    todos: bool = True
    targeting: bool = True
    artifacts: str = ""
    engine: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "gate": self.gate,
            "max_risk": self.max_risk,
            "allowed_prefixes": list(self.allowed_prefixes),
            "allow_private": self.allow_private,
            "notify": sorted(dict(self.notify).keys()),
            "notify_min_severity": self.notify_min_severity,
            "poc": self.poc,
            "review": self.review,
            "todos": self.todos,
            "targeting": self.targeting,
            "artifacts": self.artifacts,
            "engine": dict(self.engine),
        }


class Harness:
    def __init__(self, *, targets: Iterable[str] = (), settings: HarnessSettings | None = None) -> None:
        self.settings = settings or HarnessSettings()
        self.targets = tuple(str(item) for item in targets)
        self.artifacts = Path(self.settings.artifacts) if self.settings.artifacts else None
        self.target_gate = intercept.TargetGate(
            allow=self.targets,
            allow_private=self.settings.allow_private,
        )
        self.command_gate = intercept.CommandGate(
            allowed_prefixes=self.settings.allowed_prefixes,
            max_risk=self.settings.max_risk,
            targets=self.targets,
            allow_private=self.settings.allow_private,
        )
        engine_cfg = self.settings.engine or {}
        try:
            from candix.engine_bridge.config import BridgeConfig

            if isinstance(engine_cfg, BridgeConfig):
                self.bridge_config = engine_cfg
            elif isinstance(engine_cfg, dict) and engine_cfg:
                self.bridge_config = BridgeConfig.from_config({"engine": engine_cfg})
            else:
                self.bridge_config = BridgeConfig.from_env()
                if not engine_cfg and not self.bridge_config.enabled:
                    self.bridge_config = BridgeConfig()
                    self.bridge_config.enabled = False
                if isinstance(engine_cfg, dict) and "enabled" in engine_cfg:
                    self.bridge_config.enabled = bool(engine_cfg["enabled"])
            if self.bridge_config.enabled:
                from candix.engine_bridge.client import EngineClient
                from candix.engine_bridge.intercept_proxy import InterceptProxy

                self.engine_client = EngineClient(self.bridge_config)
                self.intercept_proxy = InterceptProxy(self.bridge_config)
            else:
                self.engine_client = None
                self.intercept_proxy = None
        except Exception:
            self.bridge_config = None
            self.engine_client = None
            self.intercept_proxy = None
        self.router = notify.from_config(dict(self.settings.notify), gate=self.command_gate) if self.settings.notify else None
        self.board = review.ReviewBoard(path=str(self.artifacts / "review.json") if self.artifacts else "")
        self.todos = todolist.TodoList(str(self.artifacts / "todos.json") if (self.artifacts and self.settings.todos) else "")
        self.blocked: list[dict[str, Any]] = []
        self.tool_checks = 0
        self.deliveries: list[dict[str, Any]] = []
        self.poc_files: list[str] = []
        self.written: dict[str, str] = {}
        self._todos_by_title: dict[str, Any] = {}
        self.dual_events: list[dict[str, Any]] = []

    def check_target(self, value: str) -> intercept.Decision:
        return self.target_gate.check(value)

    def check_tool(self, tool: str, arguments: dict[str, Any] | None = None) -> intercept.Decision | None:
        if not self.settings.gate:
            return None
        self.tool_checks += 1
        arguments = dict(arguments or {})
        for key in TARGET_ARGS:
            value = arguments.get(key)
            if isinstance(value, str) and value.strip():
                decision = self.target_gate.check(value)
                if not decision.allowed:
                    return self._record_block("target", f"{tool}:{key}", decision)
                if self.engine_client is not None:
                    try:
                        dual = self.engine_client.normalize_target(value)
                        if dual.ok and dual.data.get("fail_safe"):
                            disc = dual.data.get("discrepancy")
                            self.dual_events.append({"kind": "target", "target": value, "dual": dual.to_dict(), "discrepancy": disc})
                            if not decision.allowed:
                                pass
                    except Exception:
                        pass
        for key in TARGET_LIST_ARGS:
            values = arguments.get(key)
            if isinstance(values, (list, tuple)):
                for value in values:
                    decision = self.target_gate.check(str(value))
                    if not decision.allowed:
                        return self._record_block("target", f"{tool}:{key}", decision)
        if self.bridge_config is not None and getattr(self.bridge_config, "enabled", False):
            try:
                used, report = intercept.score_via_engine(tool, arguments, bridge_config=self.bridge_config)
                if used and hasattr(report, "data"):
                    data = report.data
                    risk = intercept.RiskReport(int(data.get("score", 0)), level=str(data.get("level", "")), reasons=list(data.get("reasons", [])))
                    self.dual_events.append(
                        {
                            "tool": tool,
                            "source": report.source,
                            "python": data.get("python"),
                            "go": data.get("go"),
                            "go_error": data.get("go_error", ""),
                            "discrepancy": data.get("discrepancy"),
                            "consensus": data.get("consensus"),
                        }
                    )
                else:
                    risk = report  # type: ignore
            except Exception:
                risk = intercept.score_tool(tool, arguments)
        else:
            risk = intercept.score_tool(tool, arguments)
        if risk.score >= self.settings.max_risk:
            decision = intercept.Decision(
                False,
                f"risk {risk.score} at or above {self.settings.max_risk}: {risk.reasons[0] if risk.reasons else tool}",
                "risk",
                risk,
            )
            extra: dict[str, Any] | None = None
            if self.dual_events:
                last = self.dual_events[-1] if self.dual_events else None
                if last and last.get("tool") == tool:
                    extra = last
            return self._record_block("risk", tool, decision, dual=extra)
        return None

    def check_command(self, command: str, *, targets: Iterable[str] = ()) -> intercept.Decision:
        if self.intercept_proxy is not None:
            try:
                decision = self.intercept_proxy.check_command_gate(
                    command,
                    targets=list(targets) if targets else None,
                    allowed_prefixes=self.settings.allowed_prefixes,
                    max_risk=self.settings.max_risk,
                )
                if hasattr(decision, "dual"):
                    dual = getattr(decision, "dual", {}) or {}
                    self.dual_events.append({"kind": "command", "command": command[:160], "dual": dual, "discrepancy": dual.get("discrepancy"), "go_error": dual.get("go_error", "")})
                if not decision.allowed:
                    self._record_block("command", command[:160], decision, dual=getattr(decision, "dual", None))
                return decision
            except Exception:
                pass
        decision = self.command_gate.check(command, targets=targets)
        if not decision.allowed:
            self._record_block("command", command[:160], decision)
        return decision

    def _record_block(self, kind: str, subject: str, decision: intercept.Decision, *, dual: dict[str, Any] | None = None) -> intercept.Decision:
        entry: dict[str, Any] = {"kind": kind, "subject": subject[:200], "rule": decision.rule, "reason": decision.reason[:300]}
        if dual:
            if dual.get("discrepancy"):
                entry["discrepancy"] = dual["discrepancy"]
            if dual.get("go_error"):
                entry["go_error"] = dual["go_error"]
            if dual.get("consensus"):
                entry["consensus"] = dual["consensus"]
            if dual.get("source"):
                entry["source"] = dual["source"]
        if getattr(decision, "dual", None):
            d = getattr(decision, "dual") or {}
            if d.get("discrepancy") and "discrepancy" not in entry:
                entry["discrepancy"] = d["discrepancy"]
            if d.get("go_error") and "go_error" not in entry:
                entry["go_error"] = d["go_error"]
            if dual is None and d:
                entry["dual"] = {k: d[k] for k in ("python", "go", "go_error", "consensus", "discrepancy", "source") if k in d}
        self.blocked.append(entry)
        return decision

    def plan_extras(self, assets: Any, findings: Iterable[dict[str, Any]]) -> dict[str, Any]:
        extras: dict[str, Any] = {"next_targets": [], "todos": ""}
        if self.settings.targeting:
            try:
                extras["next_targets"] = [item.to_dict() for item in targeting.next_targets(assets, findings, limit=5)]
            except Exception:
                extras["next_targets"] = []
        if self.settings.todos:
            try:
                extras["todos"] = self.todos.prompt_block(limit=8)
            except Exception:
                extras["todos"] = ""
        return extras

    def on_event(self, kind: str, payload: dict[str, Any]) -> None:
        if not self.settings.todos:
            return
        title = str(payload.get("title", "") or "")
        if kind == "intent.start" and title:
            todo = self._todos_by_title.get(title)
            if todo is None:
                todo = self.todos.add(title, priority=0.5, tags=(str(payload.get("tool", "") or "intent"),))
                self._todos_by_title[title] = todo
            todo.claim("agent")
            self.todos.save()
        elif kind in {"intent.finish", "intent.blocked"} and title:
            todo = self._todos_by_title.get(title) or self._match(title)
            if todo is None:
                return
            if kind == "intent.finish" and payload.get("ok"):
                self.todos.complete(todo, evidence=[str(payload.get("summary", ""))[:120]])
            elif kind == "intent.blocked":
                self.todos.park(todo, str(payload.get("reason", ""))[:160])
            else:
                todo.park("attempt failed")
                self.todos.save()

    def _match(self, title: str) -> Any:
        for item in self.todos.items:
            if item.text == title:
                self._todos_by_title[title] = item
                return item
        return None

    def finish(self, result: Any, session: Any = None) -> dict[str, Any]:
        findings = list(getattr(result, "findings", []) or [])
        summary: dict[str, Any] = {
            "gate": self.gate_summary(),
            "blocked": len(self.blocked),
            "poc": 0,
            "review": {},
            "todos": {},
            "notify": {},
            "artifacts": {},
        }
        if self.settings.poc and self.artifacts is not None and findings:
            try:
                self.poc_files = poc.bundle_for(findings, self.artifacts / "poc")
                summary["poc"] = len(self.poc_files)
                self.written["poc"] = str(self.artifacts / "poc")
            except Exception as error:
                summary["poc_error"] = f"{type(error).__name__}: {error}"
        if self.settings.review:
            try:
                self.board.seed(findings)
                summary["review"] = self.board.summary()
                if self.artifacts is not None and self.board.reviews:
                    review_path = self.board.save(self.artifacts / "review.json")
                    markdown_path = self.artifacts / "review.md"
                    markdown_path.write_text(self.board.markdown(), encoding="utf-8")
                    self.written["review"] = review_path
                    self.written["review_markdown"] = str(markdown_path)
            except Exception as error:
                summary["review_error"] = f"{type(error).__name__}: {error}"
        if self.settings.todos:
            try:
                self.todos.seed_from_result(result)
                if self.artifacts is not None:
                    self.written["todos"] = self.todos.save()
                summary["todos"] = self.todos.summary()
            except Exception as error:
                summary["todos_error"] = f"{type(error).__name__}: {error}"
        if self.router is not None:
            try:
                summary["notify"] = self.dispatch(result, findings)
            except Exception as error:
                summary["notify"] = {"error": f"{type(error).__name__}: {error}"}
        summary["artifacts"] = dict(self.written)
        return summary

    def dispatch(self, result: Any, findings: Iterable[dict[str, Any]] | None = None) -> dict[str, Any]:
        rows = list(findings if findings is not None else getattr(result, "findings", []) or [])
        if not notify.should_notify(rows, min_severity=self.settings.notify_min_severity):
            return {"skipped": f"no finding at or above {self.settings.notify_min_severity}", "delivered": 0}
        message = notify.redact_message(notify.build_message(result))
        deliveries = self.router.dispatch(message) if self.router is not None else []
        self.deliveries = [item.to_dict() for item in deliveries]
        return {
            "delivered": sum(1 for item in deliveries if item.ok),
            "channels": len(deliveries),
            "summary": notify.summarize_deliveries(deliveries),
            "deliveries": self.deliveries,
        }

    def gate_summary(self) -> dict[str, Any]:
        engine_info: dict[str, Any] = {}
        try:
            if self.bridge_config is not None:
                engine_info = {"enabled": self.bridge_config.enabled, "parallel": self.bridge_config.parallel, "url": self.bridge_config.url, "mode": "parallel" if self.bridge_config.enabled and self.bridge_config.parallel else ("python-only" if not self.bridge_config.enabled else "go-preferente")}
                if self.dual_events:
                    engine_info["dual_events"] = self.dual_events[-20:]
                    engine_info["go_errors"] = [e.get("go_error") for e in self.dual_events if e.get("go_error")]
                    engine_info["discrepancies"] = [e.get("discrepancy") for e in self.dual_events if e.get("discrepancy")]
        except Exception:
            pass
        base: dict[str, Any] = {
            "enabled": self.settings.gate,
            "max_risk": self.settings.max_risk,
            "targets": list(self.targets),
            "allowed_prefixes": list(self.settings.allowed_prefixes),
            "checks": len(self.command_gate.audit),
            "tool_checks": self.tool_checks,
            "blocked": len(self.blocked),
            "entries": self.command_gate.summary()["entries"],
            "blocked_details": list(self.blocked[-20:]),
        }
        if engine_info:
            base["engine"] = engine_info
        if self.dual_events:
            base["dual_events"] = self.dual_events[-20:]
        return base

    def summary(self) -> dict[str, Any]:
        adaptive = getattr(self, "adaptive", None)
        payload: dict[str, Any] = {
            "settings": self.settings.to_dict(),
            "gate": self.gate_summary(),
            "todos": {"summary": self.todos.summary(), "open": [item.to_dict() for item in self.todos.open_items()[:10]]},
            "review": self.board.summary(),
            "poc": list(self.poc_files[:20]),
            "notify": {"channels": len(getattr(self.router, "channels", []) or []), "deliveries": self.deliveries},
            "artifacts": dict(self.written),
        }
        if adaptive is not None:
            payload["adaptive"] = adaptive
        return payload


def status() -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for name, module, detail in CAPABILITIES:
        try:
            __import__(module)
            state = "wired"
        except Exception as error:
            state = f"unavailable: {type(error).__name__}"
        rows.append({"capability": name, "module": module, "state": state, "detail": detail})
    return rows
