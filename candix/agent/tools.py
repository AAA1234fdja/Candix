"""Tool registry and the execution pipeline every tool call goes through.

The pipeline is the safety boundary: validate arguments against the published
schema, check scope and red lines, spend budget, run with a timeout, frame the
output as untrusted data, then record everything in the journal and telemetry.
A tool implementation never does those checks itself.
"""

from __future__ import annotations

import hashlib
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from candix.agent.budget import AgentBudget
from candix.agent.guard import OutputGuard, ScopeGuard, ScopeBlocked, SafetyDecision
from candix.agent.journal import Journal, NullJournal
from candix.agent.telemetry import Telemetry
from candix.llm.jsonschema import ValidationError, coerced
from candix.llm.types import ToolSpec


class ToolError(Exception):
    """The tool ran but failed in a way the model should see and can react to."""


@dataclass
class ToolResult:
    ok: bool
    output: str = ""
    data: dict[str, Any] = field(default_factory=dict)
    error: str = ""
    digest: str = ""
    duration: float = 0.0
    untrusted: bool = True
    decision: SafetyDecision | None = None
    truncated: bool = False
    brief: str = ""

    @property
    def summary(self) -> str:
        if self.brief:
            return self.brief[:160]
        text = (self.output or self.error or "").strip()
        first = text.splitlines()[0] if text else ""
        return first[:160]

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "output": self.output[:4000],
            "data": self.data,
            "error": self.error,
            "digest": self.digest,
            "duration": round(self.duration, 3),
            "truncated": self.truncated,
        }

    @classmethod
    def failure(cls, message: str, *, data: dict[str, Any] | None = None) -> "ToolResult":
        return cls(ok=False, error=message, data=dict(data or {}), untrusted=False)


@dataclass
class Tool:
    name: str
    description: str
    handler: Callable[["ToolContext", dict[str, Any]], "ToolResult | dict[str, Any] | str"]
    parameters: dict[str, Any] = field(default_factory=lambda: {"type": "object", "properties": {}})
    untrusted_output: bool = True
    max_calls: int = 40
    timeout: float = 120.0
    tags: tuple[str, ...] = ()
    calls: int = 0

    def spec(self) -> ToolSpec:
        return ToolSpec(name=self.name, description=self.description, parameters=self.parameters)


@dataclass
class ToolContext:
    """Everything a tool is allowed to touch."""

    guard: ScopeGuard = field(default_factory=ScopeGuard)
    output_guard: OutputGuard = field(default_factory=OutputGuard)
    budget: AgentBudget = field(default_factory=AgentBudget)
    telemetry: Telemetry = field(default_factory=Telemetry)
    journal: Journal | NullJournal | None = None
    artifacts: Path | None = None
    settings: dict[str, Any] = field(default_factory=dict)
    state: dict[str, Any] = field(default_factory=dict)
    interceptor: Any = None

    def path(self, name: str) -> Path | None:
        if self.artifacts is None:
            return None
        self.artifacts.mkdir(parents=True, exist_ok=True)
        return self.artifacts / name

    def save_artifact(self, name: str, content: str | bytes) -> str:
        target = self.path(name)
        if target is None:
            return ""
        data = content.encode("utf-8") if isinstance(content, str) else content
        target.write_bytes(data)
        return str(target)


class ToolRegistry:
    """Name → Tool, with schema-driven validation and safe execution."""

    def __init__(self, tools: list[Tool] | None = None) -> None:
        self.tools: dict[str, Tool] = {}
        for tool in tools or []:
            self.register(tool)

    def register(self, tool: Tool) -> Tool:
        self.tools[tool.name] = tool
        return tool

    def get(self, name: str) -> Tool | None:
        return self.tools.get(name)

    def names(self) -> list[str]:
        return sorted(self.tools)

    def specs(self) -> list[ToolSpec]:
        return [tool.spec() for tool in self.tools.values()]

    def schema(self, name: str) -> dict[str, Any]:
        tool = self.tools.get(name)
        return tool.parameters if tool else {}

    def describe(self) -> list[dict[str, Any]]:
        return [
            {"name": tool.name, "description": tool.description, "tags": list(tool.tags), "calls": tool.calls}
            for tool in self.tools.values()
        ]

    # ------------------------------------------------------------------
    def validate(self, name: str, arguments: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
        tool = self.tools.get(name)
        if tool is None:
            return {}, [f"unknown tool {name!r}; available: {', '.join(self.names())}"]
        value, errors = coerced(arguments, tool.parameters)
        return (value if isinstance(value, dict) else {}), [str(error) for error in errors]

    def execute(self, name: str, arguments: dict[str, Any], context: ToolContext) -> ToolResult:
        started = time.monotonic()
        tool = self.tools.get(name)
        if tool is None:
            return ToolResult.failure(f"unknown tool {name!r}")

        arguments = dict(arguments or {})
        clean, problems = self.validate(name, arguments)
        if problems:
            self._event(context, "tool.rejected", {"tool": name, "problems": problems})
            return ToolResult.failure("invalid arguments: " + "; ".join(problems))

        if tool.calls >= tool.max_calls:
            return ToolResult.failure(f"{name} exceeded its call allowance ({tool.max_calls})")

        decision = self._preflight(name, clean, context)
        if decision is not None and not decision.allowed:
            self._event(context, "tool.blocked", {"tool": name, "reason": decision.reason})
            context.telemetry.increment("tools.blocked")
            return ToolResult(ok=False, error=decision.reason, decision=decision, untrusted=False)

        try:
            context.budget.spend_tool_call()
        except Exception as error:
            return ToolResult.failure(str(error))

        tool.calls += 1
        try:
            raw = self._run_with_timeout(tool, context, clean)
        except ToolError as error:
            duration = time.monotonic() - started
            context.telemetry.increment("tools.failed")
            self._event(context, "tool.error", {"tool": name, "error": str(error), "duration": round(duration, 3)})
            return ToolResult(ok=False, error=str(error), duration=duration, decision=decision, untrusted=False)
        except Exception as error:  # pragma: no cover - defensive
            duration = time.monotonic() - started
            context.telemetry.increment("tools.crashed")
            self._event(context, "tool.crash", {"tool": name, "error": repr(error)})
            return ToolResult(ok=False, error=f"{name} crashed: {error}", duration=duration, untrusted=False)

        result = self._coerce_result(raw)
        result.duration = time.monotonic() - started
        result.decision = decision
        if not result.brief:
            source = (result.output or result.error or "").strip()
            result.brief = source.splitlines()[0][:160] if source else ""
        result.digest = hashlib.sha256((result.output or result.error).encode("utf-8", "replace")).hexdigest()[:16]

        if tool.untrusted_output and result.ok:
            before = len(result.output)
            result.output = context.output_guard.wrap(result.output or result.summary, origin="tool", tool=name)
            result.truncated = before > context.output_guard.max_chars

        context.telemetry.increment("tools.ok" if result.ok else "tools.error")
        context.telemetry.observe(f"tool.{name}", result.duration)
        self._event(
            context,
            "tool.result",
            {
                "tool": name,
                "ok": result.ok,
                "duration": round(result.duration, 3),
                "digest": result.digest,
                "summary": result.summary,
            },
        )
        return result

    # ------------------------------------------------------------------
    def _run_with_timeout(self, tool: Tool, context: ToolContext, arguments: dict[str, Any]) -> Any:
        outcome: dict[str, Any] = {}

        def target() -> None:
            try:
                outcome["value"] = tool.handler(context, arguments)
            except BaseException as error:  # noqa: BLE001 - re-raised in the caller thread
                outcome["error"] = error

        thread = threading.Thread(target=target, name=f"tool-{tool.name}", daemon=True)
        thread.start()
        thread.join(tool.timeout)
        if thread.is_alive():
            raise ToolError(f"{tool.name} timed out after {tool.timeout:.0f}s")
        if "error" in outcome:
            error = outcome["error"]
            if isinstance(error, (ScopeBlocked, ToolError)):
                raise error
            raise ToolError(str(error))
        return outcome.get("value")

    def _preflight(self, name: str, arguments: dict[str, Any], context: ToolContext) -> SafetyDecision | None:
        target = str(arguments.get("url") or arguments.get("target") or "")
        if target:
            if "://" not in target:
                target = f"http://{target}"
            decision = context.guard.check_url(target, method=str(arguments.get("method", "GET")))
            if not decision.allowed:
                return decision
        targets = arguments.get("targets")
        if isinstance(targets, list) and targets:
            return context.guard.check_run_defaults({"targets": targets, "method": arguments.get("method", "GET")})
        red = context.guard.red_lines.check(name, tool=name, arguments=arguments)
        if not red.allowed:
            return red
        return self._intercept(name, arguments, context)

    def _intercept(self, name: str, arguments: dict[str, Any], context: ToolContext) -> SafetyDecision | None:
        """The harness gate: risk score and target check for this exact call."""

        interceptor = context.interceptor
        if interceptor is None:
            return None
        try:
            verdict = interceptor.check_tool(name, arguments)
        except Exception as error:  # a broken gate fails closed, never open
            context.telemetry.increment("intercept.failed")
            return SafetyDecision(False, reason=f"gate failed: {type(error).__name__}: {error}", rule="intercept")
        if verdict is None or verdict.allowed:
            return None
        risk = getattr(verdict, "risk", None)
        score = float(getattr(risk, "score", 0) or 0) / 100.0
        return SafetyDecision(False, reason=verdict.reason, rule=getattr(verdict, "rule", "") or "intercept", risk=score)

    @staticmethod
    def _coerce_result(raw: Any) -> ToolResult:
        if isinstance(raw, ToolResult):
            return raw
        if isinstance(raw, dict):
            return ToolResult(ok=True, output=str(raw.get("summary") or ""), data=dict(raw))
        if isinstance(raw, str):
            return ToolResult(ok=True, output=raw)
        return ToolResult(ok=True, output=str(raw))

    def _event(self, context: ToolContext, kind: str, payload: dict[str, Any]) -> None:
        journal = context.journal
        if journal is not None:
            journal.append(kind, payload)
