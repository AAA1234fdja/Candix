"""Tool-call parsing for models that do not speak the provider protocol.

Small local models frequently answer with a JSON blob, a fenced block, an XML
snippet or a ReAct-style ``Action:``/``Action Input:`` pair instead of a real
tool-call object. The parsers here recover those shapes so the agent can use
cheap models without losing the tool loop.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

from candix.llm.jsonschema import loads, repair_truncated
from candix.llm.types import ToolCall, ToolSpec

_ACTION = re.compile(r"(?im)^\s*(?:action|tool|function)\s*:\s*([A-Za-z0-9_.-]+)\s*$")
_ACTION_INPUT = re.compile(r"(?ims)^\s*(?:action\s*input|arguments|input)\s*:\s*(.+?)(?=^\s*(?:action|thought|observation)\s*:|\Z)")
_FUNCTION_BLOCK = re.compile(r"<function=([A-Za-z0-9_.-]+)>(.*?)</function>", re.DOTALL)
_TOOL_BLOCK = re.compile(r"<tool(?:_call)?\s+name=[\"']([A-Za-z0-9_.-]+)[\"']\s*>(.*?)</tool(?:_call)?>", re.DOTALL)
_PARAMETER = re.compile(r"<parameter\s+name=[\"']([A-Za-z0-9_.-]+)[\"']\s*>(.*?)</parameter>", re.DOTALL)
_JSON_CALL = re.compile(r"\{\s*\"(?:tool|name|action)\"\s*:\s*\"([A-Za-z0-9_.-]+)\"\s*,\s*\"(?:arguments|input|parameters)\"\s*:", re.DOTALL)


@dataclass
class ParseOutcome:
    calls: list[ToolCall] = field(default_factory=list)
    text: str = ""
    method: str = "none"
    problems: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return bool(self.calls)

    def to_dict(self) -> dict[str, Any]:
        return {
            "method": self.method,
            "calls": [call.to_dict() for call in self.calls],
            "problems": list(self.problems),
            "text": self.text[:400],
        }


def _known(names: set[str], candidate: str) -> bool:
    return not names or candidate in names


def from_json(text: str, names: set[str]) -> ParseOutcome:
    payload = loads(text)
    if payload is None:
        payload = loads(repair_truncated(text))
    if isinstance(payload, list):
        calls = []
        for item in payload:
            if isinstance(item, dict):
                call = _call_from_dict(item, names)
                if call is not None:
                    calls.append(call)
        return ParseOutcome(calls, text="", method="json-list", problems=[] if calls else ["no usable calls in list"])
    if not isinstance(payload, dict):
        return ParseOutcome([], text, "none", ["not JSON"])
    call = _call_from_dict(payload, names)
    if call is not None:
        return ParseOutcome([call], text="", method="json")
    for key in ("tool_calls", "calls", "actions"):
        items = payload.get(key)
        if isinstance(items, list):
            calls = [item for item in (_call_from_dict(entry, names) for entry in items if isinstance(entry, dict)) if item]
            if calls:
                return ParseOutcome(calls, text="", method=f"json.{key}")
    return ParseOutcome([], text, "none", ["JSON without a tool call"])


def _call_from_dict(payload: dict[str, Any], names: set[str]) -> ToolCall | None:
    name = payload.get("tool") or payload.get("name") or payload.get("action") or payload.get("function")
    if isinstance(name, dict):
        name = name.get("name")
    if not isinstance(name, str) or not _known(names, name):
        return None
    arguments = payload.get("arguments") or payload.get("input") or payload.get("parameters") or payload.get("args") or {}
    if isinstance(arguments, str):
        parsed = loads(arguments)
        arguments = parsed if isinstance(parsed, dict) else {}
    if not isinstance(arguments, dict):
        arguments = {}
    return ToolCall(name=name, arguments=arguments)


def from_xml(text: str, names: set[str]) -> ParseOutcome:
    calls: list[ToolCall] = []
    for match in _FUNCTION_BLOCK.finditer(text):
        name = match.group(1)
        if not _known(names, name):
            continue
        arguments: dict[str, Any] = {}
        for parameter in _PARAMETER.finditer(match.group(2)):
            arguments[parameter.group(1)] = _maybe_json(parameter.group(2).strip())
        if not arguments:
            inner = loads(match.group(2))
            if isinstance(inner, dict):
                arguments = inner
        calls.append(ToolCall(name=name, arguments=arguments))
    for match in _TOOL_BLOCK.finditer(text):
        name = match.group(1)
        if not _known(names, name):
            continue
        inner = loads(match.group(2))
        calls.append(ToolCall(name=name, arguments=inner if isinstance(inner, dict) else {}))
    return ParseOutcome(calls, _strip_blocks(text), "xml", [] if calls else ["no XML tool block"])


def from_react(text: str, names: set[str]) -> ParseOutcome:
    action = _ACTION.search(text)
    if not action:
        return ParseOutcome([], text, "none", ["no Action: line"])
    name = action.group(1)
    if not _known(names, name):
        return ParseOutcome([], text, "none", [f"unknown tool {name}"])
    payload: dict[str, Any] = {}
    match = _ACTION_INPUT.search(text)
    if match:
        raw = match.group(1).strip()
        parsed = loads(raw)
        if isinstance(parsed, dict):
            payload = parsed
        else:
            stripped = raw.strip("`'\"").strip()
            if stripped.startswith("{"):
                parsed = loads(repair_truncated(stripped))
                payload = parsed if isinstance(parsed, dict) else {}
            elif stripped:
                payload = {"input": stripped}
    return ParseOutcome([ToolCall(name=name, arguments=payload)], _strip_blocks(text), "react")


def _maybe_json(value: str) -> Any:
    parsed = loads(value)
    return parsed if parsed is not None else value


def _strip_blocks(text: str) -> str:
    cleaned = _FUNCTION_BLOCK.sub("", text)
    cleaned = _TOOL_BLOCK.sub("", cleaned)
    return re.sub(r"\n{3,}", "\n\n", cleaned).strip()


def parse(text: str, tools: Any = (), *, names: set[str] | None = None) -> ParseOutcome:
    """Try every strategy; the first that yields a call wins."""

    if names is None:
        names = {tool.name if isinstance(tool, ToolSpec) else str(tool) for tool in tools}
    for strategy in (from_json, from_xml, from_react):
        outcome = strategy(text or "", names)
        if outcome.ok:
            return outcome
    return ParseOutcome([], text=text or "", method="none", problems=["no tool call found"])


def coerce_calls(raw: Any, tools: Any = ()) -> list[ToolCall]:
    """Normalise provider payloads of unknown shape into tool calls."""

    names = {tool.name if isinstance(tool, ToolSpec) else str(tool) for tool in tools}
    if raw is None:
        return []
    if isinstance(raw, str):
        return parse(raw, names=names).calls
    if isinstance(raw, dict):
        call = _call_from_dict(raw, names)
        return [call] if call else []
    if isinstance(raw, list):
        calls: list[ToolCall] = []
        for item in raw:
            if isinstance(item, dict):
                call = _call_from_dict(item, names)
                if call:
                    calls.append(call)
            elif isinstance(item, str):
                calls.extend(parse(item, names=names).calls)
        return calls
    return []


def to_prompt_block(calls: list[ToolCall]) -> str:
    """Render calls in the XML shape some local models copy reliably."""

    parts = []
    for call in calls:
        parameters = "".join(
            f"\n<parameter name=\"{key}\">{json.dumps(value, ensure_ascii=False) if not isinstance(value, str) else value}</parameter>"
            for key, value in call.arguments.items()
        )
        parts.append(f"<function={call.name}>{parameters}\n</function>")
    return "\n".join(parts)
