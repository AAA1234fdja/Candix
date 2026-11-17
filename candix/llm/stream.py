"""Server-sent-events parsing for streamed model responses."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Iterable, Iterator


@dataclass
class StreamEvent:
    """One SSE event, normalised across providers."""

    kind: str
    text: str = ""
    tool_name: str = ""
    tool_arguments: str = ""
    tool_index: int = 0
    finish_reason: str = ""
    usage: dict[str, Any] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)


def parse_sse(lines: Iterable[str]) -> Iterator[dict[str, Any]]:
    """Yield the ``data`` payload of each SSE frame as parsed JSON."""

    buffer: list[str] = []
    for line in lines:
        line = line.rstrip("\r\n")
        if not line:
            if buffer:
                payload = "\n".join(buffer)
                buffer.clear()
                parsed = _decode(payload)
                if parsed is not None:
                    yield parsed
            continue
        if line.startswith(":") or line.startswith("event:"):
            continue
        if line.startswith("data:"):
            buffer.append(line[5:].lstrip())
    if buffer:
        parsed = _decode("\n".join(buffer))
        if parsed is not None:
            yield parsed


def _decode(payload: str) -> dict[str, Any] | None:
    payload = payload.strip()
    if not payload or payload == "[DONE]":
        return None
    try:
        value = json.loads(payload)
    except json.JSONDecodeError:
        return None
    return value if isinstance(value, dict) else None


def openai_events(chunks: Iterable[dict[str, Any]]) -> Iterator[StreamEvent]:
    for chunk in chunks:
        choices = chunk.get("choices") or []
        if chunk.get("usage"):
            yield StreamEvent(kind="usage", usage=dict(chunk["usage"]), raw=chunk)
        for choice in choices:
            delta = choice.get("delta") or {}
            if delta.get("content"):
                yield StreamEvent(kind="text", text=str(delta["content"]), raw=chunk)
            for call in delta.get("tool_calls") or []:
                function = call.get("function") or {}
                yield StreamEvent(
                    kind="tool",
                    tool_name=str(function.get("name") or ""),
                    tool_arguments=str(function.get("arguments") or ""),
                    tool_index=int(call.get("index", 0) or 0),
                    raw=chunk,
                )
            if choice.get("finish_reason"):
                yield StreamEvent(kind="finish", finish_reason=str(choice["finish_reason"]), raw=chunk)


def anthropic_events(chunks: Iterable[dict[str, Any]]) -> Iterator[StreamEvent]:
    for chunk in chunks:
        kind = str(chunk.get("type", ""))
        if kind == "content_block_delta":
            delta = chunk.get("delta") or {}
            if delta.get("type") == "text_delta":
                yield StreamEvent(kind="text", text=str(delta.get("text", "")), raw=chunk)
            elif delta.get("type") == "input_json_delta":
                yield StreamEvent(
                    kind="tool",
                    tool_arguments=str(delta.get("partial_json", "")),
                    tool_index=int(chunk.get("index", 0) or 0),
                    raw=chunk,
                )
        elif kind == "content_block_start":
            block = chunk.get("content_block") or {}
            if block.get("type") == "tool_use":
                yield StreamEvent(
                    kind="tool",
                    tool_name=str(block.get("name", "")),
                    tool_index=int(chunk.get("index", 0) or 0),
                    raw=chunk,
                )
        elif kind == "message_delta":
            delta = chunk.get("delta") or {}
            if delta.get("stop_reason"):
                yield StreamEvent(kind="finish", finish_reason=str(delta["stop_reason"]), raw=chunk)
            if chunk.get("usage"):
                yield StreamEvent(kind="usage", usage=dict(chunk["usage"]), raw=chunk)
        elif kind == "message_start":
            message = chunk.get("message") or {}
            if message.get("usage"):
                yield StreamEvent(kind="usage", usage=dict(message["usage"]), raw=chunk)


@dataclass
class StreamAccumulator:
    """Fold stream events back into text and tool calls."""

    text: str = ""
    tool_names: dict[int, str] = field(default_factory=dict)
    tool_args: dict[int, str] = field(default_factory=dict)
    finish_reason: str = ""
    usage: dict[str, Any] = field(default_factory=dict)

    def consume(self, event: StreamEvent) -> None:
        if event.kind == "text":
            self.text += event.text
        elif event.kind == "tool":
            if event.tool_name:
                self.tool_names[event.tool_index] = event.tool_name
            if event.tool_arguments:
                self.tool_args[event.tool_index] = self.tool_args.get(event.tool_index, "") + event.tool_arguments
        elif event.kind == "finish":
            self.finish_reason = event.finish_reason
        elif event.kind == "usage":
            self.usage.update(event.usage)

    def calls(self) -> list[tuple[str, str]]:
        names = sorted(set(self.tool_names) | set(self.tool_args))
        return [(self.tool_names.get(index, ""), self.tool_args.get(index, "")) for index in names]
