"""Provider-neutral message, tool and usage types."""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterable


class Role(str, Enum):
    SYSTEM = "system"
    USER = "user"
    ASSISTANT = "assistant"
    TOOL = "tool"


class FinishReason(str, Enum):
    STOP = "stop"
    LENGTH = "length"
    TOOL_CALLS = "tool_calls"
    CONTENT_FILTER = "content_filter"
    ERROR = "error"
    UNKNOWN = "unknown"

    @classmethod
    def parse(cls, value: Any) -> "FinishReason":
        if isinstance(value, cls):
            return value
        text = str(value or "").strip().lower()
        mapping = {
            "stop": cls.STOP,
            "end_turn": cls.STOP,
            "stop_sequence": cls.STOP,
            "length": cls.LENGTH,
            "max_tokens": cls.LENGTH,
            "tool_calls": cls.TOOL_CALLS,
            "tool_use": cls.TOOL_CALLS,
            "function_call": cls.TOOL_CALLS,
            "content_filter": cls.CONTENT_FILTER,
            "refusal": cls.CONTENT_FILTER,
            "error": cls.ERROR,
        }
        return mapping.get(text, cls.UNKNOWN)


@dataclass
class ToolCall:
    """A function invocation requested by the model."""

    name: str
    arguments: dict[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=lambda: f"call_{uuid.uuid4().hex[:12]}")
    raw_arguments: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.id, "name": self.name, "arguments": dict(self.arguments)}

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "ToolCall":
        arguments = payload.get("arguments")
        if isinstance(arguments, str):
            try:
                arguments = json.loads(arguments or "{}")
            except json.JSONDecodeError:
                arguments = {}
        return cls(
            name=str(payload.get("name", "")),
            arguments=dict(arguments or {}),
            id=str(payload.get("id") or f"call_{uuid.uuid4().hex[:12]}"),
            raw_arguments=str(payload.get("raw_arguments", "")),
        )


@dataclass
class Message:
    role: Role
    content: str = ""
    name: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)
    tool_call_id: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"role": self.role.value, "content": self.content}
        if self.name:
            payload["name"] = self.name
        if self.tool_calls:
            payload["tool_calls"] = [call.to_dict() for call in self.tool_calls]
        if self.tool_call_id:
            payload["tool_call_id"] = self.tool_call_id
        if self.metadata:
            payload["metadata"] = dict(self.metadata)
        return payload

    def to_openai(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"role": self.role.value}
        if self.role is Role.TOOL:
            payload["content"] = self.content
            payload["tool_call_id"] = self.tool_call_id
            return payload
        if self.tool_calls:
            payload["content"] = self.content or None
            payload["tool_calls"] = [
                {
                    "id": call.id,
                    "type": "function",
                    "function": {"name": call.name, "arguments": json.dumps(call.arguments, ensure_ascii=False)},
                }
                for call in self.tool_calls
            ]
            return payload
        payload["content"] = self.content
        return payload

    def to_anthropic(self) -> dict[str, Any]:
        if self.role is Role.TOOL:
            return {
                "role": "user",
                "content": [{"type": "tool_result", "tool_use_id": self.tool_call_id, "content": self.content}],
            }
        if self.role is Role.ASSISTANT and self.tool_calls:
            blocks: list[dict[str, Any]] = []
            if self.content:
                blocks.append({"type": "text", "text": self.content})
            for call in self.tool_calls:
                blocks.append({"type": "tool_use", "id": call.id, "name": call.name, "input": dict(call.arguments)})
            return {"role": "assistant", "content": blocks}
        return {"role": self.role.value, "content": [{"type": "text", "text": self.content}]}

    @classmethod
    def system(cls, content: str) -> "Message":
        return cls(Role.SYSTEM, content)

    @classmethod
    def user(cls, content: str) -> "Message":
        return cls(Role.USER, content)

    @classmethod
    def assistant(cls, content: str = "", tool_calls: Iterable[ToolCall] = ()) -> "Message":
        return cls(Role.ASSISTANT, content, tool_calls=list(tool_calls))

    @classmethod
    def tool(cls, call_id: str, content: str, name: str = "") -> "Message":
        return cls(Role.TOOL, content, name=name, tool_call_id=call_id)


@dataclass
class ToolSpec:
    """A tool exposed to the model, described with JSON Schema."""

    name: str
    description: str
    parameters: dict[str, Any] = field(default_factory=lambda: {"type": "object", "properties": {}})
    strict: bool = False

    def to_openai(self) -> dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters,
            },
        }

    def to_anthropic(self) -> dict[str, Any]:
        return {"name": self.name, "description": self.description, "input_schema": self.parameters}

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "description": self.description, "parameters": self.parameters}


@dataclass
class Usage:
    prompt_tokens: int = 0
    completion_tokens: int = 0
    cached_tokens: int = 0

    @property
    def total_tokens(self) -> int:
        return self.prompt_tokens + self.completion_tokens

    def add(self, other: "Usage") -> "Usage":
        return Usage(
            prompt_tokens=self.prompt_tokens + other.prompt_tokens,
            completion_tokens=self.completion_tokens + other.completion_tokens,
            cached_tokens=self.cached_tokens + other.cached_tokens,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "cached_tokens": self.cached_tokens,
            "total_tokens": self.total_tokens,
        }


@dataclass
class ChatRequest:
    messages: list[Message]
    tools: list[ToolSpec] = field(default_factory=list)
    model: str = ""
    temperature: float = 0.2
    max_tokens: int = 1024
    stop: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    tool_choice: str = "auto"
    response_format: str = ""

    def with_messages(self, messages: Iterable[Message]) -> "ChatRequest":
        return ChatRequest(
            messages=list(messages),
            tools=list(self.tools),
            model=self.model,
            temperature=self.temperature,
            max_tokens=self.max_tokens,
            stop=list(self.stop),
            metadata=dict(self.metadata),
            tool_choice=self.tool_choice,
            response_format=self.response_format,
        )


@dataclass
class ChatResponse:
    message: Message
    model: str = ""
    provider: str = ""
    usage: Usage = field(default_factory=Usage)
    finish_reason: FinishReason = FinishReason.STOP
    latency: float = 0.0
    request_id: str = ""
    raw: dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)

    @property
    def text(self) -> str:
        return self.message.content

    @property
    def tool_calls(self) -> list[ToolCall]:
        return self.message.tool_calls

    def to_dict(self) -> dict[str, Any]:
        return {
            "model": self.model,
            "provider": self.provider,
            "usage": self.usage.to_dict(),
            "finish_reason": self.finish_reason.value,
            "latency": round(self.latency, 4),
            "request_id": self.request_id,
            "text": self.text,
            "tool_calls": [call.to_dict() for call in self.tool_calls],
        }


@dataclass
class ModelInfo:
    """Static description of a model the router can pick."""

    name: str
    provider: str
    context_window: int = 32768
    max_output: int = 4096
    input_cost_per_million: float = 0.0
    output_cost_per_million: float = 0.0
    supports_tools: bool = True
    supports_json: bool = True
    tier: str = "standard"

    def cost(self, usage: Usage) -> float:
        return (
            usage.prompt_tokens / 1_000_000 * self.input_cost_per_million
            + usage.completion_tokens / 1_000_000 * self.output_cost_per_million
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "provider": self.provider,
            "context_window": self.context_window,
            "max_output": self.max_output,
            "input_cost_per_million": self.input_cost_per_million,
            "output_cost_per_million": self.output_cost_per_million,
            "supports_tools": self.supports_tools,
            "tier": self.tier,
        }
