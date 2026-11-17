"""HTTP providers for OpenAI-compatible, Anthropic and Ollama endpoints."""

from __future__ import annotations

import json
import os
import socket
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Iterable, Iterator

from candix import VERSION
from candix.llm.errors import (
    AuthenticationError,
    ConfigurationError,
    ContentFilterError,
    ContextLengthError,
    ParseError,
    RateLimitError,
    TransportError,
)
from candix.llm.stream import StreamEvent, anthropic_events, openai_events, parse_sse
from candix.llm.types import ChatRequest, ChatResponse, FinishReason, Message, Role, ToolCall, Usage

DEFAULT_TIMEOUT = 120.0
USER_AGENT = f"candix/{VERSION} (+agentic)"


class Provider:
    """Base class: one deployment of one model family."""

    name = "base"
    supports_tools = True
    supports_streaming = True

    def __init__(self, *, model: str, base_url: str = "", api_key: str = "", timeout: float = DEFAULT_TIMEOUT, headers: dict[str, str] | None = None) -> None:
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self.extra_headers = dict(headers or {})

    # ------------------------------------------------------------------
    def complete(self, request: ChatRequest) -> ChatResponse:
        raise NotImplementedError

    def stream(self, request: ChatRequest) -> Iterator[StreamEvent]:
        raise NotImplementedError

    def describe(self) -> dict[str, Any]:
        return {
            "provider": self.name,
            "model": self.model,
            "base_url": self.base_url,
            "tools": self.supports_tools,
            "streaming": self.supports_streaming,
        }

    # ------------------------------------------------------------------
    def _post(self, path: str, payload: dict[str, Any], headers: dict[str, str], *, stream: bool = False) -> Any:
        url = self.base_url + path
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        request = urllib.request.Request(url, data=body, method="POST")
        request.add_header("Content-Type", "application/json")
        request.add_header("Accept", "text/event-stream" if stream else "application/json")
        request.add_header("User-Agent", USER_AGENT)
        for name, value in {**self.extra_headers, **headers}.items():
            request.add_header(name, value)
        try:
            response = urllib.request.urlopen(request, timeout=self.timeout)
        except urllib.error.HTTPError as error:
            return self._http_error(error)
        except (urllib.error.URLError, socket.timeout, TimeoutError, ConnectionError) as error:
            raise TransportError(f"{self.name}: {error}", provider=self.name, model=self.model) from error
        if stream:
            return response
        with response:
            raw = response.read()
            content_type = response.headers.get("Content-Type", "")
        return self._decode(raw, content_type)

    def _http_error(self, error: urllib.error.HTTPError) -> Any:
        status = int(error.code)
        try:
            detail = error.read().decode("utf-8", "replace")[:800]
        except OSError:
            detail = ""
        message = f"{self.name} HTTP {status}: {detail or error.reason}"
        lowered = detail.lower()
        retry_after = None
        try:
            retry_after = float(error.headers.get("Retry-After", "") or 0) or None
        except (TypeError, ValueError):
            retry_after = None
        if status in {401, 403}:
            raise AuthenticationError(message, provider=self.name, model=self.model, status=status)
        if status == 429:
            raise RateLimitError(message, retry_after=retry_after, provider=self.name, model=self.model, status=status)
        if status in {413} or "context" in lowered and ("length" in lowered or "window" in lowered):
            raise ContextLengthError(message, provider=self.name, model=self.model, status=status)
        if status == 400 and ("content" in lowered and ("filter" in lowered or "policy" in lowered)):
            raise ContentFilterError(message, provider=self.name, model=self.model, status=status)
        if status >= 500 or status == 408:
            raise TransportError(message, provider=self.name, model=self.model, status=status)
        raise TransportError(message, provider=self.name, model=self.model, status=status)

    @staticmethod
    def _decode(raw: bytes, content_type: str) -> dict[str, Any]:
        text = raw.decode("utf-8", "replace")
        if "event-stream" in content_type:
            chunks = [chunk for chunk in parse_sse(text.splitlines())]
            return {"_stream": chunks}
        try:
            payload = json.loads(text)
        except json.JSONDecodeError as error:
            raise ParseError(f"response is not JSON: {text[:200]}") from error
        if not isinstance(payload, dict):
            raise ParseError("response is not a JSON object")
        return payload


class OpenAICompatibleProvider(Provider):
    """Anything that speaks ``POST /chat/completions`` (OpenAI, vLLM, LM Studio, OpenRouter, DeepSeek...)."""

    name = "openai"

    def __init__(self, *, model: str, base_url: str = "https://api.openai.com/v1", api_key: str = "", **kwargs: Any) -> None:
        if not base_url:
            raise ConfigurationError("openai-compatible provider needs a base URL")
        super().__init__(model=model, base_url=base_url, api_key=api_key, **kwargs)

    def _headers(self) -> dict[str, str]:
        headers: dict[str, str] = {}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    def _payload(self, request: ChatRequest, *, stream: bool) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "model": request.model or self.model,
            "messages": [message.to_openai() for message in request.messages],
            "temperature": request.temperature,
            "max_tokens": request.max_tokens,
            "stream": stream,
        }
        if request.tools:
            payload["tools"] = [tool.to_openai() for tool in request.tools]
            payload["tool_choice"] = request.tool_choice
        if request.stop:
            payload["stop"] = request.stop
        if request.response_format == "json":
            payload["response_format"] = {"type": "json_object"}
        if stream:
            payload["stream_options"] = {"include_usage": True}
        return payload

    def complete(self, request: ChatRequest) -> ChatResponse:
        started = time.monotonic()
        payload = self._post("/chat/completions", self._payload(request, stream=False), self._headers())
        if "_stream" in payload:
            return self._from_chunks(payload["_stream"], started)
        choices = payload.get("choices") or []
        if not choices:
            raise ParseError("response has no choices", provider=self.name, model=self.model)
        choice = choices[0]
        message = choice.get("message") or {}
        tool_calls = []
        for call in message.get("tool_calls") or []:
            function = call.get("function") or {}
            raw_arguments = str(function.get("arguments") or "{}")
            tool_calls.append(
                ToolCall(
                    name=str(function.get("name", "")),
                    arguments=_parse_arguments(raw_arguments),
                    id=str(call.get("id") or ""),
                    raw_arguments=raw_arguments,
                )
            )
        usage_payload = payload.get("usage") or {}
        usage = Usage(
            prompt_tokens=int(usage_payload.get("prompt_tokens", 0) or 0),
            completion_tokens=int(usage_payload.get("completion_tokens", 0) or 0),
            cached_tokens=int((usage_payload.get("prompt_tokens_details") or {}).get("cached_tokens", 0) or 0),
        )
        return ChatResponse(
            message=Message(Role.ASSISTANT, str(message.get("content") or ""), tool_calls=tool_calls),
            model=str(payload.get("model") or request.model or self.model),
            provider=self.name,
            usage=usage,
            finish_reason=FinishReason.parse(choice.get("finish_reason")),
            latency=time.monotonic() - started,
            request_id=str(payload.get("id", "")),
            raw=payload,
        )

    def stream(self, request: ChatRequest) -> Iterator[StreamEvent]:
        response = self._post("/chat/completions", self._payload(request, stream=True), self._headers(), stream=True)
        try:
            for chunk in parse_sse(_iter_lines(response)):
                yield from openai_events([chunk])
        finally:
            if hasattr(response, "close"):
                response.close()

    def _from_chunks(self, chunks: Iterable[dict[str, Any]], started: float) -> ChatResponse:
        from candix.llm.stream import StreamAccumulator

        accumulator = StreamAccumulator()
        for event in openai_events(chunks):
            accumulator.consume(event)
        calls = [
            ToolCall(name=name, arguments=_parse_arguments(raw), raw_arguments=raw)
            for name, raw in accumulator.calls()
            if name
        ]
        usage_payload = accumulator.usage or {}
        usage = Usage(
            int(usage_payload.get("prompt_tokens", 0) or 0),
            int(usage_payload.get("completion_tokens", 0) or 0),
            int((usage_payload.get("prompt_tokens_details") or {}).get("cached_tokens", 0) or 0),
        )
        return ChatResponse(
            message=Message(Role.ASSISTANT, accumulator.text, tool_calls=calls),
            model=self.model,
            provider=self.name,
            usage=usage,
            finish_reason=FinishReason.parse(accumulator.finish_reason),
            latency=time.monotonic() - started,
        )


class AnthropicProvider(Provider):
    """Anthropic Messages API (``POST /v1/messages``)."""

    name = "anthropic"
    API_VERSION = "2023-06-01"

    def __init__(self, *, model: str, base_url: str = "https://api.anthropic.com", api_key: str = "", **kwargs: Any) -> None:
        super().__init__(model=model, base_url=base_url or "https://api.anthropic.com", api_key=api_key, **kwargs)

    def _headers(self) -> dict[str, str]:
        headers = {"anthropic-version": self.API_VERSION}
        if self.api_key:
            headers["x-api-key"] = self.api_key
        return headers

    def _payload(self, request: ChatRequest, *, stream: bool) -> dict[str, Any]:
        system_parts = [message.content for message in request.messages if message.role is Role.SYSTEM]
        conversation = [message for message in request.messages if message.role is not Role.SYSTEM]
        payload: dict[str, Any] = {
            "model": request.model or self.model,
            "messages": [message.to_anthropic() for message in conversation],
            "max_tokens": request.max_tokens,
            "temperature": request.temperature,
            "stream": stream,
        }
        if system_parts:
            payload["system"] = "\n\n".join(part for part in system_parts if part)
        if request.tools:
            payload["tools"] = [tool.to_anthropic() for tool in request.tools]
        if request.stop:
            payload["stop_sequences"] = request.stop
        return payload

    def complete(self, request: ChatRequest) -> ChatResponse:
        started = time.monotonic()
        payload = self._post("/v1/messages", self._payload(request, stream=False), self._headers())
        blocks = payload.get("content") or []
        text_parts: list[str] = []
        calls: list[ToolCall] = []
        for block in blocks:
            if block.get("type") == "text":
                text_parts.append(str(block.get("text", "")))
            elif block.get("type") == "tool_use":
                calls.append(
                    ToolCall(
                        name=str(block.get("name", "")),
                        arguments=dict(block.get("input") or {}),
                        id=str(block.get("id", "")),
                    )
                )
        usage_payload = payload.get("usage") or {}
        usage = Usage(
            prompt_tokens=int(usage_payload.get("input_tokens", 0) or 0),
            completion_tokens=int(usage_payload.get("output_tokens", 0) or 0),
            cached_tokens=int(usage_payload.get("cache_read_input_tokens", 0) or 0),
        )
        return ChatResponse(
            message=Message(Role.ASSISTANT, "".join(text_parts), tool_calls=calls),
            model=str(payload.get("model") or self.model),
            provider=self.name,
            usage=usage,
            finish_reason=FinishReason.parse(payload.get("stop_reason")),
            latency=time.monotonic() - started,
            request_id=str(payload.get("id", "")),
            raw=payload,
        )

    def stream(self, request: ChatRequest) -> Iterator[StreamEvent]:
        response = self._post("/v1/messages", self._payload(request, stream=True), self._headers(), stream=True)
        try:
            for chunk in parse_sse(_iter_lines(response)):
                yield from anthropic_events([chunk])
        finally:
            if hasattr(response, "close"):
                response.close()


class OllamaProvider(Provider):
    """Local Ollama daemon (``POST /api/chat``)."""

    name = "ollama"

    def __init__(self, *, model: str, base_url: str = "http://127.0.0.1:11434", api_key: str = "", **kwargs: Any) -> None:
        super().__init__(model=model, base_url=base_url or "http://127.0.0.1:11434", api_key=api_key, **kwargs)

    def _payload(self, request: ChatRequest, *, stream: bool) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "model": request.model or self.model,
            "messages": [message.to_openai() for message in request.messages],
            "stream": stream,
            "options": {"temperature": request.temperature, "num_predict": request.max_tokens},
        }
        if request.tools:
            payload["tools"] = [tool.to_openai() for tool in request.tools]
        if request.response_format == "json":
            payload["format"] = "json"
        return payload

    def complete(self, request: ChatRequest) -> ChatResponse:
        started = time.monotonic()
        payload = self._post("/api/chat", self._payload(request, stream=False), {})
        message = payload.get("message") or {}
        calls = [
            ToolCall(
                name=str((call.get("function") or {}).get("name", "")),
                arguments=dict((call.get("function") or {}).get("arguments") or {}),
            )
            for call in message.get("tool_calls") or []
        ]
        usage = Usage(
            prompt_tokens=int(payload.get("prompt_eval_count", 0) or 0),
            completion_tokens=int(payload.get("eval_count", 0) or 0),
        )
        return ChatResponse(
            message=Message(Role.ASSISTANT, str(message.get("content") or ""), tool_calls=calls),
            model=str(payload.get("model") or self.model),
            provider=self.name,
            usage=usage,
            finish_reason=FinishReason.parse(payload.get("done_reason") or ("stop" if payload.get("done") else "")),
            latency=time.monotonic() - started,
            raw=payload,
        )

    def stream(self, request: ChatRequest) -> Iterator[StreamEvent]:
        response = self._post("/api/chat", self._payload(request, stream=True), {}, stream=True)
        try:
            for line in _iter_lines(response):
                line = line.strip()
                if not line:
                    continue
                try:
                    chunk = json.loads(line)
                except json.JSONDecodeError:
                    continue
                message = chunk.get("message") or {}
                if message.get("content"):
                    yield StreamEvent(kind="text", text=str(message["content"]))
                if chunk.get("done"):
                    yield StreamEvent(kind="finish", finish_reason=str(chunk.get("done_reason") or "stop"))
        finally:
            if hasattr(response, "close"):
                response.close()


@dataclass
class ScriptedProvider(Provider):
    """Replays a fixed list of responses; used by tests and offline demos."""

    name: str = "scripted"
    responses: list[ChatResponse] = field(default_factory=list)
    calls: list[ChatRequest] = field(default_factory=list)
    model: str = "scripted-model"
    base_url: str = ""
    api_key: str = ""
    timeout: float = DEFAULT_TIMEOUT
    extra_headers: dict[str, str] = field(default_factory=dict)

    def complete(self, request: ChatRequest) -> ChatResponse:
        self.calls.append(request)
        if not self.responses:
            return ChatResponse(
                message=Message.assistant(json.dumps({"action": "stop", "reason": "script exhausted"})),
                model=self.model,
                provider=self.name,
                finish_reason=FinishReason.STOP,
            )
        index = min(len(self.calls) - 1, len(self.responses) - 1)
        return self.responses[index]


def _iter_lines(response: Any) -> Iterator[str]:
    try:
        for raw in response:
            yield raw.decode("utf-8", "replace") if isinstance(raw, bytes) else str(raw)
    except (OSError, ConnectionError) as error:  # pragma: no cover - network dependent
        raise TransportError(f"stream interrupted: {error}") from error


def _parse_arguments(raw: str) -> dict[str, Any]:
    from candix.llm.jsonschema import loads, repair_truncated

    parsed = loads(raw)
    if parsed is None:
        parsed = loads(repair_truncated(raw))
    return parsed if isinstance(parsed, dict) else {}


# ----------------------------------------------------------------------
# Factory


def provider_from_env(prefix: str = "CANDIX_LLM", env: dict[str, str] | None = None) -> Provider:
    """Build a provider from environment variables.

    Recognised variables (all optional except a model):
    ``CANDIX_LLM_PROVIDER`` (openai|anthropic|ollama), ``CANDIX_LLM_MODEL``,
    ``CANDIX_LLM_BASE_URL``, ``CANDIX_LLM_API_KEY``, ``CANDIX_LLM_TIMEOUT``.
    Falls back to ``ANTHROPIC_API_KEY`` / ``OPENAI_API_KEY`` when the prefixed
    key is absent, and to Ollama on localhost when nothing else is configured.
    """

    environment = dict(os.environ if env is None else env)
    kind = (environment.get(f"{prefix}_PROVIDER") or "").strip().lower()
    api_key = environment.get(f"{prefix}_API_KEY", "")
    model = environment.get(f"{prefix}_MODEL", "")
    base_url = environment.get(f"{prefix}_BASE_URL", "")
    try:
        timeout = float(environment.get(f"{prefix}_TIMEOUT", "") or DEFAULT_TIMEOUT)
    except ValueError:
        timeout = DEFAULT_TIMEOUT

    if not kind:
        if api_key and environment.get("ANTHROPIC_API_KEY"):
            kind = "anthropic"
        elif environment.get("ANTHROPIC_API_KEY"):
            kind = "anthropic"
        elif environment.get("OPENAI_API_KEY") or base_url:
            kind = "openai"
        else:
            kind = "ollama"

    if kind == "anthropic":
        return AnthropicProvider(
            model=model or environment.get("CANDIX_LLM_MODEL", "claude-sonnet-4-5"),
            base_url=base_url or "https://api.anthropic.com",
            api_key=api_key or environment.get("ANTHROPIC_API_KEY", ""),
            timeout=timeout,
        )
    if kind == "ollama":
        return OllamaProvider(
            model=model or "llama3.1",
            base_url=base_url or environment.get("OLLAMA_HOST", "http://127.0.0.1:11434"),
            timeout=timeout,
        )
    if kind in {"openai", "openai-compatible", "compatible"}:
        return OpenAICompatibleProvider(
            model=model or "gpt-4.1-mini",
            base_url=base_url or environment.get("OPENAI_BASE_URL", "https://api.openai.com/v1"),
            api_key=api_key or environment.get("OPENAI_API_KEY", ""),
            timeout=timeout,
        )
    raise ConfigurationError(f"unknown provider: {kind}")
