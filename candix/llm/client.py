"""Retrying, budget-aware client in front of one or more providers."""

from __future__ import annotations

import random
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Iterator, Sequence

from candix.llm.cache import ResponseCache
from candix.llm.errors import (
    AuthenticationError,
    BudgetExhausted,
    ConfigurationError,
    ContentFilterError,
    ContextLengthError,
    LLMError,
    RateLimitError,
    TransportError,
)
from candix.llm.jsonschema import check, coerced, loads, repair_truncated
from candix.llm.providers import Provider
from candix.llm.stream import StreamEvent
from candix.llm.tokens import estimate_request
from candix.llm.types import ChatRequest, ChatResponse, FinishReason, Message, ToolSpec
from candix.llm.usage import UsageLedger


@dataclass
class RetryPolicy:
    attempts: int = 3
    base_delay: float = 0.8
    max_delay: float = 20.0
    jitter: float = 0.25

    def delay(self, attempt: int, retry_after: float | None = None) -> float:
        if retry_after:
            return min(self.max_delay, max(0.0, retry_after))
        raw = min(self.max_delay, self.base_delay * (2 ** max(0, attempt - 1)))
        return raw * (1 + random.uniform(-self.jitter, self.jitter))


@dataclass
class CallRecord:
    task: str
    provider: str
    model: str
    ok: bool
    attempts: int
    latency: float
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "task": self.task,
            "provider": self.provider,
            "model": self.model,
            "ok": self.ok,
            "attempts": self.attempts,
            "latency": round(self.latency, 3),
            "error": self.error,
        }


class LLMClient:
    """The only object the agent talks to for model output.

    Responsibilities: pick a provider, retry transient failures, fall back to
    the next provider when a deployment is unusable, enforce budgets before the
    call, cache deterministic calls, and hand every response to the ledger.
    """

    def __init__(
        self,
        providers: Sequence[Provider],
        *,
        cache: ResponseCache | None = None,
        ledger: UsageLedger | None = None,
        retry: RetryPolicy | None = None,
        on_retry: Callable[[int, float, LLMError], None] | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if not providers:
            raise ConfigurationError("LLMClient needs at least one provider")
        self.providers = list(providers)
        self.cache = cache
        self.ledger = ledger or UsageLedger()
        self.retry = retry or RetryPolicy()
        self.on_retry = on_retry
        self._sleep = sleep
        self.calls: list[CallRecord] = []

    # ------------------------------------------------------------------
    @property
    def provider(self) -> Provider:
        return self.providers[0]

    def describe(self) -> dict[str, Any]:
        return {
            "providers": [provider.describe() for provider in self.providers],
            "retry": {"attempts": self.retry.attempts, "base_delay": self.retry.base_delay, "max_delay": self.retry.max_delay},
            "ledger": self.ledger.snapshot(),
            "cache": self.cache.stats() if self.cache else {"enabled": False},
        }

    # ------------------------------------------------------------------
    def complete(self, request: ChatRequest, *, task: str = "generic", use_cache: bool = True) -> ChatResponse:
        estimated = estimate_request(request.messages, request.tools)
        self.ledger.guard(prompt_tokens=estimated)

        if use_cache and self.cache is not None and request.temperature <= 0.35:
            cached = self.cache.get(request)
            if cached is not None:
                self.ledger.record(
                    task=task,
                    provider=cached.provider,
                    model=cached.model or request.model,
                    usage=cached.usage,
                    cached=True,
                )
                self.calls.append(CallRecord(task, cached.provider, cached.model, True, 0, 0.0))
                return cached

        errors: list[str] = []
        for index, provider in enumerate(self.providers):
            last_error: LLMError | None = None
            for attempt in range(1, self.retry.attempts + 1):
                started = time.monotonic()
                try:
                    response = provider.complete(self._bind_model(request, provider))
                except RateLimitError as error:
                    last_error = error
                    if attempt < self.retry.attempts:
                        self._pause(attempt, error)
                        continue
                except TransportError as error:
                    last_error = error
                    if attempt < self.retry.attempts:
                        self._pause(attempt, error)
                        continue
                except (AuthenticationError, ConfigurationError) as error:
                    errors.append(str(error))
                    last_error = error
                    break
                except ContentFilterError as error:
                    errors.append(str(error))
                    last_error = error
                    break
                except ContextLengthError:
                    raise
                except BudgetExhausted:
                    raise
                except LLMError as error:
                    errors.append(str(error))
                    last_error = error
                    break
                else:
                    latency = time.monotonic() - started
                    self.ledger.record(
                        task=task,
                        provider=response.provider or provider.name,
                        model=response.model or provider.model,
                        usage=response.usage,
                    )
                    self.calls.append(
                        CallRecord(task, response.provider or provider.name, response.model, True, attempt, latency)
                    )
                    if self.cache is not None:
                        self.cache.put(request, response)
                    return response
            if last_error is not None:
                errors.append(f"{provider.name}: {last_error}")
                self.calls.append(
                    CallRecord(task, provider.name, provider.model, False, self.retry.attempts, 0.0, str(last_error))
                )
            if index + 1 < len(self.providers):
                continue
        raise TransportError("; ".join(errors) or "all providers failed")

    # ------------------------------------------------------------------
    def complete_json(
        self,
        request: ChatRequest,
        *,
        task: str = "json",
        schema: dict[str, Any] | None = None,
        use_cache: bool = True,
    ) -> tuple[dict[str, Any], ChatResponse]:
        """Ask for JSON and return (parsed object, response).

        The call is retried once with an explicit repair instruction when the
        model returns prose, and truncated objects are closed before parsing.
        """

        prepared = ChatRequest(
            messages=list(request.messages),
            tools=[],
            model=request.model,
            temperature=request.temperature,
            max_tokens=request.max_tokens,
            stop=list(request.stop),
            metadata=dict(request.metadata),
            tool_choice="none",
            response_format="json",
        )
        response = self.complete(prepared, task=task, use_cache=use_cache)
        parsed = loads(response.text)
        if not isinstance(parsed, dict):
            parsed = loads(repair_truncated(response.text))
        if not isinstance(parsed, dict):
            repair_messages = list(prepared.messages) + [
                Message.assistant(response.text[:2000] or "(empty)"),
                Message.user("That was not valid JSON. Reply with the JSON object only, no prose, no code fences."),
            ]
            retry_request = prepared.with_messages(repair_messages)
            retry_request.max_tokens = max(prepared.max_tokens, 700)
            response = self.complete(retry_request, task=f"{task}:repair", use_cache=False)
            parsed = loads(response.text)
            if not isinstance(parsed, dict):
                parsed = loads(repair_truncated(response.text))
        data = parsed if isinstance(parsed, dict) else {}
        if schema and data:
            value, errors = coerced(data, schema)
            if errors:
                data.setdefault("_validation_errors", [str(error) for error in errors[:5]])
                data = value if isinstance(value, dict) else data
            else:
                data = value
        return data, response

    # ------------------------------------------------------------------
    def complete_with_tools(
        self,
        messages: Iterable[Message],
        tools: Sequence[ToolSpec],
        *,
        task: str = "tools",
        model: str = "",
        temperature: float = 0.1,
        max_tokens: int = 1024,
    ) -> ChatResponse:
        request = ChatRequest(
            messages=list(messages),
            tools=list(tools),
            model=model,
            temperature=temperature,
            max_tokens=max_tokens,
            tool_choice="auto",
        )
        return self.complete(request, task=task, use_cache=False)

    # ------------------------------------------------------------------
    def stream(self, request: ChatRequest, *, task: str = "stream") -> Iterator[StreamEvent]:
        self.ledger.guard(prompt_tokens=estimate_request(request.messages, request.tools))
        for provider in self.providers:
            try:
                emitted = False
                for event in provider.stream(self._bind_model(request, provider)):
                    emitted = True
                    yield event
                if emitted:
                    return
            except (AuthenticationError, ConfigurationError, TransportError):
                continue
        raise TransportError("no provider produced a stream")

    # ------------------------------------------------------------------
    def _bind_model(self, request: ChatRequest, provider: Provider) -> ChatRequest:
        if request.model:
            return request
        rebound = ChatRequest(
            messages=request.messages,
            tools=request.tools,
            model=provider.model,
            temperature=request.temperature,
            max_tokens=request.max_tokens,
            stop=request.stop,
            metadata=request.metadata,
            tool_choice=request.tool_choice,
            response_format=request.response_format,
        )
        return rebound

    def _pause(self, attempt: int, error: LLMError) -> None:
        delay = self.retry.delay(attempt, getattr(error, "retry_after", None))
        if self.on_retry is not None:
            self.on_retry(attempt, delay, error)
        self._sleep(delay)

    # ------------------------------------------------------------------
    def stats(self) -> dict[str, Any]:
        return {
            "calls": len(self.calls),
            "failures": sum(1 for call in self.calls if not call.ok),
            "by_task": {},
            "ledger": self.ledger.snapshot(),
        }
