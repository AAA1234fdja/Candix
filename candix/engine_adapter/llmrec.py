"""LLM rec adapter — engine/llmrec grabación en Python."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any, Callable


@dataclass
class LlmRecord:
    session_id: str
    task_id: str
    worker: str
    model: str
    profile_name: str
    latency_ms: int
    input_tokens: int
    output_tokens: int
    status: str
    request_body: str = ""
    response_body: str = ""

@dataclass
class LlmUsage:
    task_id: str
    exploration_id: int
    worker: str
    model: str
    profile_name: str
    input_tokens: int
    output_tokens: int
    latency_ms: int
    status: str

class LlmRecorder:
    """Decorator que graba cada llamada LLM — espejo de engine/llmrec.Recorder."""

    def __init__(self, inner: Any = None, model: str = "", profile_name: str = "", enabled: Callable[[], bool] | None = None, pg: Any = None):
        self.inner = inner
        self.model = model
        self.profile_name = profile_name
        self.enabled = enabled or (lambda: True)
        self.pg = pg
        self.records: list[LlmRecord] = []
        self.usages: list[LlmUsage] = []

    def _record_usage(self, usage: dict[str, Any], task_id: str = "", worker: str = "", latency_ms: int = 0, status: str = "ok") -> None:
        u = LlmUsage(task_id=task_id, exploration_id=0, worker=worker, model=self.model, profile_name=self.profile_name, input_tokens=int(usage.get("input_tokens", 0)), output_tokens=int(usage.get("output_tokens", 0)), latency_ms=latency_ms, status=status)
        self.usages.append(u)
        if self.pg and hasattr(self.pg, "insert_llm_usage"):
            try:
                self.pg.insert_llm_usage(u)
            except Exception:
                pass

    def complete(self, messages: Any, **kw: Any) -> tuple[Any, dict[str, Any]]:
        start = time.time()
        task_id = kw.get("task_id", "")
        worker = kw.get("worker", "")
        try:
            if self.inner and hasattr(self.inner, "complete"):
                result = self.inner.complete(messages, **kw)
            else:
                result = {"text": "stub response"}
            latency_ms = int((time.time() - start) * 1000)
            # usage from provider if available
            usage = kw.get("usage", {"input_tokens": 0, "output_tokens": 0})
            if self.enabled():
                rec = LlmRecord(session_id=kw.get("session_id", ""), task_id=task_id, worker=worker, model=self.model, profile_name=self.profile_name, latency_ms=latency_ms, input_tokens=int(usage.get("input_tokens", 0)), output_tokens=int(usage.get("output_tokens", 0)), status="ok", request_body=json.dumps({"messages": messages})[:4000], response_body=json.dumps(result)[:4000])
                self.records.append(rec)
            self._record_usage(usage, task_id, worker, latency_ms, "ok")
            return result, usage
        except Exception as e:
            latency_ms = int((time.time() - start) * 1000)
            self._record_usage({}, task_id, worker, latency_ms, "error")
            raise

    def stream(self, messages: Any, **kw: Any):  # type: ignore
        # generator that yields chunks and records
        start = time.time()
        task_id = kw.get("task_id", "")
        worker = kw.get("worker", "")
        text_buf: list[str] = []
        usage: dict[str, Any] = {}
        try:
            if self.inner and hasattr(self.inner, "stream"):
                for chunk in self.inner.stream(messages, **kw):  # type: ignore
                    if isinstance(chunk, dict) and "text" in chunk:
                        text_buf.append(chunk["text"])
                    yield chunk
                usage = getattr(self.inner, "last_usage", {}) or {}
            else:
                yield {"text": "stub stream", "done": True}
            latency_ms = int((time.time() - start) * 1000)
            if self.enabled():
                rec = LlmRecord(session_id=kw.get("session_id", ""), task_id=task_id, worker=worker, model=self.model, profile_name=self.profile_name, latency_ms=latency_ms, input_tokens=int(usage.get("input_tokens", 0)), output_tokens=int(usage.get("output_tokens", 0)), status="ok", response_body="".join(text_buf)[:4000])
                self.records.append(rec)
            self._record_usage(usage, task_id, worker, latency_ms, "ok")
        except Exception:
            latency_ms = int((time.time() - start) * 1000)
            self._record_usage({}, task_id, worker, latency_ms, "error")
            raise

    def history(self, task_id: str | None = None) -> list[LlmRecord]:
        if task_id:
            return [r for r in self.records if r.task_id == task_id]
        return list(self.records)
