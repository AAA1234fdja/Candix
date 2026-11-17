"""On-disk response cache for deterministic model calls."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from candix.llm.types import ChatRequest, ChatResponse, FinishReason, Message, Role, ToolCall, Usage


def request_key(request: ChatRequest) -> str:
    """Stable digest of everything that can change a completion."""

    payload = {
        "model": request.model,
        "temperature": round(float(request.temperature), 3),
        "max_tokens": request.max_tokens,
        "messages": [
            {
                "role": message.role.value,
                "content": message.content,
                "tool_calls": [call.to_dict() for call in message.tool_calls],
                "tool_call_id": message.tool_call_id,
                "name": message.name,
            }
            for message in request.messages
        ],
        "tools": [tool.to_dict() for tool in request.tools],
        "tool_choice": request.tool_choice,
        "response_format": request.response_format,
        "stop": request.stop,
    }
    blob = json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


@dataclass
class CacheEntry:
    key: str
    response: ChatResponse
    created_at: float
    hits: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "created_at": self.created_at,
            "hits": self.hits,
            "response": {
                "text": self.response.text,
                "model": self.response.model,
                "provider": self.response.provider,
                "finish_reason": self.response.finish_reason.value,
                "usage": self.response.usage.to_dict(),
                "tool_calls": [call.to_dict() for call in self.response.tool_calls],
            },
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "CacheEntry":
        response_payload = payload.get("response") or {}
        usage = response_payload.get("usage") or {}
        return cls(
            key=str(payload.get("key", "")),
            created_at=float(payload.get("created_at", 0.0)),
            hits=int(payload.get("hits", 0)),
            response=ChatResponse(
                message=Message(
                    Role.ASSISTANT,
                    str(response_payload.get("text", "")),
                    tool_calls=[ToolCall.from_dict(item) for item in response_payload.get("tool_calls") or []],
                ),
                model=str(response_payload.get("model", "")),
                provider=str(response_payload.get("provider", "cache")),
                usage=Usage(
                    int(usage.get("prompt_tokens", 0)),
                    int(usage.get("completion_tokens", 0)),
                    int(usage.get("cached_tokens", 0)),
                ),
                finish_reason=FinishReason.parse(response_payload.get("finish_reason")),
            ),
        )


class ResponseCache:
    """Small LRU-ish JSON cache with TTL; safe to disable entirely."""

    def __init__(self, directory: str | Path | None = None, *, ttl: float = 3600.0, max_entries: int = 512, enabled: bool = True) -> None:
        self.enabled = enabled and bool(directory)
        self.directory = Path(directory) if directory else None
        self.ttl = ttl
        self.max_entries = max_entries
        self._memory: dict[str, CacheEntry] = {}
        self.hits = 0
        self.misses = 0
        if self.enabled and self.directory is not None:
            self.directory.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    def get(self, request: ChatRequest) -> ChatResponse | None:
        if not self.enabled:
            return None
        key = request_key(request)
        entry = self._memory.get(key)
        if entry is None and self.directory is not None:
            entry = self._load(key)
        if entry is None:
            self.misses += 1
            return None
        if self.ttl and time.time() - entry.created_at > self.ttl:
            self._memory.pop(key, None)
            self.misses += 1
            return None
        entry.hits += 1
        self.hits += 1
        self._memory[key] = entry
        response = entry.response
        return ChatResponse(
            message=response.message,
            model=response.model,
            provider="cache",
            usage=response.usage,
            finish_reason=response.finish_reason,
            latency=0.0,
            request_id=f"cache-{key[:10]}",
        )

    def put(self, request: ChatRequest, response: ChatResponse) -> None:
        if not self.enabled or response.finish_reason is FinishReason.ERROR:
            return
        key = request_key(request)
        entry = CacheEntry(key=key, response=response, created_at=time.time())
        self._memory[key] = entry
        if len(self._memory) > self.max_entries:
            self._evict()
        if self.directory is not None:
            self._store(entry)

    # ------------------------------------------------------------------
    def _path(self, key: str) -> Path:
        assert self.directory is not None
        return self.directory / f"{key[:2]}" / f"{key}.json"

    def _load(self, key: str) -> CacheEntry | None:
        path = self._path(key)
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        try:
            return CacheEntry.from_dict(payload)
        except (TypeError, ValueError):
            return None

    def _store(self, entry: CacheEntry) -> None:
        path = self._path(entry.key)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            data = json.dumps(entry.to_dict(), sort_keys=True).encode("utf-8")
            handle, temp = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
            with os.fdopen(handle, "wb") as stream:
                stream.write(data)
            os.replace(temp, path)
        except OSError:
            return

    def _evict(self) -> None:
        ordered = sorted(self._memory.values(), key=lambda item: (item.hits, item.created_at))
        while len(self._memory) > self.max_entries and ordered:
            oldest = ordered.pop(0)
            self._memory.pop(oldest.key, None)

    def stats(self) -> dict[str, Any]:
        total = self.hits + self.misses
        return {
            "enabled": self.enabled,
            "entries": len(self._memory),
            "hits": self.hits,
            "misses": self.misses,
            "hit_rate": round(self.hits / total, 3) if total else 0.0,
        }

    def clear(self) -> None:
        self._memory.clear()
        self.hits = 0
        self.misses = 0
