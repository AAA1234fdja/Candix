"""LLM pool adapter — engine/llmpool multi-provider."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any


@dataclass
class LlmProfile:
    id: int
    name: str
    provider: str
    model: str
    enabled: bool = True


class LlmPoolAdapter:
    def __init__(self, server_url: str = ""):
        self.server_url = server_url or os.getenv("CANDIX_ENGINE_URL", "http://127.0.0.1:8787")
        self.timeout = float(os.getenv("CANDIX_ENGINE_TIMEOUT", "4.0"))

    def list_profiles(self) -> list[LlmProfile]:
        # Try engine server first
        try:
            from candix.engine_adapter.server_client import ServerClient
            r = ServerClient(self.server_url).list_llm_profiles()
            if r.ok and isinstance(r.data, list):
                return [LlmProfile(id=int(p.get("id", i)), name=p.get("name",""), provider=p.get("provider",""), model=p.get("model","")) for i,p in enumerate(r.data)]
            if r.ok and isinstance(r.data, dict) and "profiles" in r.data:
                return [LlmProfile(id=int(p.get("id", i)), name=p.get("name",""), provider=p.get("provider",""), model=p.get("model","")) for i,p in enumerate(r.data["profiles"])]
        except Exception:
            pass
        # fallback: env-based
        profiles: list[LlmProfile] = []
        if os.getenv("ANTHROPIC_API_KEY"):
            profiles.append(LlmProfile(1, "anthropic", "anthropic", os.getenv("ANTHROPIC_MODEL", "claude-3-5-sonnet")))
        if os.getenv("OPENAI_API_KEY"):
            profiles.append(LlmProfile(2, "openai", "openai", os.getenv("OPENAI_MODEL", "gpt-4o")))
        if not profiles:
            profiles.append(LlmProfile(1, "stub", "stub", "stub"))
        return profiles

    def active(self) -> LlmProfile | None:
        lst = self.list_profiles()
        return lst[0] if lst else None

    def resolve(self, profile_id: int | None = None) -> LlmProfile | None:
        if profile_id is None:
            return self.active()
        for p in self.list_profiles():
            if p.id == profile_id:
                return p
        return None
