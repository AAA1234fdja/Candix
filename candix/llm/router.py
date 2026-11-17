"""Model routing by task shape, capability and price."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterable

from candix.llm.errors import ConfigurationError
from candix.llm.types import ModelInfo


class TaskKind(str, Enum):
    PLAN = "plan"
    ACT = "act"
    SUMMARIZE = "summarize"
    REFLECT = "reflect"
    JUDGE = "judge"
    EXTRACT = "extract"

    @classmethod
    def parse(cls, value: Any) -> "TaskKind":
        if isinstance(value, cls):
            return value
        try:
            return cls(str(value).lower())
        except ValueError:
            return cls.ACT


# Prices are deliberately conservative round numbers in USD per million tokens;
# the router only needs them for relative ranking.
KNOWN_MODELS: dict[str, ModelInfo] = {
    "claude-sonnet-4-5": ModelInfo("claude-sonnet-4-5", "anthropic", 200000, 8192, 3.0, 15.0, tier="frontier"),
    "claude-haiku-4-5": ModelInfo("claude-haiku-4-5", "anthropic", 200000, 8192, 1.0, 5.0, tier="fast"),
    "gpt-4.1": ModelInfo("gpt-4.1", "openai", 128000, 8192, 2.0, 8.0, tier="frontier"),
    "gpt-4.1-mini": ModelInfo("gpt-4.1-mini", "openai", 128000, 8192, 0.4, 1.6, tier="fast"),
    "gpt-4o-mini": ModelInfo("gpt-4o-mini", "openai", 128000, 4096, 0.15, 0.6, tier="fast"),
    "deepseek-chat": ModelInfo("deepseek-chat", "openai", 128000, 8192, 0.27, 1.1, tier="value"),
    "qwen2.5-coder": ModelInfo("qwen2.5-coder", "ollama", 32768, 4096, 0.0, 0.0, tier="local"),
    "llama3.1": ModelInfo("llama3.1", "ollama", 128000, 4096, 0.0, 0.0, tier="local"),
}

_TIER_BY_KIND: dict[TaskKind, tuple[str, ...]] = {
    TaskKind.PLAN: ("frontier", "standard", "value", "fast", "local"),
    TaskKind.ACT: ("frontier", "standard", "value", "fast", "local"),
    TaskKind.SUMMARIZE: ("fast", "value", "local", "standard", "frontier"),
    TaskKind.REFLECT: ("frontier", "standard", "value", "local"),
    TaskKind.JUDGE: ("frontier", "standard", "value", "local"),
    TaskKind.EXTRACT: ("fast", "local", "value", "standard"),
}


@dataclass
class Route:
    kind: TaskKind
    model: ModelInfo
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"kind": self.kind.value, "model": self.model.to_dict(), "reason": self.reason}


@dataclass
class ModelRouter:
    """Chooses a model per task, honouring availability and a price ceiling."""

    models: dict[str, ModelInfo] = field(default_factory=lambda: dict(KNOWN_MODELS))
    available: tuple[str, ...] = ()
    max_cost_per_million: float = 0.0
    prefer_local: bool = False
    overrides: dict[str, str] = field(default_factory=dict)

    def is_available(self, model: ModelInfo) -> bool:
        if not self.available:
            return True
        return any(model.name.startswith(prefix) or prefix in model.name for prefix in self.available)

    def register(self, info: ModelInfo) -> None:
        self.models[info.name] = info

    def choose(self, kind: TaskKind | str, *, hint: str = "") -> Route:
        kind = TaskKind.parse(kind)
        if hint and hint in self.overrides:
            hint = self.overrides[hint]
        if hint:
            for name, info in self.models.items():
                if name.startswith(hint) or hint in name:
                    return Route(kind, info, reason=f"explicit hint {hint}")
        candidates = [info for info in self.models.values() if self.is_available(info)]
        if self.max_cost_per_million:
            candidates = [
                info
                for info in candidates
                if info.input_cost_per_million <= self.max_cost_per_million or info.input_cost_per_million == 0
            ]
        if self.prefer_local:
            local = [info for info in candidates if info.tier == "local"]
            if local:
                candidates = local
        if not candidates:
            raise ConfigurationError("no model satisfies the routing constraints")
        order = _TIER_BY_KIND[kind]
        for tier in order:
            for info in sorted(candidates, key=lambda item: (item.input_cost_per_million, item.name)):
                if info.tier == tier:
                    return Route(kind, info, reason=f"tier {tier} for {kind.value}")
        best = sorted(candidates, key=lambda item: (item.input_cost_per_million, item.name))[0]
        return Route(kind, best, reason="cheapest available fallback")

    def chain(self, kind: TaskKind | str, *, limit: int = 3) -> list[Route]:
        kind = TaskKind.parse(kind)
        routes: list[Route] = []
        seen: set[str] = set()
        for tier in _TIER_BY_KIND[kind]:
            for info in sorted(self.models.values(), key=lambda item: (item.input_cost_per_million, item.name)):
                if info.tier != tier or info.name in seen or not self.is_available(info):
                    continue
                seen.add(info.name)
                routes.append(Route(kind, info, reason=f"tier {tier}"))
                if len(routes) >= limit:
                    return routes
        return routes

    def table(self) -> list[dict[str, Any]]:
        return [info.to_dict() for info in sorted(self.models.values(), key=lambda item: (item.tier, item.name))]

    def apply_to(self, model_name: str) -> ModelInfo:
        for name, info in self.models.items():
            if name == model_name:
                return info
        return ModelInfo(model_name, "unknown", 32768, 4096)
