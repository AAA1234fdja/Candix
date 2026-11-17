"""SideQuestion adapter — engine/sidequestion en Python."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable


@dataclass
class SideAnswer:
    text: str
    usage: dict[str, int] = None  # type: ignore
    tool_use: bool = False

    def __post_init__(self) -> None:
        if self.usage is None:
            self.usage = {"input_tokens": 0, "output_tokens": 0}

class SideQuestionService:
    """Responde preguntas laterales via LLM provider — sin harness/tools."""

    def __init__(self, provider: Any = None):
        self.provider = provider

    def answer(self, messages: list[dict[str, str]], system: str = "", streaming: bool = False, on_update: Callable[[SideAnswer], None] | None = None) -> SideAnswer:
        if self.provider is None:
            return SideAnswer(text="No LLM provider configured for side questions. Configure engine LLM profile.", tool_use=False)
        try:
            # provider is expected to expose complete/stream like llm.Provider
            req = {"system": system, "messages": messages}
            if hasattr(self.provider, "complete"):
                msg, stop_reason, usage, err = self.provider.complete(None, req)  # type: ignore
                text = getattr(msg, "text", lambda: str(msg))() if hasattr(msg, "text") else str(msg)
                if not text.strip():
                    text = "model did not return an answer"
                return SideAnswer(text=text, usage={"input_tokens": getattr(usage, "input_tokens", 0), "output_tokens": getattr(usage, "output_tokens", 0)}, tool_use=False)
            elif hasattr(self.provider, "chat"):
                text = self.provider.chat(messages, system=system)  # type: ignore
                return SideAnswer(text=str(text))
        except Exception as e:
            return SideAnswer(text=f"side question error: {e}")
        return SideAnswer(text="No answer")
