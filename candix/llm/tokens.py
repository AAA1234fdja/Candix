"""Token estimation, context fitting and output compaction.

Candix does not ship a tokenizer: vendoring one per provider would add megabytes
for an estimate that only needs to be conservative. These helpers over-estimate
slightly (English ~3.6 chars/token, code ~3.2) so a prompt that fits here almost
always fits at the provider.
"""

from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass
from typing import Any, Iterable, Sequence

from candix.llm.types import Message, ToolSpec

_WORD = re.compile(r"\w+|[^\w\s]", re.UNICODE)
_CJK = re.compile(r"[\u3400-\u4dbf\u4e00-\u9fff\u3040-\u30ff\uac00-\ud7af]")

# Rough per-message overhead: role markers, separators, tool-call wrappers.
MESSAGE_OVERHEAD = 4
TOOL_SPEC_OVERHEAD = 12


def estimate_text(text: str) -> int:
    """Estimate tokens for a plain string."""

    if not text:
        return 0
    cjk = len(_CJK.findall(text))
    if cjk:
        # CJK characters are close to one token each; keep the rest of the text.
        remainder = len(text) - cjk
        return cjk + max(1, math.ceil(remainder / 3.6))
    words = len(_WORD.findall(text))
    by_chars = math.ceil(len(text) / 3.6)
    # Word count catches whitespace-poor payloads, char count catches dense code.
    return max(1, min(by_chars, max(words, math.ceil(len(text) / 4.4))))


def estimate_message(message: Message) -> int:
    total = MESSAGE_OVERHEAD + estimate_text(message.content)
    for call in message.tool_calls:
        total += MESSAGE_OVERHEAD + estimate_text(call.name)
        total += estimate_text(json.dumps(call.arguments, ensure_ascii=False, sort_keys=True))
    if message.name:
        total += estimate_text(message.name) + 1
    return total


def estimate_messages(messages: Iterable[Message]) -> int:
    return sum(estimate_message(message) for message in messages)


def estimate_tools(tools: Iterable[ToolSpec]) -> int:
    total = 0
    for tool in tools:
        total += TOOL_SPEC_OVERHEAD + estimate_text(tool.name) + estimate_text(tool.description)
        total += estimate_text(json.dumps(tool.parameters, ensure_ascii=False, sort_keys=True))
    return total


def estimate_request(messages: Sequence[Message], tools: Sequence[ToolSpec] = ()) -> int:
    return estimate_messages(messages) + estimate_tools(tools)


def truncate_text(text: str, max_tokens: int, *, marker: str = "\n… [truncated {n} chars]") -> str:
    """Cut text to roughly ``max_tokens`` keeping both the head and the tail.

    Head and tail matter for tool output: the beginning carries status lines,
    the end carries stack traces and error messages.
    """

    if max_tokens <= 0:
        return ""
    budget_chars = max_tokens * 4
    if len(text) <= budget_chars:
        return text
    if budget_chars < 64:
        return text[:budget_chars]
    head = int(budget_chars * 0.65)
    tail = budget_chars - head - 32
    removed = len(text) - head - max(0, tail)
    suffix = marker.format(n=max(0, removed))
    return text[:head] + suffix + (text[-tail:] if tail > 0 else "")


@dataclass
class FitResult:
    messages: list[Message]
    dropped: int = 0
    truncated: int = 0
    estimated_tokens: int = 0

    @property
    def changed(self) -> bool:
        return self.dropped > 0 or self.truncated > 0


def fit_messages(
    messages: Sequence[Message],
    *,
    max_tokens: int,
    reserve_output: int = 1024,
    tools: Sequence[ToolSpec] = (),
    keep_system: bool = True,
) -> FitResult:
    """Shrink a conversation until it fits the window.

    Strategy, in order: truncate oversized tool results, drop middle history
    (keeping the first user turn and the most recent exchanges), and only then
    truncate the remaining messages. The system prompt and the latest turn are
    never dropped.
    """

    budget = max(256, max_tokens - reserve_output - estimate_tools(tools))
    result = list(messages)
    dropped = 0
    truncated = 0

    # 1. compact tool results (they are usually the bulk of the context)
    compacted: list[Message] = []
    for message in result:
        if message.role.value == "tool" and estimate_message(message) > budget // 3:
            compacted.append(
                Message(
                    message.role,
                    truncate_text(message.content, max(64, budget // 4)),
                    name=message.name,
                    metadata=dict(message.metadata),
                    tool_call_id=message.tool_call_id,
                )
            )
            truncated += 1
        else:
            compacted.append(message)
    result = compacted

    def total() -> int:
        return estimate_messages(result)

    # 2. drop middle history, oldest first
    head_count = 1 if keep_system and result and result[0].role.value == "system" else 0
    guard = 0
    while total() > budget and len(result) > head_count + 2 and guard < 500:
        del result[head_count]
        dropped += 1
        guard += 1

    # 3. truncate what remains except system + last message
    if total() > budget and result:
        for index in range(head_count, max(head_count, len(result) - 1)):
            message = result[index]
            over = total() - budget
            if over <= 0:
                break
            new_size = max(32, estimate_message(message) - over)
            result[index] = Message(
                message.role,
                truncate_text(message.content, new_size),
                name=message.name,
                tool_calls=message.tool_calls,
                tool_call_id=message.tool_call_id,
                metadata=dict(message.metadata),
            )
            truncated += 1

    # 4. last resort: shrink the remaining messages (system included) so the
    #    request never exceeds the window. Truncation keeps head and tail.
    guard = 0
    while total() > budget and guard < 64:
        largest = max(range(len(result)), key=lambda index: estimate_message(result[index]), default=-1)
        if largest < 0:
            break
        message = result[largest]
        over = total() - budget
        target = max(32, estimate_message(message) - over)
        shrunk = truncate_text(message.content, target)
        if shrunk == message.content or estimate_text(shrunk) >= estimate_text(message.content):
            break
        result[largest] = Message(
            message.role,
            shrunk,
            name=message.name,
            tool_calls=message.tool_calls,
            tool_call_id=message.tool_call_id,
            metadata=dict(message.metadata),
        )
        truncated += 1
        guard += 1

    return FitResult(messages=result, dropped=dropped, truncated=truncated, estimated_tokens=total())


def json_tokens(payload: Any) -> int:
    return estimate_text(json.dumps(payload, ensure_ascii=False, sort_keys=True))


def summarize_json(payload: Any, max_tokens: int = 200) -> str:
    """Compact a JSON payload for inclusion in a prompt."""

    text = json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=None)
    return truncate_text(text, max_tokens)
