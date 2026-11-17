"""Ordering of planned intents."""

from __future__ import annotations

import heapq
from dataclasses import dataclass, field
from typing import Iterable

from candix.agent.models import Intent, IntentStatus, Phase


_PHASE_WEIGHT = {
    Phase.RECON: 1.0,
    Phase.DETECT: 0.9,
    Phase.EXPLOIT: 0.75,
    Phase.VERIFY: 0.7,
    Phase.REPORT: 0.2,
}


@dataclass(order=True)
class _Entry:
    sort_key: tuple[float, float, str]
    intent: Intent = field(compare=False)


class IntentScheduler:
    """Priority queue that respects dependencies and phase order."""

    def __init__(self, *, phase_bias: bool = True) -> None:
        self.phase_bias = phase_bias
        self._queue: list[_Entry] = []
        self._known: dict[str, Intent] = {}

    # ------------------------------------------------------------------
    def push(self, intent: Intent) -> None:
        self._known[intent.id] = intent
        if intent.status not in {IntentStatus.PENDING, IntentStatus.READY}:
            return
        heapq.heappush(self._queue, _Entry(self._key(intent), intent))

    def extend(self, intents: Iterable[Intent]) -> None:
        for intent in intents:
            self.push(intent)

    def _key(self, intent: Intent) -> tuple[float, float, str]:
        phase = _PHASE_WEIGHT.get(intent.phase, 0.5) if self.phase_bias else 1.0
        # Higher priority and lower risk first; severity of phase breaks ties.
        score = -(intent.priority * phase) + intent.risk * 0.1
        return (round(score, 4), intent.risk, intent.id)

    # ------------------------------------------------------------------
    def pop_ready(self, *, completed: set[str] | None = None) -> Intent | None:
        completed = completed or set()
        deferred: list[_Entry] = []
        chosen: Intent | None = None
        while self._queue:
            entry = heapq.heappop(self._queue)
            intent = entry.intent
            if intent.status not in {IntentStatus.PENDING, IntentStatus.READY}:
                continue
            if any(dependency not in completed for dependency in intent.depends_on):
                deferred.append(entry)
                continue
            chosen = intent
            break
        for entry in deferred:
            heapq.heappush(self._queue, entry)
        return chosen

    def pending(self) -> list[Intent]:
        return [entry.intent for entry in sorted(self._queue)]

    def __len__(self) -> int:
        return len([entry for entry in self._queue if entry.intent.status in {IntentStatus.PENDING, IntentStatus.READY}])

    def completed_ids(self) -> set[str]:
        return {intent.id for intent in self._known.values() if intent.status is IntentStatus.DONE}

    def prune(self) -> int:
        before = len(self._queue)
        self._queue = [entry for entry in self._queue if entry.intent.status in {IntentStatus.PENDING, IntentStatus.READY}]
        heapq.heapify(self._queue)
        return before - len(self._queue)

    def snapshot(self) -> dict[str, object]:
        return {
            "queued": len(self),
            "known": len(self._known),
            "by_phase": _by_phase([intent for intent in self._known.values()]),
        }


def _by_phase(intents: Iterable[Intent]) -> dict[str, int]:
    grouped: dict[str, int] = {}
    for intent in intents:
        grouped[intent.phase.value] = grouped.get(intent.phase.value, 0) + 1
    return grouped
