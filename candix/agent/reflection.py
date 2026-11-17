"""Post-run review that turns a trace into reusable lessons."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

from candix.agent.models import IntentStatus, TaskResult


@dataclass
class LessonDraft:
    text: str
    tags: tuple[str, ...] = ()
    weight: float = 1.0

    def to_dict(self) -> dict[str, Any]:
        return {"text": self.text, "tags": list(self.tags), "weight": round(self.weight, 3)}


def _blocked_intents(result: TaskResult) -> list[Any]:
    return [intent for intent in result.intents if intent.status is IntentStatus.BLOCKED]


def _failed_intents(result: TaskResult) -> list[Any]:
    return [intent for intent in result.intents if intent.status is IntentStatus.FAILED]


def derive_lessons(result: TaskResult, telemetry: Any = None) -> list[LessonDraft]:
    lessons: list[LessonDraft] = []
    blocked = _blocked_intents(result)
    failed = _failed_intents(result)
    done = [intent for intent in result.intents if intent.status is IntentStatus.DONE]

    if result.proofs:
        lessons.append(
            LessonDraft(
                f"Proof worked with {len(result.proofs)} accepted fact set(s); keep the fact-first path: observe, record, prove.",
                tags=("proof", "process"),
                weight=1.3,
            )
        )
    if blocked:
        rules = sorted({intent.result.split(":")[0][:40] for intent in blocked if intent.result})
        lessons.append(
            LessonDraft(
                f"{len(blocked)} intent(s) were blocked ({'; '.join(rules[:3])}). Check scope and autonomy before planning active work.",
                tags=("scope", "process"),
                weight=1.1,
            )
        )
    if failed:
        tools = sorted({intent.tool for intent in failed if intent.tool})
        lessons.append(
            LessonDraft(
                f"Tools {', '.join(tools[:4])} failed on this target class; prefer a plain request before a detector for the same check.",
                tags=("tools", "reliability"),
                weight=1.0,
            )
        )
    if done and not result.findings:
        lessons.append(
            LessonDraft(
                "The run completed actions but registered no findings: widen the crawl or lower the verification gate next time.",
                tags=("coverage",),
                weight=0.9,
            )
        )
    severity_counts: dict[str, int] = {}
    for finding in result.findings:
        severity = str(finding.get("severity", "info"))
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
    if severity_counts.get("critical") or severity_counts.get("high"):
        hot = sorted(
            {str(finding.get("category", "") or "exposure") for finding in result.findings if str(finding.get("severity", "")).lower() in {"critical", "high"}}
        )
        lessons.append(
            LessonDraft(
                f"High severity came from {', '.join(hot[:3])}; those endpoints deserve the first minutes of the next run.",
                tags=("prioritisation",),
                weight=1.2,
            )
        )
    if telemetry is not None:
        snapshot = telemetry.snapshot()
        slow = [
            name
            for name, summary in (snapshot.get("durations") or {}).items()
            if summary.get("count") and summary.get("p95", 0) > 20
        ]
        if slow:
            lessons.append(
                LessonDraft(f"Slow steps: {', '.join(slow[:3])}. Cap their time or run them later.", tags=("performance",), weight=0.8)
            )
    return lessons


def reflect(result: TaskResult, *, telemetry: Any = None, memory: Any = None, journal: Any = None) -> list[dict[str, Any]]:
    """Persist lessons for the next run and return them as JSON."""

    drafts = derive_lessons(result, telemetry=telemetry)
    payload: list[dict[str, Any]] = []
    for draft in drafts:
        entry = draft.to_dict()
        if memory is not None:
            lesson = memory.add(draft.text, tags=draft.tags, source_run=result.goal.statement[:80], weight=draft.weight)
            entry["id"] = lesson.id
        payload.append(entry)
    if journal is not None:
        journal.append("reflection", {"lessons": payload})
    return payload
