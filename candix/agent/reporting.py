"""Run reports: the artefact an operator reads after the agent stops."""

from __future__ import annotations

import json
from typing import Any

import re

from candix.agent.models import TaskResult

_FRAME = re.compile(r"<<<UNTRUSTED_OUTPUT[^\n]*\n?")


def _row(cells: list[Any]) -> str:
    return "| " + " | ".join(str(cell) for cell in cells) + " |"


def render_markdown(result: TaskResult, *, snapshot: dict[str, Any] | None = None, max_intents: int = 40) -> str:
    counts = result.counts()
    lines = [
        f"# Agent run — {result.goal.statement}",
        "",
        f"- **Stop reason:** {result.stop_reason}",
        f"- **Duration:** {result.duration:.1f}s",
        f"- **Intents:** {counts.get('done', 0)} done, {counts.get('failed', 0)} failed, {counts.get('blocked', 0)} blocked",
        f"- **Findings registered:** {len(result.findings)}",
        f"- **Proofs:** {len(result.proofs)}",
        "",
        "## Plan and execution",
        "",
        _row(["#", "Phase", "Intent", "Tool", "Status", "Result"]),
        _row(["---"] * 6),
    ]
    for index, intent in enumerate(result.intents[:max_intents], start=1):
        lines.append(
            _row(
                [
                    index,
                    intent.phase.value,
                    intent.title[:60],
                    intent.tool or "-",
                    intent.status.value,
                    _FRAME.sub("", intent.result or "-")[:80].replace("|", "/"),
                ]
            )
        )
    if result.findings:
        lines.extend(["", "## Findings", "", _row(["Severity", "Title", "Endpoint"]), _row(["---"] * 3)])
        for finding in result.findings[:60]:
            lines.append(
                _row(
                    [
                        str(finding.get("severity", "")).upper(),
                        str(finding.get("title", ""))[:70],
                        str(finding.get("url", ""))[:80],
                    ]
                )
            )
    if result.proofs:
        lines.extend(["", "## Proofs", ""])
        for proof in result.proofs[:20]:
            lines.append(f"- {proof.get('claim', 'claim')[:200]}")
            for fact in proof.get("facts", [])[:3]:
                lines.append(f"  - ({fact.get('source')}/{fact.get('confidence')}) {fact.get('claim', '')[:160]}")
    if result.lessons:
        lines.extend(["", "## Lessons recorded", ""])
        for lesson in result.lessons:
            lines.append(f"- {lesson.get('text', '')}")
    if snapshot:
        lines.extend(["", "## Run telemetry", ""])
        budget = snapshot.get("budget") or {}
        lines.append(
            f"- turns {budget.get('turns')}/{budget.get('limits', {}).get('turns')}, "
            f"tool calls {budget.get('tool_calls')}/{budget.get('limits', {}).get('tool_calls')}, "
            f"tokens {budget.get('tokens')}, cost ${budget.get('cost_usd', 0):.4f}"
        )
        telemetry = snapshot.get("telemetry") or {}
        if telemetry.get("counters"):
            lines.append("- counters: " + ", ".join(f"{k}={v}" for k, v in sorted(telemetry["counters"].items())[:10]))
        journal = snapshot.get("journal") or {}
        if journal.get("entries"):
            lines.append(f"- journal: {journal['entries']} entries, tail {journal.get('tail', '')[:12]}")
        coverage = (snapshot.get("graphs") or {}).get("coverage") or {}
        if coverage:
            lines.append(
                "- coverage: {endpoints} endpoints, {endpoints_untested} untested, {parameters} parameters".format(**coverage)
            )
    lines.append("")
    return "\n".join(lines)


def render_json(result: TaskResult, *, snapshot: dict[str, Any] | None = None) -> str:
    payload = result.to_dict()
    if snapshot:
        payload["session"] = snapshot
    return json.dumps(payload, indent=2, sort_keys=True, default=str)


def summary_line(result: TaskResult) -> str:
    counts = result.counts()
    return (
        f"{counts.get('done', 0)} done · {counts.get('failed', 0)} failed · "
        f"{len(result.findings)} findings · {len(result.proofs)} proofs · {result.duration:.1f}s"
    )
