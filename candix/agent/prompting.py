"""Assemble the prompts the agent sends, from state instead of ad hoc strings."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

from candix.agent.retrieval import Retriever, Snippet, build_context
from candix.llm.prompts import render
from candix.llm.tokens import estimate_text, truncate_text


@dataclass
class Brief:
    system: str = ""
    user: str = ""
    sections: dict[str, int] = field(default_factory=dict)

    @property
    def tokens(self) -> int:
        return estimate_text(self.system) + estimate_text(self.user)

    def to_dict(self) -> dict[str, Any]:
        return {"system": self.system[:2000], "user": self.user[:4000], "tokens": self.tokens, "sections": self.sections}


def _section(name: str, body: str) -> tuple[str, int]:
    body = (body or "").strip()
    if not body:
        return "", 0
    return f"## {name}\n{body}", estimate_text(body)


def planner_brief(
    state: Any,
    *,
    tools: Iterable[Any] = (),
    assets: Any = None,
    facts: Iterable[Any] = (),
    journal: Iterable[Any] = (),
    skills: Iterable[Any] = (),
    todos: Any = None,
    lessons: Iterable[str] = (),
    max_tokens: int = 2400,
) -> Brief:
    """The planner prompt: state, context, standing instructions."""

    retriever = Retriever()
    context = build_context(
        getattr(state, "goal", ""),
        assets=assets,
        facts=facts,
        journal=journal,
        skills=skills,
        max_tokens=min(700, max_tokens // 3),
    )
    tool_lines = []
    for tool in tools:
        name = getattr(tool, "name", str(tool))
        description = getattr(tool, "description", "")
        tool_lines.append(f"- {name}: {description[:120]}")

    parts: list[tuple[str, str]] = [
        ("targets", ", ".join(getattr(state, "targets", []) or [])),
        ("coverage", _coverage_text(state)),
        ("attempted", "\n".join(f"- {item}" for item in (getattr(state, "attempted", []) or [])[:10])),
        ("findings", _findings_text(getattr(state, "findings", []) or [])),
        ("context", context.replace("Context:\n", "")),
        ("lessons", "\n".join(f"- {item}" for item in list(lessons)[:3])),
        ("todos", todos.prompt_block() if hasattr(todos, "prompt_block") else ""),
    ]
    system = render("system")
    body_parts: list[str] = []
    sections: dict[str, int] = {}
    remaining = max_tokens - estimate_text(system)
    if remaining < 120:
        system = truncate_text(system, max(60, max_tokens // 2))
        remaining = max(60, max_tokens - estimate_text(system))
    for name, value in parts:
        text, cost = _section(name, value)
        if not text or cost == 0:
            continue
        if cost > remaining:
            text = truncate_text(text, max(32, remaining - 16))
            cost = estimate_text(text)
        if cost == 0:
            continue
        body_parts.append(text)
        sections[name] = cost
        remaining -= cost
        if remaining <= 24:
            break
    remaining_turns = int(getattr(state, "remaining_turns", 3) or 3)
    user = render(
        "planner",
        goal=truncate_text(getattr(state, "goal", ""), 120),
        state="\n\n".join(body_parts),
        tools="\n".join(tool_lines) or "none",
        max_intents=max(1, min(3, remaining_turns)),
    )
    return Brief(system=system, user=user, sections=sections)


def _coverage_text(state: Any) -> str:
    coverage = getattr(state, "coverage", {}) or {}
    if not coverage:
        return ""
    return ", ".join(f"{name}={value}" for name, value in coverage.items())


def _findings_text(findings: list[dict[str, Any]], *, limit: int = 6) -> str:
    lines = []
    for finding in findings[:limit]:
        lines.append(
            f"- {finding.get('severity', '?')} {finding.get('title', '')[:60]} @ {finding.get('url', '')[:60]}"
            + (" (verified)" if finding.get("verified") else "")
        )
    return "\n".join(lines)


def worker_brief(
    intent: Any,
    *,
    goal: str = "",
    skills: Iterable[Any] = (),
    context: str = "",
    max_tokens: int = 1200,
) -> Brief:
    """The worker prompt for one intent."""

    parts = [
        ("goal", goal),
        ("intent", f"{getattr(intent, 'title', '')}\n{getattr(intent, 'description', '')}"),
        ("tool", str(getattr(intent, "tool", "") or "(your choice)")),
        ("arguments", str(getattr(intent, "arguments", {}) or {})),
        ("skills", "\n".join(f"- {getattr(skill, 'name', skill)}: {getattr(skill, 'body', '')[:400]}" for skill in skills)),
        ("context", context),
    ]
    system = render("system")
    body: list[str] = []
    sections: dict[str, int] = {}
    remaining = max_tokens - estimate_text(system)
    if remaining < 120:
        system = truncate_text(system, max(60, max_tokens // 2))
        remaining = max(60, max_tokens - estimate_text(system))
    for name, value in parts:
        text, cost = _section(name, value)
        if not text or cost == 0:
            continue
        if cost > remaining:
            text = truncate_text(text, max(32, remaining - 16))
            cost = estimate_text(text)
        body.append(text)
        sections[name] = cost
        remaining -= cost
        if remaining <= 24:
            break
    return Brief(
        system=system,
        user=render("worker", goal=goal, title=str(getattr(intent, "title", "")), description="\n\n".join(body)),
        sections=sections,
    )


def reflection_brief(result: Any, *, max_tokens: int = 900) -> Brief:
    findings = getattr(result, "findings", []) or []
    blocked = [
        intent.title
        for intent in getattr(result, "intents", [])
        if getattr(intent.status, "value", "") in {"blocked", "failed"}
    ]
    summary = _findings_text(findings, limit=5)
    user = render(
        "reflect",
        goal=str(getattr(getattr(result, "goal", ""), "statement", "")),
        stop_reason=str(getattr(result, "stop_reason", "")),
        findings=summary or "none",
        blocked=", ".join(blocked[:5]) or "none",
    )
    system = render("system")
    body_budget = max(80, max_tokens - estimate_text(system))
    return Brief(system=system, user=truncate_text(user, body_budget), sections={"findings": estimate_text(summary)})


def triage_brief(finding: dict[str, Any], *, evidence: str = "", max_tokens: int = 600) -> Brief:
    body = (
        f"Title: {finding.get('title', '')}\n"
        f"Severity: {finding.get('severity', '')}\n"
        f"URL: {finding.get('url', '')}\n"
        f"Parameter: {finding.get('parameter', '')}\n"
        f"Description: {finding.get('description', '')}\n"
        f"Evidence: {evidence[:800]}"
    )
    return Brief(system=render("system"), user=render("triage", evidence=truncate_text(body, max_tokens)))


def skill_context(skills: Iterable[Any], *, phase: str = "", limit: int = 2) -> str:
    chosen = []
    for skill in skills:
        if phase and getattr(skill, "phase", "") and getattr(skill, "phase", "") != phase:
            continue
        chosen.append(f"### {getattr(skill, 'name', '')}\n{getattr(skill, 'body', '')[:800]}")
        if len(chosen) >= limit:
            break
    return "\n\n".join(chosen)


def memory_context(lessons: Iterable[Any]) -> str:
    lines = []
    for lesson in lessons:
        text = lesson.text if hasattr(lesson, "text") else str(lesson)
        if text:
            lines.append(f"- {text[:180]}")
    return "\n".join(lines)


def snippet_block(snippets: Iterable[Snippet]) -> str:
    return "\n".join(f"- [{snippet.kind}] {snippet.text[:200]}" for snippet in snippets)


def check_brief(brief: Brief, *, ceiling: int = 8000) -> list[str]:
    problems: list[str] = []
    if not brief.system.strip():
        problems.append("missing system prompt")
    if not brief.user.strip():
        problems.append("missing user prompt")
    if brief.tokens > ceiling:
        problems.append(f"prompt uses {brief.tokens} tokens, above the {ceiling} ceiling")
    return problems
