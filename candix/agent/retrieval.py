"""Context assembly under a token budget.

A model prompt can only hold so much, and most of what a run produces is
irrelevant to the next decision. This module ranks candidate snippets (lessons,
facts, journal entries, skill bodies) with a hybrid lexical/vector score, adds
recency and outcome bias, and packs them until the budget is spent.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

from candix.llm.embeddings import VectorIndex, Document
from candix.llm.tokens import estimate_text


_LABEL = {"lesson": "lessons", "fact": "facts", "journal": "log", "skill": "skills", "coverage": "coverage"}


@dataclass
class Snippet:
    kind: str
    text: str
    score: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def tokens(self) -> int:
        return estimate_text(self.text)

    def render(self) -> str:
        label = self.kind.upper()
        return f"[{label}] {self.text.strip()}"


@dataclass
class Budget:
    max_tokens: int = 1200
    per_kind: dict[str, int] = field(default_factory=lambda: {"lesson": 5, "fact": 8, "journal": 4, "skill": 2, "coverage": 2})
    kinds: tuple[str, ...] = ("lesson", "fact", "skill", "journal", "coverage")

    def allowance(self, kind: str) -> int:
        return self.per_kind.get(kind, 3)


class Retriever:
    def __init__(self, budget: Budget | None = None, *, semantic_weight: float = 0.5) -> None:
        self.budget = budget or Budget()
        self.semantic_weight = semantic_weight

    # ------------------------------------------------------------------
    def _score(self, query: str, snippets: list[Snippet], index: VectorIndex) -> None:
        results = index.search(query, limit=len(snippets) or 1)
        scores = {result.document.id: result for result in results}
        for position, snippet in enumerate(snippets):
            match = scores.get(str(position))
            lexical = match.lexical if match else 0.0
            semantic = match.semantic if match else 0.0
            base = self.semantic_weight * semantic + (1 - self.semantic_weight) * lexical
            weight = float(snippet.metadata.get("weight", 1.0) or 1.0)
            recency = float(snippet.metadata.get("recency", 0.0) or 0.0)
            confirmed = 1.15 if snippet.metadata.get("confirmed") else 1.0
            snippet.score = base * weight * confirmed + 0.12 * recency

    def rank(self, query: str, snippets: Iterable[Snippet]) -> list[Snippet]:
        items = [snippet for snippet in snippets if snippet.text.strip()]
        if not items:
            return []
        index = VectorIndex()
        for position, snippet in enumerate(items):
            index.add(Document(str(position), snippet.text))
        self._score(query, items, index)
        return sorted(items, key=lambda item: (-item.score, item.kind, item.text[:40]))

    # ------------------------------------------------------------------
    def select(self, query: str, snippets: Iterable[Snippet]) -> list[Snippet]:
        ranked = self.rank(query, snippets)
        chosen: list[Snippet] = []
        used = 0
        counts: dict[str, int] = {}
        for snippet in ranked:
            if counts.get(snippet.kind, 0) >= self.budget.allowance(snippet.kind):
                continue
            cost = snippet.tokens
            if used + cost > self.budget.max_tokens:
                continue
            counts[snippet.kind] = counts.get(snippet.kind, 0) + 1
            used += cost
            chosen.append(snippet)
        return chosen

    def render(self, query: str, snippets: Iterable[Snippet], *, header: str = "") -> str:
        chosen = self.select(query, snippets)
        if not chosen:
            return header
        lines = [header] if header else []
        for kind in self.budget.kinds:
            block = [snippet for snippet in chosen if snippet.kind == kind]
            if not block:
                continue
            lines.append(f"{_LABEL.get(kind, kind)}:")
            for snippet in block:
                lines.append(f"  - {snippet.text.strip()[:400]}")
        return "\n".join(lines).strip()


# ----------------------------------------------------------------------
def snippets_from_result(result: Any, *, facts: Iterable[Any] = (), journal: Iterable[Any] = ()) -> list[Snippet]:
    snippets: list[Snippet] = []
    for lesson in getattr(result, "lessons", []) or []:
        text = lesson.get("text", "") if isinstance(lesson, dict) else str(lesson)
        if text:
            snippets.append(Snippet("lesson", text, metadata={"weight": float(lesson.get("weight", 1.0)) if isinstance(lesson, dict) else 1.0}))
    for index, intent in enumerate(getattr(result, "intents", []) or []):
        status = getattr(intent.status, "value", str(intent.status))
        if status in {"failed", "blocked"}:
            snippets.append(
                Snippet(
                    "journal",
                    f"{intent.tool or intent.title} {status}: {(intent.result or '')[:160]}",
                    metadata={"recency": 1.0 - index / max(1, len(result.intents))},
                )
            )
    for fact in facts:
        payload = fact.to_dict() if hasattr(fact, "to_dict") else dict(fact)
        source = str(payload.get("source", ""))
        snippets.append(
            Snippet(
                "fact",
                f"{payload.get('claim', '')} ({source})",
                metadata={"weight": 1.2 if source in {"target_response", "third_party_intel"} else 1.0, "confirmed": True},
            )
        )
    for entry in journal:
        payload = entry.to_dict() if hasattr(entry, "to_dict") else dict(entry)
        snippets.append(Snippet("journal", f"{payload.get('kind', '')}: {payload.get('summary', '')}", metadata={"recency": 0.5}))
    return snippets


def coverage_snippets(assets: Any) -> list[Snippet]:
    try:
        coverage = assets.coverage()
    except Exception:
        return []
    lines = [
        Snippet("coverage", f"endpoints {coverage.get('endpoints', 0)} ({coverage.get('endpoints_untested', 0)} untested)"),
        Snippet("coverage", f"parameters {coverage.get('parameters', 0)}, findings {coverage.get('findings', 0)}"),
    ]
    for node in list(assets.endpoints_without_findings())[:5]:
        lines.append(Snippet("coverage", f"untested endpoint: {node.label}", metadata={"weight": 1.1}))
    return lines


def build_context(query: str, *, result: Any = None, assets: Any = None, facts: Iterable[Any] = (), journal: Iterable[Any] = (), skills: Iterable[Any] = (), max_tokens: int = 1200) -> str:
    snippets: list[Snippet] = []
    if result is not None:
        snippets.extend(snippets_from_result(result, facts=facts, journal=journal))
    if assets is not None:
        snippets.extend(coverage_snippets(assets))
    for skill in skills:
        payload = skill.to_dict() if hasattr(skill, "to_dict") else dict(skill)
        body = str(payload.get("body", ""))[:1200]
        if body:
            snippets.append(Snippet("skill", f"{payload.get('name', '')}: {body}", metadata={"weight": 1.05}))
    retriever = Retriever(Budget(max_tokens=max_tokens))
    return retriever.render(query, snippets, header="Context:")
