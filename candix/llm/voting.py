"""Ask more than once and keep what the samples agree on."""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable


@dataclass
class Vote:
    value: str
    weight: float = 1.0
    confidence: float = 0.0
    sample: int = 0
    meta: dict[str, Any] = field(default_factory=dict)

    def key(self) -> str:
        return self.value.strip().lower()


@dataclass
class Outcome:
    winner: str
    weight: float
    agreement: float
    votes: Counter
    samples: int
    unanimous: bool = False
    tie: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "winner": self.winner,
            "weight": round(self.weight, 3),
            "agreement": round(self.agreement, 3),
            "samples": self.samples,
            "unanimous": self.unanimous,
            "tie": self.tie,
            "distribution": dict(self.votes),
        }

    def describe(self) -> str:
        return f"{self.winner} with {self.agreement:.0%} agreement over {self.samples} sample(s)"


def tally(votes: Iterable[Vote]) -> Outcome:
    items = list(votes)
    if not items:
        return Outcome(winner="", weight=0.0, agreement=0.0, votes=Counter(), samples=0)
    counter: Counter = Counter()
    display: dict[str, str] = {}
    for vote in items:
        weight = max(0.01, float(vote.weight))
        counter[vote.key()] += weight
        display.setdefault(vote.key(), vote.value.strip())
    total = sum(counter.values())
    ranked = counter.most_common()
    top_key, top_weight = ranked[0]
    tie = len(ranked) > 1 and abs(ranked[1][1] - top_weight) < 1e-9
    return Outcome(
        winner=display.get(top_key, top_key),
        weight=top_weight,
        agreement=top_weight / total if total else 0.0,
        votes=counter,
        samples=len(items),
        unanimous=len(ranked) == 1,
        tie=tie,
    )


def weighted(value: str, *, confidence: float = 0.0, sample: int = 0, meta: dict[str, Any] | None = None) -> Vote:
    return Vote(value=value, weight=max(0.05, confidence), confidence=confidence, sample=sample, meta=meta or {}) 


def from_answers(answers: Iterable[str]) -> Outcome:
    return tally(Vote(value=answer) for answer in answers)


def from_tool_calls(calls: Iterable[dict[str, Any]]) -> Outcome:
    votes = []
    for index, call in enumerate(calls):
        name = str(call.get("tool") or call.get("name") or "")
        confidence = float(call.get("confidence", 0.6) or 0.6)
        votes.append(Vote(value=name, weight=confidence, confidence=confidence, sample=index, meta=call.get("arguments") or {}))
    return tally(votes)


def sample_once(fn: Callable[[int], str], *, samples: int = 3) -> Outcome:
    answers = []
    for index in range(max(1, samples)):
        try:
            answers.append(fn(index))
        except Exception as error:
            answers.append(f"__error__:{error}")
    return from_answers(answers)


def choose_tool(samples: Iterable[dict[str, Any]], *, tools: Iterable[str], min_agreement: float = 0.6) -> tuple[str, Outcome]:
    allowed = set(tools)
    calls = [call for call in samples if str(call.get("tool") or call.get("name")) in allowed]
    outcome = from_tool_calls(calls)
    if not outcome.winner or outcome.agreement < min_agreement:
        return "", outcome
    return outcome.winner, outcome


def majority_arguments(votes: Iterable[Vote]) -> dict[str, Any]:
    """Pick the arguments that came with the winning tool, by vote weight."""

    items = [vote for vote in votes if vote.meta]
    if not items:
        return {}
    outcome = tally(items)
    for vote in items:
        if vote.key() == outcome.winner.strip().lower():
            return dict(vote.meta)
    return dict(items[0].meta)


def consensus_json(answers: Iterable[str], *, keys: Iterable[str] = ()) -> dict[str, Any]:
    """Vote field by field so one bad field does not sink a good answer."""

    parsed: list[dict[str, Any]] = []
    for answer in answers:
        try:
            payload = json.loads(answer)
        except (TypeError, json.JSONDecodeError):
            continue
        if isinstance(payload, dict):
            parsed.append(payload)
    if not parsed:
        return {}
    fields = set(keys) or {key for payload in parsed for key in payload}
    result: dict[str, Any] = {}
    for name in fields:
        values = [json.dumps(payload[name], sort_keys=True) for payload in parsed if name in payload]
        if not values:
            continue
        outcome = from_answers(values)
        try:
            result[name] = json.loads(outcome.winner)
        except json.JSONDecodeError:
            result[name] = outcome.winner
    return result


def escalate(agreement: float, *, floor: float = 0.5, ceiling: float = 0.95) -> bool:
    """Should a low-agreement answer be handed to a stronger model?"""

    return agreement < floor or agreement > ceiling


def agreement_stats(outcomes: Iterable[Outcome]) -> dict[str, float]:
    items = list(outcomes)
    if not items:
        return {"runs": 0.0, "mean_agreement": 0.0, "unanimous_rate": 0.0}
    return {
        "runs": float(len(items)),
        "mean_agreement": round(sum(item.agreement for item in items) / len(items), 3),
        "unanimous_rate": round(sum(1 for item in items if item.unanimous) / len(items), 3),
    }


def explain(outcome: Outcome) -> str:
    lines = [f"winner: {outcome.winner or 'none'}", f"agreement: {outcome.agreement:.2f}", "votes:"]
    for value, weight in outcome.votes.most_common():
        lines.append(f"- {value}: {weight:.2f}")
    return "\n".join(lines)
