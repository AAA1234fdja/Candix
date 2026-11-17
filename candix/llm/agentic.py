"""Small reasoning helpers shared by the planner and the worker.

Nothing here calls a model. These are the deterministic pieces around a model
call: parsing a ReAct trace, checking that a plan is actionable, scoring a
self-critique, and rewriting a failed step into a narrower retry.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Iterable

from candix.llm.jsonschema import loads

_THOUGHT = re.compile(r"(?ims)^\s*(?:thought|thinking)\s*:\s*(.+?)(?=^\s*(?:action|observation)\s*:|\Z)")
_ACTION = re.compile(r"(?im)^\s*action\s*:\s*(.+?)\s*$")
_OBSERVATION = re.compile(r"(?ims)^\s*observation\s*:\s*(.+?)(?=^\s*(?:thought|action)\s*:|\Z)")
_FINAL = re.compile(r"(?im)^\s*(?:final answer|answer)\s*:\s*(.+)$")


@dataclass
class Step:
    thought: str = ""
    action: str = ""
    observation: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"thought": self.thought[:600], "action": self.action, "observation": self.observation[:600]}


@dataclass
class Trace:
    steps: list[Step] = field(default_factory=list)
    final: str = ""

    @property
    def actions(self) -> list[str]:
        return [step.action for step in self.steps if step.action]

    def to_dict(self) -> dict[str, Any]:
        return {"steps": [step.to_dict() for step in self.steps], "final": self.final[:800]}


def parse_trace(text: str) -> Trace:
    """Read a Thought/Action/Observation transcript, tolerant of missing parts."""

    trace = Trace()
    thought = _THOUGHT.search(text or "")
    action = _ACTION.search(text or "")
    observation = _OBSERVATION.search(text or "")
    if thought:
        trace.steps.append(Step(thought=thought.group(1).strip()))
    if action:
        current = trace.steps[-1] if trace.steps else Step()
        current.action = action.group(1).strip()
        if not trace.steps:
            trace.steps.append(current)
    if observation:
        current = trace.steps[-1] if trace.steps else Step()
        current.observation = observation.group(1).strip()
        if not trace.steps:
            trace.steps.append(current)
    final = _FINAL.search(text or "")
    if final:
        trace.final = final.group(1).strip()
    return trace


def is_actionable(step: dict[str, Any], tool_names: Iterable[str]) -> tuple[bool, list[str]]:
    """A step is actionable when the tool exists and arguments are an object."""

    problems: list[str] = []
    tool = str(step.get("tool") or step.get("name") or "")
    if not tool:
        problems.append("no tool named")
    elif tool not in set(tool_names):
        problems.append(f"unknown tool {tool!r}")
    arguments = step.get("arguments", step.get("args", {}))
    if arguments is None:
        arguments = {}
    if not isinstance(arguments, dict):
        problems.append("arguments must be an object")
    return not problems, problems


def narrow(step: dict[str, Any], *, reason: str = "") -> dict[str, Any]:
    """Rewrite a failed step into a smaller, safer retry."""

    clone = json.loads(json.dumps(step))
    arguments = clone.setdefault("arguments", {})
    if "max_pages" in arguments:
        arguments["max_pages"] = max(1, int(arguments["max_pages"]) // 2)
    if "iterations" in arguments:
        arguments["iterations"] = max(10, int(arguments["iterations"]) // 2)
    if "max_attempts" in arguments:
        arguments["max_attempts"] = max(1, int(arguments["max_attempts"]) - 1)
    if "limit" in arguments:
        arguments["limit"] = max(5, int(arguments["limit"]) // 2)
    if "urls" in arguments and isinstance(arguments["urls"], list):
        arguments["urls"] = arguments["urls"][: max(1, len(arguments["urls"]) // 2)]
    if reason:
        arguments["note"] = f"retry after: {reason[:120]}"
    clone["retry"] = True
    return clone


def repair_plan(text: str, tool_names: Iterable[str]) -> list[dict[str, Any]]:
    """Extract the actionable steps from a model plan, dropping the rest."""

    payload = loads(text)
    steps: list[Any] = []
    if isinstance(payload, dict):
        steps = payload.get("intents") or payload.get("steps") or payload.get("plan") or []
    elif isinstance(payload, list):
        steps = payload
    output = []
    for item in steps:
        if not isinstance(item, dict):
            continue
        ok, _problems = is_actionable(item, tool_names)
        if ok:
            output.append(item)
    return output


@dataclass
class Critique:
    score: float
    issues: list[str] = field(default_factory=list)
    missing_evidence: bool = False
    overclaimed: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": round(self.score, 2),
            "issues": self.issues,
            "missing_evidence": self.missing_evidence,
            "overclaimed": self.overclaimed,
        }

    def acceptable(self, *, threshold: float = 0.6) -> bool:
        return self.score >= threshold and not self.overclaimed


_STRONG = ("confirmed", "proven", "exploited", "demonstrated", "verified")
_WEAK = ("may", "might", "could", "possibly", "perhaps", "seems", "appears")


def critique(text: str, *, evidence_refs: int = 0) -> Critique:
    """Score a finding narrative for evidence and overclaiming."""

    lowered = (text or "").lower()
    issues: list[str] = []
    score = 1.0
    if not text.strip():
        return Critique(0.0, ["empty text"], missing_evidence=True)
    if any(marker in lowered for marker in _STRONG) and evidence_refs == 0:
        issues.append("strong claim without a referenced exchange")
        score -= 0.35
    if evidence_refs:
        score += min(0.2, 0.05 * evidence_refs)
    if any(marker in lowered for marker in _WEAK):
        issues.append("hedged language; state the observation instead")
        score -= 0.1
    if len(text) > 1200:
        issues.append("narrative too long for a ticket")
        score -= 0.05
    if "impact" not in lowered:
        issues.append("impact not stated")
        score -= 0.1
    return Critique(
        score=max(0.0, min(1.0, score)),
        issues=issues,
        missing_evidence=evidence_refs == 0,
        overclaimed=any(marker in lowered for marker in _STRONG) and evidence_refs == 0,
    )


def reflection_questions(trace: Trace, *, findings: int = 0, proofs: int = 0) -> list[str]:
    """Questions a run should answer before it writes its lessons."""

    questions: list[str] = []
    if not trace.steps:
        questions.append("Why did the model produce no reasoning steps?")
    if findings == 0:
        questions.append("Was the surface actually reachable, or did scope block it?")
    if proofs == 0 and findings:
        questions.append("Why did no finding reach a proof: gate, payload or evidence?")
    if len(trace.actions) > len(set(trace.actions)):
        questions.append("Which action repeated, and what made it look necessary?")
    return questions


def compress_observations(observations: Iterable[str], *, limit: int = 6) -> str:
    """Keep the first line of each observation, deduplicated."""

    seen: list[str] = []
    for observation in observations:
        line = " ".join(str(observation).strip().splitlines()[0].split())[:160] if str(observation).strip() else ""
        if line and line not in seen:
            seen.append(line)
        if len(seen) >= limit:
            break
    return "\n".join(f"- {line}" for line in seen)


def confidence_from_evidence(evidence_count: int, reproduced: bool = False) -> str:
    if reproduced and evidence_count >= 2:
        return "confirmed"
    if evidence_count >= 1:
        return "likely"
    return "possible"
