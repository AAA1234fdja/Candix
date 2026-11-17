"""Recover a usable answer from a model that did not follow the format."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Callable


@dataclass
class Repair:
    value: Any
    raw: str
    steps: list[str] = field(default_factory=list)
    ok: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {"ok": self.ok, "steps": self.steps, "value": self.value}


FENCE = re.compile(r"```(?:json|javascript|python)?\s*(.*?)```", re.DOTALL)
TRUE_WORDS = (("True", "true"), ("False", "false"), ("None", "null"), ("NaN", "null"), ("undefined", "null"))


def strip_fences(text: str) -> tuple[str, bool]:
    match = FENCE.search(text or "")
    if match:
        return match.group(1).strip(), True
    return (text or "").strip(), False


def extract_object(text: str) -> tuple[str, bool]:
    """Return the first balanced {...} or [...] block, ignoring braces in strings."""

    depth = 0
    start = -1
    opened = ""
    in_string = False
    escape = False
    for index, char in enumerate(text or ""):
        if in_string:
            if escape:
                escape = False
            elif char == "\\":
                escape = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char in "{[":
            if depth == 0:
                start = index
                opened = char
            depth += 1
        elif char in "}]":
            depth -= 1
            if depth == 0 and start >= 0:
                candidate = text[start : index + 1]
                if (opened == "{" and char == "}") or (opened == "[" and char == "]"):
                    return candidate, True
                depth = 0
                start = -1
    return "", False


def strip_trailing_commas(text: str) -> tuple[str, bool]:
    cleaned = re.sub(r",(\s*[}\]])", r"\1", text)
    return cleaned, cleaned != text


def quote_keys(text: str) -> tuple[str, bool]:
    cleaned = re.sub(r"([{,]\s*)([A-Za-z_][A-Za-z0-9_\-]*)\s*:", r'\1"\2":', text)
    return cleaned, cleaned != text


def single_to_double(text: str) -> tuple[str, bool]:
    if '"' in text and "'" not in text:
        return text, False
    cleaned = re.sub(r"(?<!\\)'([^'\\]*(?:\\.[^'\\]*)*)'", lambda m: '"' + m.group(1).replace('"', '\\"') + '"', text)
    return cleaned, cleaned != text


def normalise_literals(text: str) -> tuple[str, bool]:
    cleaned = text
    for source, target in TRUE_WORDS:
        cleaned = re.sub(rf"(?<=[:\s,\[]){source}(?=[\s,\]\}}])", target, cleaned)
    return cleaned, cleaned != text


def strip_comments(text: str) -> tuple[str, bool]:
    cleaned = re.sub(r"(?m)^\s*//.*$", "", text)
    cleaned = re.sub(r"/\*.*?\*/", "", cleaned, flags=re.DOTALL)
    return cleaned, cleaned != text


LADDER: tuple[tuple[str, Callable[[str], tuple[str, bool]]], ...] = (
    ("strip_fences", strip_fences),
    ("strip_comments", strip_comments),
    ("trailing_commas", strip_trailing_commas),
    ("normalise_literals", normalise_literals),
    ("single_quotes", single_to_double),
    ("quote_keys", quote_keys),
)


def repair_json(text: str) -> Repair:
    steps: list[str] = []
    candidate, fenced = strip_fences(text)
    if fenced:
        steps.append("unstripped code fence")
    extracted, found = extract_object(candidate)
    if found:
        if extracted != candidate.strip():
            steps.append("extracted embedded block")
        candidate = extracted
    try:
        return Repair(value=json.loads(candidate), raw=text, steps=steps)
    except json.JSONDecodeError:
        pass
    for name, step in LADDER:
        candidate, changed = step(candidate)
        if changed:
            steps.append(name)
        try:
            return Repair(value=json.loads(candidate), raw=text, steps=steps)
        except json.JSONDecodeError:
            continue
    return Repair(value=None, raw=text, steps=steps + ["unrecoverable"], ok=False)


def repair_arguments(text: str, *, allowed: set[str] | None = None) -> Repair:
    result = repair_json(text)
    if not result.ok or not isinstance(result.value, dict):
        return Repair(value={}, raw=text, steps=result.steps + ["arguments are not an object"], ok=False)
    payload = dict(result.value)
    for key in list(payload):
        if allowed is not None and key not in allowed:
            steps = list(result.steps) + [f"dropped unknown key {key}"]
            payload.pop(key)
            result = Repair(value=payload, raw=text, steps=steps)
    return Repair(value=payload, raw=text, steps=result.steps, ok=result.ok)


def repair_action(text: str, *, tools: set[str]) -> Repair:
    result = repair_json(text)
    if result.ok and isinstance(result.value, dict):
        name = str(result.value.get("tool") or result.value.get("action") or "")
        if name in tools:
            result.value["tool"] = name
            return result
        for candidate in tools:
            if candidate.lower() == name.lower().replace(" ", "_"):
                result.value["tool"] = candidate
                result.steps.append("normalised tool name")
                return result
    # Last try: find a tool name mentioned in the prose.
    lowered = text.lower()
    for candidate in sorted(tools, key=len, reverse=True):
        if candidate.lower() in lowered:
            brace = text.find("{")
            arguments = repair_json(text[brace:]) if brace >= 0 else Repair(value={}, raw=text, ok=False)
            return Repair(
                value={"tool": candidate, "arguments": arguments.value if isinstance(arguments.value, dict) else {}},
                raw=text,
                steps=["recovered tool from prose"],
            )
    return Repair(value=None, raw=text, steps=["no tool recovered"], ok=False)


def coerce_number(value: Any, *, default: float = 0.0) -> float:
    if isinstance(value, (int, float)):
        return float(value)
    try:
        return float(str(value).strip().rstrip("%"))
    except (TypeError, ValueError):
        return default


def coerce_bool(value: Any, *, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "y", "on"}:
        return True
    if text in {"0", "false", "no", "n", "off"}:
        return False
    return default


def coerce_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if value in (None, ""):
        return []
    if isinstance(value, str):
        return [part.strip() for part in re.split(r"[,\n;]", value) if part.strip()]
    return [value]


def repair_ladder(text: str, *, parsers: list[Callable[[str], Any]]) -> Any:
    """Try several parsers in order and return the first non-None result."""

    for parser in parsers:
        try:
            result = parser(text)
        except Exception:
            continue
        if result is not None:
            return result
    return None


def attempts_report(repairs: list[Repair]) -> str:
    total = len(repairs)
    fixed = sum(1 for item in repairs if item.ok and item.steps)
    failed = sum(1 for item in repairs if not item.ok)
    return f"{total} response(s): {fixed} repaired, {failed} unrecoverable"


def needs_retry(repair: Repair, *, max_steps: int = 2) -> bool:
    if repair.ok:
        return False
    return len(repair.steps) < max_steps


def instruct_retry(original: str, failure: str, *, schema: str = "") -> str:
    lines = [
        "The previous answer could not be used.",
        f"Problem: {failure}",
    ]
    if schema:
        lines.append(f"Required shape: {schema}")
    lines.append("Reply with JSON only, no prose and no code fence.")
    lines.append(f"Previous answer: {original[:500]}")
    return "\n".join(lines)
