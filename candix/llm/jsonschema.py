"""A small JSON Schema validator plus tolerant JSON extraction.

Models are not reliable JSON emitters. This module validates tool arguments
against the schema we advertise and extracts a JSON object from prose, fenced
code blocks or truncated output. It deliberately implements the subset of
JSON Schema that Candix actually publishes: ``type``, ``properties``,
``required``, ``enum``, ``items``, ``additionalProperties``, ``minimum``,
``maximum``, ``minLength``, ``maxLength``, ``pattern``, ``oneOf``/``anyOf`` and
``const``.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Iterable

_FENCE = re.compile(r"```(?:json|JSON)?\s*(.*?)```", re.DOTALL)
_OBJECT = re.compile(r"\{(?:[^{}]|(?:\{[^{}]*\}))*\}", re.DOTALL)


@dataclass
class ValidationError:
    path: str
    message: str

    def __str__(self) -> str:
        return f"{self.path or '$'}: {self.message}"

    def to_dict(self) -> dict[str, str]:
        return {"path": self.path, "message": self.message}


@dataclass
class ValidationResult:
    valid: bool
    errors: list[ValidationError] = field(default_factory=list)
    value: Any = None

    def messages(self, limit: int = 5) -> list[str]:
        return [str(error) for error in self.errors[:limit]]

    def as_feedback(self) -> str:
        if self.valid:
            return ""
        return "The arguments failed validation:\n" + "\n".join(f"- {item}" for item in self.errors[:8])


_TYPES = {
    "object": dict,
    "array": list,
    "string": str,
    "integer": int,
    "number": (int, float),
    "boolean": bool,
    "null": type(None),
}


def _type_ok(value: Any, expected: str) -> bool:
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if expected == "boolean":
        return isinstance(value, bool)
    python_type = _TYPES.get(expected)
    if python_type is None:
        return True
    return isinstance(value, python_type)


def validate(value: Any, schema: dict[str, Any], *, path: str = "") -> list[ValidationError]:
    """Validate ``value`` against ``schema`` returning every problem found."""

    errors: list[ValidationError] = []
    if not schema:
        return errors

    if "const" in schema and value != schema["const"]:
        errors.append(ValidationError(path, f"must equal {schema['const']!r}"))

    if "enum" in schema and value not in schema["enum"]:
        allowed = ", ".join(repr(item) for item in schema["enum"][:8])
        errors.append(ValidationError(path, f"must be one of {allowed}"))

    expected = schema.get("type")
    if expected:
        names = expected if isinstance(expected, list) else [expected]
        if not any(_type_ok(value, name) for name in names):
            errors.append(ValidationError(path, f"expected {', '.join(names)}, got {type(value).__name__}"))
            return errors

    if isinstance(value, str):
        if "minLength" in schema and len(value) < int(schema["minLength"]):
            errors.append(ValidationError(path, f"shorter than {schema['minLength']} characters"))
        if "maxLength" in schema and len(value) > int(schema["maxLength"]):
            errors.append(ValidationError(path, f"longer than {schema['maxLength']} characters"))
        if "pattern" in schema:
            try:
                if not re.search(str(schema["pattern"]), value):
                    errors.append(ValidationError(path, f"does not match pattern {schema['pattern']}"))
            except re.error:
                pass

    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            errors.append(ValidationError(path, f"below minimum {schema['minimum']}"))
        if "maximum" in schema and value > schema["maximum"]:
            errors.append(ValidationError(path, f"above maximum {schema['maximum']}"))

    if isinstance(value, dict):
        properties = schema.get("properties") or {}
        for name in schema.get("required") or ():
            if name not in value:
                errors.append(ValidationError(f"{path}.{name}".strip("."), "is required"))
        additional = schema.get("additionalProperties", True)
        for name, item in value.items():
            child = f"{path}.{name}".strip(".")
            if name in properties:
                errors.extend(validate(item, properties[name], path=child))
            elif additional is False:
                errors.append(ValidationError(child, "is not an allowed property"))
            elif isinstance(additional, dict):
                errors.extend(validate(item, additional, path=child))

    if isinstance(value, list):
        item_schema = schema.get("items")
        if isinstance(item_schema, dict):
            for index, item in enumerate(value):
                errors.extend(validate(item, item_schema, path=f"{path}[{index}]"))
        if "minItems" in schema and len(value) < int(schema["minItems"]):
            errors.append(ValidationError(path, f"needs at least {schema['minItems']} items"))
        if "maxItems" in schema and len(value) > int(schema["maxItems"]):
            errors.append(ValidationError(path, f"allows at most {schema['maxItems']} items"))

    for keyword in ("oneOf", "anyOf"):
        options = schema.get(keyword)
        if not isinstance(options, list):
            continue
        results = [validate(value, option, path=path) for option in options]
        passing = [result for result in results if not result]
        if keyword == "oneOf" and len(passing) != 1:
            errors.append(ValidationError(path, f"must match exactly one oneOf branch ({len(passing)} matched)"))
        if keyword == "anyOf" and not passing:
            errors.append(ValidationError(path, "matches none of the anyOf branches"))

    return errors


def check(value: Any, schema: dict[str, Any]) -> ValidationResult:
    errors = validate(value, schema)
    return ValidationResult(valid=not errors, errors=errors, value=value)


def coerce(value: Any, schema: dict[str, Any]) -> Any:
    """Best-effort coercion for the usual model mistakes ("true", "3", "1")."""

    expected = schema.get("type")
    if expected == "string" and isinstance(value, (int, float, bool)):
        return str(value)
    if isinstance(value, str):
        if expected in {"boolean"} and value.strip().lower() in {"true", "false", "yes", "no", "1", "0"}:
            return value.strip().lower() in {"true", "yes", "1"}
        if expected in {"integer", "number"}:
            try:
                number = float(value.strip())
                return int(number) if expected == "integer" and number.is_integer() else number
            except ValueError:
                return value
        if expected in {"array", "object"}:
            parsed = loads(value)
            if parsed is not None:
                return parsed
    return value


def coerced(value: Any, schema: dict[str, Any]) -> tuple[Any, list[ValidationError]]:
    """Coerce scalars, apply defaults, then validate."""

    candidate = coerce(value, schema)
    if isinstance(candidate, dict):
        candidate = dict(candidate)
        for name, prop in (schema.get("properties") or {}).items():
            if name not in candidate and "default" in prop:
                candidate[name] = prop["default"]
            if name in candidate:
                candidate[name] = coerce(candidate[name], prop)
    errors = validate(candidate, schema)
    return candidate, errors


def loads(text: str) -> Any:
    """Parse JSON, tolerating fences, trailing commas and single quotes."""

    text = (text or "").strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    for match in _FENCE.finditer(text):
        candidate = match.group(1).strip()
        for attempt in (candidate, _relax(candidate)):
            try:
                return json.loads(attempt)
            except json.JSONDecodeError:
                continue
    for match in _OBJECT.finditer(text):
        candidate = match.group(0)
        for attempt in (candidate, _relax(candidate), _relax(candidate).replace("'", '"')):
            try:
                return json.loads(attempt)
            except json.JSONDecodeError:
                continue
    relaxed = _relax(text)
    try:
        return json.loads(relaxed)
    except json.JSONDecodeError:
        return None


def _relax(text: str) -> str:
    without_comments = re.sub(r"(?m)^\s*//.*$", "", text)
    no_trailing = re.sub(r",(\s*[}\]])", r"\1", without_comments)
    return no_trailing


def extract_object(text: str) -> dict[str, Any]:
    parsed = loads(text)
    return parsed if isinstance(parsed, dict) else {}


def repair_truncated(text: str) -> str:
    """Close an unterminated JSON object produced by a max_tokens cut."""

    text = (text or "").strip()
    if not text.startswith("{"):
        return text
    depth = 0
    in_string = False
    escaped = False
    for char in text:
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
    if in_string:
        text += '"'
    if depth > 0:
        text = text.rstrip().rstrip(",")
        text += "}" * depth
    return text


def schema_for_tools(specs: Iterable[Any]) -> dict[str, dict[str, Any]]:
    return {spec.name: spec.parameters for spec in specs}
