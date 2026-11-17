"""Observation contracts: what a tool promises to return.

A tool that silently changes its payload shape breaks every consumer downstream.
Contracts declare the required keys and value types for the ``data`` dictionary
of an observation, validate it when present, and degrade gracefully (drop the
malformed observation, record why) instead of crashing the run.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Iterable

_TYPE_CHECKS: dict[str, Callable[[Any], bool]] = {
    "str": lambda value: isinstance(value, str),
    "int": lambda value: isinstance(value, int) and not isinstance(value, bool),
    "float": lambda value: isinstance(value, (int, float)) and not isinstance(value, bool),
    "bool": lambda value: isinstance(value, bool),
    "list": lambda value: isinstance(value, (list, tuple)),
    "dict": lambda value: isinstance(value, dict),
    "any": lambda value: True,
}


@dataclass
class Field:
    name: str
    kind: str = "any"
    required: bool = True
    item_kind: str = ""
    description: str = ""

    def check(self, value: Any) -> str:
        checker = _TYPE_CHECKS.get(self.kind, _TYPE_CHECKS["any"])
        if not checker(value):
            return f"{self.name}: expected {self.kind}, got {type(value).__name__}"
        if self.kind in {"list"} and self.item_kind:
            item_checker = _TYPE_CHECKS.get(self.item_kind, _TYPE_CHECKS["any"])
            for index, item in enumerate(value):
                if not item_checker(item):
                    return f"{self.name}[{index}]: expected {self.item_kind}, got {type(item).__name__}"
        return ""


@dataclass
class Contract:
    tool: str
    fields: list[Field] = field(default_factory=list)
    allow_unknown: bool = True
    notes: str = ""

    def validate(self, payload: dict[str, Any]) -> tuple[bool, list[str]]:
        problems: list[str] = []
        if not isinstance(payload, dict):
            return False, ["payload is not an object"]
        for spec in self.fields:
            if spec.name not in payload:
                if spec.required:
                    problems.append(f"missing required field: {spec.name}")
                continue
            problem = spec.check(payload[spec.name])
            if problem:
                problems.append(problem)
        if not self.allow_unknown:
            known = {spec.name for spec in self.fields}
            for key in payload:
                if key not in known:
                    problems.append(f"unexpected field: {key}")
        return not problems, problems

    def coerce(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Best-effort conversion of scalar-ish values before validation."""

        output = dict(payload or {})
        for spec in self.fields:
            if spec.name not in output:
                continue
            value = output[spec.name]
            if spec.kind == "str" and isinstance(value, (int, float, bool)):
                output[spec.name] = str(value)
            elif spec.kind == "int" and isinstance(value, str) and value.strip().lstrip("-").isdigit():
                output[spec.name] = int(value)
            elif spec.kind == "float" and isinstance(value, str):
                try:
                    output[spec.name] = float(value)
                except ValueError:
                    pass
            elif spec.kind == "list" and isinstance(value, tuple):
                output[spec.name] = list(value)
        return output

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "required": [spec.name for spec in self.fields if spec.required],
            "optional": [spec.name for spec in self.fields if not spec.required],
            "notes": self.notes,
        }


CONTRACTS: dict[str, Contract] = {
    "recon.crawl": Contract(
        "recon.crawl",
        [Field("pages", "list", item_kind="dict"), Field("stats", "dict", required=False)],
        notes="pages holds at least url and method",
    ),
    "recon.fingerprint": Contract(
        "recon.fingerprint",
        [Field("technologies", "list", required=False, item_kind="dict"), Field("headers", "dict", required=False)],
    ),
    "detect.run": Contract("detect.run", [Field("findings", "list", item_kind="dict")]),
    "http.request": Contract(
        "http.request",
        [Field("status", "int"), Field("headers", "dict", required=False), Field("body", "str", required=False)],
    ),
    "facts.add": Contract("facts.add", [Field("fact", "dict", required=False), Field("action", "str", required=False)]),
    "goal.prove": Contract(
        "goal.prove",
        [Field("proven", "bool"), Field("facts", "list", required=False)],
    ),
    "exploit.run": Contract(
        "exploit.run",
        [Field("proofs", "list", item_kind="dict"), Field("attempts", "list", required=False, item_kind="dict")],
    ),
}


@dataclass
class Validation:
    tool: str
    ok: bool
    problems: list[str] = field(default_factory=list)
    payload: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"tool": self.tool, "ok": self.ok, "problems": list(self.problems)}


def contract_for(tool: str) -> Contract | None:
    return CONTRACTS.get(tool)


def validate(tool: str, payload: Any) -> Validation:
    contract = contract_for(tool)
    if contract is None:
        return Validation(tool, True, [], payload if isinstance(payload, dict) else {})
    if not isinstance(payload, dict):
        return Validation(tool, False, ["payload is not an object"], {})
    coerced = contract.coerce(payload)
    ok, problems = contract.validate(coerced)
    return Validation(tool, ok, problems, coerced)


def register(contract: Contract) -> Contract:
    CONTRACTS[contract.tool] = contract
    return contract


def catalogue() -> list[dict[str, Any]]:
    return [contract.to_dict() for contract in sorted(CONTRACTS.values(), key=lambda item: item.tool)]


def audit(results: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Validate a batch, returning counters per tool."""

    counts: dict[str, dict[str, int]] = {}
    for result in results:
        tool = str(result.get("tool", ""))
        valid = validate(tool, result.get("payload") or result.get("data") or {})
        bucket = counts.setdefault(tool, {"ok": 0, "bad": 0})
        bucket["ok" if valid.ok else "bad"] += 1
    return counts
