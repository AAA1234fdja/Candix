"""Named playbooks: a plan written once, parameterised per target.

The heuristic planner is reactive. A playbook is the opposite: a short, ordered
list of steps an operator already knows they want, with parameters filled from
the target. Both live in the same loop, so a playbook can seed the first turns
and the planner takes over when it runs out.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from candix.agent.models import Decision, Intent, Phase
from candix.llm.embeddings import VectorIndex, Document


class PlaybookError(ValueError):
    """A playbook is malformed or cannot be expanded for this target."""


@dataclass
class Step:
    tool: str
    title: str = ""
    phase: str = "recon"
    arguments: dict[str, Any] = field(default_factory=dict)
    priority: float = 0.8
    when: str = ""
    tags: list[str] = field(default_factory=list)

    def to_intent(self, values: dict[str, Any]) -> Intent:
        arguments = _fill(self.arguments, values)
        return Intent(
            title=_fill_text(self.title or self.tool, values),
            description=str(arguments.get("note", ""))[:200],
            phase=Phase(self.phase),
            tool=self.tool,
            arguments=arguments,
            priority=self.priority,
            tags=list(self.tags) + ["playbook"],
            origin="playbook",
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "title": self.title,
            "phase": self.phase,
            "arguments": self.arguments,
            "priority": self.priority,
            "when": self.when,
            "tags": self.tags,
        }


def _fill(value: Any, values: dict[str, Any]) -> Any:
    if isinstance(value, str):
        return _fill_text(value, values)
    if isinstance(value, list):
        return [_fill(item, values) for item in value]
    if isinstance(value, dict):
        return {key: _fill(item, values) for key, item in value.items()}
    return value


def _fill_text(text: str, values: dict[str, Any]) -> str:
    out = text
    for key, value in values.items():
        out = out.replace("{" + key + "}", str(value))
    return out


def _missing(text: str, values: dict[str, Any]) -> list[str]:
    import re

    return [name for name in re.findall(r"\{([a-z_][a-z0-9_]*)\}", text) if name not in values]


@dataclass
class Playbook:
    name: str
    description: str = ""
    steps: list[Step] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    requires: list[str] = field(default_factory=list)

    def validate(self) -> list[str]:
        problems: list[str] = []
        if not self.steps:
            problems.append("no steps")
        for step in self.steps:
            if step.phase not in {phase.value for phase in Phase}:
                problems.append(f"{step.tool}: unknown phase {step.phase!r}")
            if not step.tool:
                problems.append("step without a tool")
        return problems

    def expand(self, values: dict[str, Any], *, limit: int = 0) -> list[Intent]:
        missing: list[str] = []
        for step in self.steps:
            missing.extend(_missing(json.dumps(step.arguments), values))
        if missing:
            raise PlaybookError(f"{self.name}: missing values for {', '.join(sorted(set(missing)))}")
        steps = self.steps[:limit] if limit else self.steps
        return [step.to_intent(values) for step in steps]

    def applicable(self, state: Any) -> bool:
        """Only expand a step when its precondition holds."""

        coverage = getattr(state, "coverage", {}) or {}
        attempted = " ".join(getattr(state, "attempted", []) or [])
        if "requires endpoints" in self.requires and not int(coverage.get("endpoints", 0) or 0):
            return False
        if "requires findings" in self.requires and not getattr(state, "findings", []):
            return False
        if self.name.split(":")[0] in attempted:
            return False
        return True

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "tags": self.tags,
            "requires": self.requires,
            "steps": [step.to_dict() for step in self.steps],
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "Playbook":
        steps = [
            Step(
                tool=str(item.get("tool", "")),
                title=str(item.get("title", "")),
                phase=str(item.get("phase", "recon")),
                arguments=dict(item.get("arguments") or {}),
                priority=float(item.get("priority", 0.8)),
                when=str(item.get("when", "")),
                tags=[str(tag) for tag in item.get("tags") or []],
            )
            for item in payload.get("steps") or []
            if isinstance(item, dict)
        ]
        return cls(
            name=str(payload.get("name", "")),
            description=str(payload.get("description", "")),
            steps=steps,
            tags=[str(tag) for tag in payload.get("tags") or []],
            requires=[str(item) for item in payload.get("requires") or []],
        )


BUILTIN: tuple[Playbook, ...] = (
    Playbook(
        name="recon-sweep",
        description="Map the surface: crawl, probe for exposed files, read any API description.",
        tags=["recon", "enumeration"],
        steps=[
            Step("recon.crawl", "Crawl {url}", "recon", {"url": "{url}", "depth": 2, "max_pages": 25}, 1.0, tags=["recon"]),
            Step("recon.fingerprint", "Fingerprint {url}", "recon", {"url": "{url}"}, 0.9, tags=["recon"]),
            Step("web.probe", "Probe well-known paths", "recon", {"url": "{url}", "limit": 60}, 0.8, tags=["recon"]),
            Step("api.spec", "Read the API description", "recon", {"url": "{url}"}, 0.7, tags=["api"]),
            Step("graphql.query", "Introspect GraphQL", "recon", {"url": "{url}"}, 0.6, tags=["api"]),
        ],
    ),
    Playbook(
        name="exposure-sweep",
        description="Look for files that should never be public and prove the exposure.",
        tags=["exposure"],
        requires=["requires endpoints"],
        steps=[
            Step("web.probe", "Hunt exposed files", "recon", {"url": "{url}", "limit": 120}, 0.9, tags=["exposure"]),
            Step("http.batch", "Re-request the sensitive paths", "detect", {"urls": ["{url}/.env", "{url}/.git/config"]}, 0.7),
        ],
    ),
    Playbook(
        name="api-review",
        description="Ingest the API description, then attack authorization on the documented objects.",
        tags=["api", "authorization"],
        requires=["requires endpoints"],
        steps=[
            Step("api.spec", "Ingest the OpenAPI document", "recon", {"url": "{url}"}, 0.9, tags=["api"]),
            Step("detect.run", "Run the detector catalogue", "detect", {"include_intrusive": True, "max_findings": 40}, 0.8),
            Step("http.request", "Probe an object endpoint with a foreign id", "detect", {"url": "{idor_url}", "note": "authorization probe"}, 0.6),
        ],
    ),
    Playbook(
        name="auth-review",
        description="Check login, session handling, token validation and OAuth metadata.",
        tags=["auth"],
        requires=["requires endpoints"],
        steps=[
            Step("auth.flow", "Exercise the login form", "detect", {"url": "{url}"}, 0.9, tags=["auth"]),
            Step("oauth.flow", "Read OIDC metadata", "recon", {"issuer": "{url}"}, 0.6, tags=["oauth"]),
            Step("ws.probe", "Check WebSocket handling", "recon", {"url": "{url}", "timeout": 3}, 0.5, tags=["websocket"]),
        ],
    ),
    Playbook(
        name="injection-sweep",
        description="Fuzz the parameters that matter, then prove what reacts.",
        tags=["injection", "fuzz"],
        requires=["requires endpoints"],
        steps=[
            Step("detect.run", "Baseline with the detector catalogue", "detect", {"include_intrusive": True, "max_findings": 40}, 0.9),
            Step("fuzz.run", "Mutate discovered parameters", "detect", {"iterations": 120, "strategy": "depth"}, 0.8, tags=["fuzz"]),
            Step("exploit.run", "Prove the strongest finding", "exploit", {"max_attempts": 2, "min_severity": "high"}, 0.7),
        ],
    ),
    Playbook(
        name="proof-run",
        description="Turn verified findings into proofs and close the goal.",
        tags=["exploit", "proof"],
        requires=["requires findings"],
        steps=[
            Step("exploit.run", "Exploit the strongest findings", "exploit", {"max_attempts": 3, "min_severity": "high"}, 0.95),
            Step("facts.add", "Record the strongest finding", "verify", {"claim": "{finding_claim}", "source": "tool_output", "confidence": "observed"}, 0.6),
            Step("goal.prove", "Prove the goal", "verify", {"claim": "{goal}"}, 0.5),
        ],
    ),
)


class PlaybookRegistry:
    def __init__(self, playbooks: Iterable[Playbook] = ()) -> None:
        self.playbooks: dict[str, Playbook] = {}
        self.extend(playbooks)

    def add(self, playbook: Playbook) -> Playbook:
        problems = playbook.validate()
        if problems:
            raise PlaybookError(f"{playbook.name}: {', '.join(problems)}")
        self.playbooks[playbook.name] = playbook
        return playbook

    def extend(self, playbooks: Iterable[Playbook]) -> None:
        for playbook in playbooks:
            self.add(playbook)

    def get(self, name: str) -> Playbook:
        try:
            return self.playbooks[name]
        except KeyError as error:
            raise PlaybookError(f"unknown playbook: {name}") from error

    def names(self) -> list[str]:
        return sorted(self.playbooks)

    def search(self, text: str, *, limit: int = 3) -> list[Playbook]:
        index = VectorIndex()
        ordered = [self.playbooks[name] for name in self.names()]
        for position, playbook in enumerate(ordered):
            index.add(Document(str(position), f"{playbook.name} {playbook.description} {' '.join(playbook.tags)}"))
        hits = index.search(text, limit=limit)
        return [ordered[int(hit.document.id)] for hit in hits]

    def load_directory(self, directory: str | Path) -> int:
        root = Path(directory)
        if not root.exists():
            return 0
        loaded = 0
        for path in sorted(root.glob("*.json")):
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            playbook = Playbook.from_dict(payload if isinstance(payload, dict) else {})
            if playbook.name and playbook.steps:
                self.add(playbook)
                loaded += 1
        return loaded

    def catalogue(self) -> list[dict[str, Any]]:
        return [self.playbooks[name].to_dict() for name in self.names()]


def default_registry(directory: str | Path = "playbooks") -> PlaybookRegistry:
    registry = PlaybookRegistry(BUILTIN)
    registry.load_directory(directory)
    return registry


def values_for(targets: Iterable[str], *, goal: str = "", findings: Iterable[dict[str, Any]] = ()) -> dict[str, Any]:
    target_list = list(targets)
    base = target_list[0].rstrip("/") if target_list else ""
    finding_list = list(findings)
    claim = ""
    if finding_list:
        top = finding_list[0]
        claim = f"{top.get('severity', 'high')} {top.get('title', 'finding')} at {top.get('url', '')}"
    return {
        "url": base,
        "target": base,
        "goal": goal,
        "idor_url": base + "/api/users?id=1" if base else "",
        "finding_claim": claim,
    }


class PlaybookPlanner:
    """Seeds a run with a playbook, then hands over to the normal planner."""

    def __init__(self, playbook: Playbook, fallback: Any, *, values: dict[str, Any] | None = None, limit: int = 0) -> None:
        self.playbook = playbook
        self.fallback = fallback
        self.values = dict(values or {})
        self.limit = limit
        self.expanded = False

    def decide(self, state: Any) -> Decision:
        if not self.expanded and self.playbook.applicable(state):
            values = dict(self.values)
            if "url" not in values and getattr(state, "targets", None):
                values["url"] = str(state.targets[0]).rstrip("/")
            if "goal" not in values:
                values["goal"] = getattr(state, "goal", "")
            try:
                intents = self.playbook.expand(values, limit=self.limit)
            except PlaybookError:
                intents = []
            self.expanded = True
            if intents:
                return Decision(
                    "plan",
                    f"playbook {self.playbook.name}: {len(intents)} step(s)",
                    intents,
                    0.85,
                    "playbook",
                )
        return self.fallback.decide(state)
