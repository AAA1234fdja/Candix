"""Markdown skills: load, validate, select and render.

A skill is a ``SKILL.md`` file with YAML-ish frontmatter:

    ---
    name: api-recon
    description: "when to use it"
    tags: [api, recon]
    phase: detect
    tools: [http.request, payloads.search]
    ---

    Body: the procedure the worker should follow.

The loader rejects malformed frontmatter with a precise message instead of
silently shipping a skill the model will never select.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

_FRONTMATTER = re.compile(r"\A---\s*\n(.*?)\n---\s*\n?(.*)\Z", re.DOTALL)
_KEY = re.compile(r"^([A-Za-z_][A-Za-z0-9_-]*)\s*:\s*(.*)$")
_REQUIRED = ("name", "description")


class SkillError(ValueError):
    """A skill file is malformed."""


@dataclass
class Skill:
    name: str
    description: str
    body: str = ""
    tags: list[str] = field(default_factory=list)
    phase: str = ""
    tools: list[str] = field(default_factory=list)
    path: str = ""
    when_to_use: str = ""
    version: str = "1"

    @property
    def words(self) -> int:
        return len(self.body.split())

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "tags": list(self.tags),
            "phase": self.phase,
            "tools": list(self.tools),
            "path": self.path,
            "words": self.words,
        }

    def render(self, *, max_chars: int = 6000) -> str:
        body = self.body.strip()
        if len(body) > max_chars:
            body = body[:max_chars] + "\n… [skill truncated]"
        header = f"### Skill: {self.name}\n{self.description}\n"
        if self.tools:
            header += f"Preferred tools: {', '.join(self.tools)}\n"
        return header + "\n" + body


def parse_frontmatter(text: str) -> tuple[dict[str, Any], str]:
    match = _FRONTMATTER.match(text)
    if not match:
        raise SkillError("missing frontmatter block delimited by --- lines")
    raw, body = match.group(1), match.group(2)
    meta: dict[str, Any] = {}
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match_key = _KEY.match(line)
        if not match_key:
            raise SkillError(f"cannot parse frontmatter line: {line!r}")
        key, value = match_key.group(1), match_key.group(2).strip()
        meta[key] = _coerce_value(value)
    return meta, body


def _coerce_value(value: str) -> Any:
    text = value.strip()
    if not text:
        return ""
    if text.startswith("[") and text.endswith("]"):
        inner = text[1:-1].strip()
        if not inner:
            return []
        return [_strip_quotes(item.strip()) for item in inner.split(",") if item.strip()]
    if text.lower() in {"true", "false"}:
        return text.lower() == "true"
    return _strip_quotes(text)


def _strip_quotes(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        return value[1:-1]
    return value


def load_skill(path: str | Path) -> Skill:
    source = Path(path)
    try:
        text = source.read_text(encoding="utf-8")
    except OSError as error:
        raise SkillError(f"cannot read {source}: {error}") from error
    meta, body = parse_frontmatter(text)
    missing = [key for key in _REQUIRED if not meta.get(key)]
    if missing:
        raise SkillError(f"{source.name}: missing required field(s): {', '.join(missing)}")
    name = str(meta["name"]).strip()
    if not re.match(r"^[a-z0-9][a-z0-9-]{1,40}$", name):
        raise SkillError(f"{source.name}: name {name!r} must be lowercase kebab-case")
    tags = meta.get("tags") or []
    tools = meta.get("tools") or []
    if isinstance(tags, str):
        tags = [tags]
    if isinstance(tools, str):
        tools = [tools]
    return Skill(
        name=name,
        description=str(meta["description"]).strip(),
        body=body.strip(),
        tags=[str(tag) for tag in tags],
        phase=str(meta.get("phase", "")),
        tools=[str(tool) for tool in tools],
        path=str(source),
        when_to_use=str(meta.get("when_to_use", "")),
        version=str(meta.get("version", "1")),
    )


class SkillRegistry:
    """A directory of skills plus selection by goal text and phase."""

    def __init__(self, skills: Iterable[Skill] = (), *, errors: Iterable[str] = ()) -> None:
        self.skills: dict[str, Skill] = {skill.name: skill for skill in skills}
        self.errors: list[str] = list(errors)

    @classmethod
    def load(cls, directory: str | Path) -> "SkillRegistry":
        root = Path(directory)
        skills: list[Skill] = []
        errors: list[str] = []
        if not root.exists():
            return cls((), errors=[f"skills directory not found: {root}"])
        for path in sorted(root.rglob("SKILL.md")):
            try:
                skills.append(load_skill(path))
            except SkillError as error:
                errors.append(str(error))
        return cls(skills, errors=errors)

    # ------------------------------------------------------------------
    def get(self, name: str) -> Skill | None:
        return self.skills.get(name)

    def names(self) -> list[str]:
        return sorted(self.skills)

    def select(self, text: str, *, phase: str = "", limit: int = 2) -> list[Skill]:
        """Rank skills by keyword overlap with the goal and phase."""

        terms = {token for token in re.findall(r"[a-z0-9]+", (text or "").lower()) if len(token) > 3}
        scored: list[tuple[float, Skill]] = []
        for skill in self.skills.values():
            haystack = f"{skill.name} {skill.description} {' '.join(skill.tags)} {skill.when_to_use}".lower()
            overlap = len(terms & {token for token in re.findall(r"[a-z0-9]+", haystack) if len(token) > 3})
            score = overlap / max(1, len(terms)) if terms else 0.0
            if phase and skill.phase and skill.phase == phase:
                score += 0.25
            if score > 0:
                scored.append((score, skill))
        scored.sort(key=lambda item: (-item[0], item[1].name))
        return [skill for _score, skill in scored[:limit]]

    def render(self, names: Iterable[str] | None = None, *, max_chars: int = 6000) -> str:
        selected = [self.skills[name] for name in (names or self.skills) if name in self.skills]
        return "\n\n".join(skill.render(max_chars=max_chars) for skill in selected)

    def validate(self) -> list[str]:
        problems = list(self.errors)
        seen: set[str] = set()
        for skill in self.skills.values():
            if skill.name in seen:
                problems.append(f"duplicate skill name: {skill.name}")
            seen.add(skill.name)
            if not skill.body:
                problems.append(f"{skill.name}: empty body")
            unknown_phase = skill.phase and skill.phase not in {"recon", "detect", "exploit", "verify", "report"}
            if unknown_phase:
                problems.append(f"{skill.name}: unknown phase {skill.phase!r}")
        return problems

    def snapshot(self) -> dict[str, Any]:
        return {
            "skills": self.names(),
            "errors": list(self.errors),
            "problems": self.validate(),
        }
