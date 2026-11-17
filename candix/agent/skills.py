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

# Skills that are part of Candix core (original 6). Others may be reference-only
# when they require tools not in the Candix registry.
ORIGINAL_SKILLS: frozenset[str] = frozenset({
    "api-authorization",
    "auth-session",
    "evidence-capture",
    "injection-triage",
    "report-writing",
    "secret-exposure",
})

# External tool indicators that imply a skill cannot run on Candix's 23-tool registry
_EXTERNAL_TOOL_HINTS: tuple[str, ...] = (
    "bbot", "subfinder", "httpx", "nuclei", "gowitness", "katana", "ffuf",
    "playwright", "mcp__", "mcp", "cursor", "scopesentry", "rea ",
    "ghidra", "apk", "jadx", "burp", "zap", "sqlmap ", "dalfox",
)


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
    allowed_tools: list[str] = field(default_factory=list)
    mcps: list[str] = field(default_factory=list)
    reference_only: bool = False
    requires_external: list[str] = field(default_factory=list)

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
            "allowed_tools": list(self.allowed_tools),
            "mcps": list(self.mcps),
            "path": self.path,
            "words": self.words,
            "reference_only": self.reference_only,
            "requires_external": list(self.requires_external),
        }

    def render(self, *, max_chars: int = 6000) -> str:
        body = self.body.strip()
        if len(body) > max_chars:
            body = body[:max_chars] + "\n… [skill truncated]"
        header = f"### Skill: {self.name}\n{self.description}\n"
        if self.tools:
            header += f"Preferred tools: {', '.join(self.tools)}\n"
        if self.reference_only:
            header += f"[reference-only: requires {', '.join(self.requires_external) or 'external tooling'}]\n"
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
        # normalise hyphenated keys (allowed-tools → allowed_tools)
        key = key.replace("-", "_")
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


def _detect_external_requirements(skill: Skill) -> list[str]:
    """Return external tool hints found in the skill body/description."""
    haystack = f"{skill.description} {skill.body} {' '.join(skill.allowed_tools)} {' '.join(skill.mcps)}".lower()
    found: list[str] = []
    for hint in _EXTERNAL_TOOL_HINTS:
        if hint.lower() in haystack:
            found.append(hint.strip())
    # also detect tools that are not in ORIGINAL set and contain external naming
    if skill.name not in ORIGINAL_SKILLS and skill.name not in {"api-recon", "api-security"}:
        # api-recon/api-security are borderline but reference ARTEX image assumptions
        # If the body says "installed in the image" it's ARTEX-specific
        if "installed in the image" in haystack:
            if "image" not in found:
                found.append("image")
    return sorted(set(found))


def _is_available(skill: Skill, available_tools: set[str] | None) -> bool:
    if available_tools is None:
        return not skill.reference_only
    # if skill explicitly lists tools, they must all be available
    for tool in skill.tools:
        if tool not in available_tools:
            return False
    # allowed_tools like Bash(playwright-cli:*) implies external bash tooling
    if skill.allowed_tools:
        for at in skill.allowed_tools:
            # Candix tools are dotted names like http.request; Bash(*) is external
            if at not in available_tools:
                # if allowed_tools contains anything not in available, consider unavailable
                # But we don't want to be too strict; check if it mentions external binary
                if any(ext in at.lower() for ext in ("playwright", "bbot", "nuclei", "httpx", "katana", "ffuf", "npx", "npm")):
                    return False
    if skill.mcps:
        return False
    if skill.requires_external:
        return False
    return True


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
    allowed_tools = meta.get("allowed_tools") or []
    mcps = meta.get("mcps") or []
    if isinstance(tags, str):
        tags = [tags]
    if isinstance(tools, str):
        tools = [tools]
    if isinstance(allowed_tools, str):
        allowed_tools = [allowed_tools]
    if isinstance(mcps, str):
        mcps = [mcps]
    skill = Skill(
        name=name,
        description=str(meta["description"]).strip(),
        body=body.strip(),
        tags=[str(tag) for tag in tags],
        phase=str(meta.get("phase", "")),
        tools=[str(tool) for tool in tools],
        path=str(source),
        when_to_use=str(meta.get("when_to_use", "")),
        version=str(meta.get("version", "1")),
        allowed_tools=[str(t) for t in allowed_tools],
        mcps=[str(m) for m in mcps],
    )
    # detect external requirements for filtering
    skill.requires_external = _detect_external_requirements(skill)
    # Mark as reference-only if it needs external tooling or is not one of the originals
    # but declares external hints
    if skill.requires_external:
        skill.reference_only = True
    # Also mark known ARTEX-only skills as reference-only when they assume docker image
    if skill.name not in ORIGINAL_SKILLS and skill.requires_external:
        skill.reference_only = True
    # Special case: bbot-recon etc always reference-only even if hints not caught
    if skill.name in {"bbot-recon", "playwright-cli", "scopesentry", "rea", "edr-bypass-re", "patch-diff", "php2shell", "codeaudit", "api-recon", "api-security"}:
        # Only keep as available if it has no external hints and is in original? But these are not original, so mark reference
        if skill.name not in ORIGINAL_SKILLS:
            # check if body actually requires external
            if skill.requires_external or skill.allowed_tools or skill.mcps:
                skill.reference_only = True
    return skill


class SkillRegistry:
    """A directory of skills plus selection by goal text and phase."""

    def __init__(self, skills: Iterable[Skill] = (), *, errors: Iterable[str] = ()) -> None:
        self.skills: dict[str, Skill] = {skill.name: skill for skill in skills}
        self.errors: list[str] = list(errors)

    @classmethod
    def load(cls, directory: str | Path, *, available_tools: Iterable[str] | None = None) -> "SkillRegistry":
        root = Path(directory) if directory else Path("")
        skills: list[Skill] = []
        errors: list[str] = []
        # Resolve fallback locations when the requested directory doesn't exist
        # (e.g. pip-installed wheel where skills live inside candix/_skills)
        if not root.exists() or not root.is_dir():
            fallback_candidates: list[Path] = []
            # 1. explicit directory as-is failed, try candix/_skills next to this file
            try:
                candix_pkg = Path(__file__).parent
                fallback_candidates.append(candix_pkg / "_skills")
                fallback_candidates.append(candix_pkg.parent / "skills")
                # 2. importlib.resources for installed package
                try:
                    import importlib.resources as _res
                    for pkg in ("candix._skills", "skills"):
                        try:
                            p = Path(str(_res.files(pkg)))
                            if p.exists():
                                fallback_candidates.append(p)
                        except Exception:
                            continue
                except Exception:
                    pass
            except Exception:
                pass
            found = None
            for cand in fallback_candidates:
                if cand.exists() and cand.is_dir():
                    found = cand
                    break
            if found is not None:
                root = found
                errors.append(f"skills directory '{directory}' not found; using fallback '{root}'")
            else:
                return cls((), errors=[f"skills directory not found: {root}"])
        for path in sorted(root.rglob("SKILL.md")):
            try:
                skills.append(load_skill(path))
            except SkillError as error:
                errors.append(str(error))
        # Apply availability filtering for reference-only marking if requested
        if available_tools is not None:
            avail_set = set(available_tools)
            for skill in skills:
                if not _is_available(skill, avail_set):
                    skill.reference_only = True
        else:
            # auto-detect via default registry if available
            try:
                from candix.agent.toolset import default_registry
                avail_set = set(default_registry().names())
                for skill in skills:
                    if not _is_available(skill, avail_set):
                        skill.reference_only = True
            except Exception:
                pass
        return cls(skills, errors=errors)

    # ------------------------------------------------------------------
    def get(self, name: str) -> Skill | None:
        return self.skills.get(name)

    def names(self) -> list[str]:
        return sorted(self.skills)

    def available_names(self) -> list[str]:
        return sorted(name for name, skill in self.skills.items() if not skill.reference_only)

    def reference_names(self) -> list[str]:
        return sorted(name for name, skill in self.skills.items() if skill.reference_only)

    def select(self, text: str, *, phase: str = "", limit: int = 2, include_reference: bool = False) -> list[Skill]:
        """Rank skills by keyword overlap with the goal and phase.

        By default reference-only skills (those requiring external tooling) are
        excluded from selection so the model is not instructed to use tools that
        do not exist in the registry. Pass ``include_reference=True`` to allow
        them for documentation purposes.
        """

        terms = {token for token in re.findall(r"[a-z0-9]+", (text or "").lower()) if len(token) > 3}
        scored: list[tuple[float, Skill]] = []
        for skill in self.skills.values():
            if skill.reference_only and not include_reference:
                continue
            haystack = f"{skill.name} {skill.description} {' '.join(skill.tags)} {skill.when_to_use}".lower()
            overlap = len(terms & {token for token in re.findall(r"[a-z0-9]+", haystack) if len(token) > 3})
            score = overlap / max(1, len(terms)) if terms else 0.0
            if phase and skill.phase and skill.phase == phase:
                score += 0.25
            if score > 0:
                scored.append((score, skill))
        scored.sort(key=lambda item: (-item[0], item[1].name))
        return [skill for _score, skill in scored[:limit]]

    def render(self, names: Iterable[str] | None = None, *, max_chars: int = 6000, include_reference: bool = False) -> str:
        if names is not None:
            selected = [self.skills[name] for name in names if name in self.skills and (include_reference or not self.skills[name].reference_only)]
        else:
            selected = [s for s in self.skills.values() if include_reference or not s.reference_only]
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
            "available": self.available_names(),
            "reference_only": self.reference_names(),
            "errors": list(self.errors),
            "problems": self.validate(),
        }
