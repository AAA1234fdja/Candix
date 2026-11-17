"""Package a finished run into something a client can be handed."""

from __future__ import annotations

import hashlib
import json
import os
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

MANIFEST_NAME = "manifest.json"
BUNDLE_README = "README.md"

DEFAULT_INCLUDE = (
    "*.md",
    "*.json",
    "*.sarif",
    "*.html",
    "*.xml",
    "*.prom",
    "*.jsonl",
)


@dataclass
class BundleEntry:
    path: str
    size: int
    sha256: str
    kind: str = "artifact"

    def to_dict(self) -> dict[str, Any]:
        return {"path": self.path, "size": self.size, "sha256": self.sha256, "kind": self.kind}


@dataclass
class Bundle:
    root: Path
    entries: list[BundleEntry] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def size(self) -> int:
        return sum(entry.size for entry in self.entries)

    def find(self, suffix: str) -> list[BundleEntry]:
        return [entry for entry in self.entries if entry.path.endswith(suffix)]

    def to_dict(self) -> dict[str, Any]:
        return {"root": str(self.root), "size": self.size, "count": len(self.entries), "entries": [entry.to_dict() for entry in self.entries], "metadata": self.metadata}


def digest(path: Path, *, chunk: int = 1 << 20) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(chunk), b""):
            hasher.update(block)
    return hasher.hexdigest()


def classify(path: Path) -> str:
    if path.suffix in {".md"}:
        return "narrative"
    if path.suffix in {".sarif"}:
        return "sarif"
    if path.suffix in {".html"}:
        return "html"
    if path.suffix in {".jsonl"}:
        return "log"
    if path.suffix in {".json"}:
        if "evidence" in path.name:
            return "evidence"
        if "manifest" in path.name:
            return "manifest"
        return "data"
    if path.suffix in {".prom"}:
        return "metrics"
    return "artifact"


def collect(root: str | Path, *, patterns: Iterable[str] = DEFAULT_INCLUDE, exclude: Iterable[str] = ("manifest.json",)) -> Bundle:
    base = Path(root)
    if not base.is_dir():
        raise FileNotFoundError(f"not a directory: {base}")
    skip = set(exclude)
    entries: list[BundleEntry] = []
    for pattern in patterns:
        for path in sorted(base.rglob(pattern)):
            if not path.is_file() or path.name in skip:
                continue
            relative = str(path.relative_to(base))
            if any(part == "__pycache__" for part in path.parts):
                continue
            entries.append(BundleEntry(path=relative, size=path.stat().st_size, sha256=digest(path), kind=classify(path)))
    unique = {entry.path: entry for entry in entries}
    return Bundle(root=base, entries=sorted(unique.values(), key=lambda item: item.path))


def from_session(session_file: str | Path) -> dict[str, Any]:
    path = Path(session_file)
    if not path.is_file():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}
    budget = payload.get("budget") or {}
    findings = payload.get("findings") or []
    return {
        "run_id": payload.get("run_id", ""),
        "goal": payload.get("goal", ""),
        "targets": payload.get("targets", []),
        "findings": len(findings),
        "severity": (payload.get("scorecard") or {}).get("grade", ""),
        "turns": budget.get("turns", 0),
        "tokens": budget.get("tokens", 0),
        "started_at": payload.get("started_at", ""),
    }


def summarise(bundle: Bundle) -> dict[str, Any]:
    kinds: dict[str, int] = {}
    for entry in bundle.entries:
        kinds[entry.kind] = kinds.get(entry.kind, 0) + 1
    return {"files": len(bundle.entries), "bytes": bundle.size, "by_kind": kinds}


def render_readme(bundle: Bundle) -> str:
    lines = ["# Candix run bundle", ""]
    meta = bundle.metadata
    if meta:
        lines.append(f"- run: `{meta.get('run_id', 'unknown')}`")
        lines.append(f"- goal: {meta.get('goal', 'n/a')}")
        lines.append(f"- targets: {', '.join(meta.get('targets', [])) or 'n/a'}")
        lines.append(f"- findings: {meta.get('findings', 0)}")
        lines.append("")
    summary = summarise(bundle)
    lines.append(f"{summary['files']} file(s), {summary['bytes']} byte(s).")
    lines.append("")
    lines.append("| file | kind | bytes | sha256 |")
    lines.append("| --- | --- | --- | --- |")
    for entry in bundle.entries:
        lines.append(f"| `{entry.path}` | {entry.kind} | {entry.size} | `{entry.sha256[:16]}` |")
    lines.append("")
    lines.append("Verify with `candix bundle --verify <dir>` before sending.")
    return "\n".join(lines) + "\n"


def write_manifest(bundle: Bundle, *, extra: dict[str, Any] | None = None) -> Path:
    payload = {
        "version": 1,
        "root": str(bundle.root),
        "metadata": {**bundle.metadata, **(extra or {})},
        "summary": summarise(bundle),
        "entries": [entry.to_dict() for entry in bundle.entries],
    }
    path = bundle.root / MANIFEST_NAME
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return path


def write_readme(bundle: Bundle) -> Path:
    path = bundle.root / BUNDLE_README
    path.write_text(render_readme(bundle), encoding="utf-8")
    return path


def write_zip(bundle: Bundle, destination: str | Path) -> Path:
    target = Path(destination)
    target.parent.mkdir(parents=True, exist_ok=True)
    written = set()
    with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for entry in bundle.entries:
            if entry.path in written:
                continue
            archive.write(bundle.root / entry.path, arcname=entry.path)
            written.add(entry.path)
        for name in (MANIFEST_NAME, BUNDLE_README):
            path = bundle.root / name
            if path.is_file() and name not in written:
                archive.write(path, arcname=name)
                written.add(name)
    return target


def verify(root: str | Path) -> tuple[bool, list[str]]:
    base = Path(root)
    manifest = base / MANIFEST_NAME
    if not manifest.is_file():
        return False, [f"{MANIFEST_NAME} missing"]
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    problems: list[str] = []
    for entry in payload.get("entries", []):
        path = base / entry["path"]
        if not path.is_file():
            problems.append(f"missing: {entry['path']}")
            continue
        actual = digest(path)
        if actual != entry["sha256"]:
            problems.append(f"changed: {entry['path']}")
        if path.stat().st_size != entry.get("size"):
            problems.append(f"size changed: {entry['path']}")
    return (not problems), problems


def build(root: str | Path, *, destination: str | Path | None = None, metadata: dict[str, Any] | None = None) -> Bundle:
    bundle = collect(root)
    session = next((path for path in bundle.root.rglob("session.json")), None)
    if session is not None:
        bundle.metadata.update(from_session(session))
    bundle.metadata.update(metadata or {})
    write_manifest(bundle)
    write_readme(bundle)
    if destination:
        write_zip(bundle, destination)
    return bundle


def prune(root: str | Path, *, keep_kinds: Iterable[str] = ("narrative", "data", "evidence", "sarif", "html")) -> list[str]:
    """Delete artifacts outside the kinds a client needs; returns what went."""

    base = Path(root)
    keep = set(keep_kinds)
    removed: list[str] = []
    for path in base.rglob("*"):
        if not path.is_file():
            continue
        if classify(path) in keep or path.name in {MANIFEST_NAME, BUNDLE_README}:
            continue
        removed.append(str(path.relative_to(base)))
        try:
            os.remove(path)
        except OSError:
            continue
    return removed


def inventory(root: str | Path) -> dict[str, int]:
    counts: dict[str, int] = {}
    for path in Path(root).rglob("*"):
        if path.is_file():
            counts[classify(path)] = counts.get(classify(path), 0) + 1
    return counts


def ensure_readable(bundle: Bundle) -> list[str]:
    """Cheap sanity check before a bundle goes to a client."""

    problems: list[str] = []
    narrative = bundle.find(".md")
    if not narrative:
        problems.append("no markdown report in the bundle")
    if not bundle.find(".json"):
        problems.append("no machine-readable report in the bundle")
    if bundle.size == 0:
        problems.append("bundle is empty")
    return problems


def stamp(bundle: Bundle, *, version: str = "") -> dict[str, Any]:
    return {
        "files": len(bundle.entries),
        "bytes": bundle.size,
        "kinds": sorted({entry.kind for entry in bundle.entries}),
        "candix": version,
    }
