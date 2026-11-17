"""Scan checkpoints and resume planning."""

from __future__ import annotations

import json
import os
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from candix import VERSION
from candix.core.clock import isoformat
from candix.core.ids import sha256

SCHEMA = "candix.checkpoint/1"


@dataclass
class Checkpoint:
    scan_id: str
    phase: str
    status: str = "running"
    created_at: str = field(default_factory=isoformat)
    updated_at: str = field(default_factory=isoformat)
    targets: list[str] = field(default_factory=list)
    profile: str = "standard"
    config: dict[str, Any] = field(default_factory=dict)
    endpoints: list[dict[str, Any]] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    completed_detectors: list[str] = field(default_factory=list)
    pending_detectors: list[str] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)
    schema: str = SCHEMA
    version: str = VERSION

    def touch(self) -> None:
        self.updated_at = isoformat()

    @property
    def finished(self) -> bool:
        return self.status in {"complete", "failed", "aborted"}

    @property
    def age(self) -> float:
        return time.time() - _parse_time(self.updated_at)

    def digest(self) -> str:
        payload = json.dumps(
            {
                "scan_id": self.scan_id,
                "phase": self.phase,
                "findings": [item.get("id") for item in self.findings],
                "endpoints": [item.get("id") for item in self.endpoints],
            },
            sort_keys=True,
        )
        return sha256(payload)[:32]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "version": self.version,
            "scan_id": self.scan_id,
            "phase": self.phase,
            "status": self.status,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "targets": list(self.targets),
            "profile": self.profile,
            "config": dict(self.config),
            "endpoints": list(self.endpoints),
            "findings": list(self.findings),
            "completed_detectors": list(self.completed_detectors),
            "pending_detectors": list(self.pending_detectors),
            "stats": dict(self.stats),
            "notes": list(self.notes),
            "digest": self.digest(),
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "Checkpoint":
        if payload.get("schema") not in (SCHEMA, None):
            raise ValueError(f"unsupported checkpoint schema: {payload.get('schema')}")
        return cls(
            scan_id=str(payload.get("scan_id", "")),
            phase=str(payload.get("phase", "preflight")),
            status=str(payload.get("status", "running")),
            created_at=str(payload.get("created_at", isoformat())),
            updated_at=str(payload.get("updated_at", isoformat())),
            targets=[str(item) for item in payload.get("targets", []) or []],
            profile=str(payload.get("profile", "standard")),
            config=dict(payload.get("config") or {}),
            endpoints=list(payload.get("endpoints") or []),
            findings=list(payload.get("findings") or []),
            completed_detectors=[str(item) for item in payload.get("completed_detectors", []) or []],
            pending_detectors=[str(item) for item in payload.get("pending_detectors", []) or []],
            stats=dict(payload.get("stats") or {}),
            notes=[str(item) for item in payload.get("notes", []) or []],
            schema=str(payload.get("schema", SCHEMA)),
            version=str(payload.get("version", VERSION)),
        )


def _parse_time(value: str) -> float:
    try:
        return time.mktime(time.strptime(value[:19], "%Y-%m-%dT%H:%M:%S"))
    except (ValueError, TypeError):
        return 0.0


class CheckpointStore:
    """One JSON file per scan, written atomically."""

    def __init__(self, directory: str | Path = "checkpoints") -> None:
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)

    def path_for(self, scan_id: str) -> Path:
        safe = "".join(char if char.isalnum() or char in "-_." else "-" for char in scan_id)
        return self.directory / f"{safe}.json"

    def save(self, checkpoint: Checkpoint) -> Path:
        checkpoint.touch()
        path = self.path_for(checkpoint.scan_id)
        handle, temporary = tempfile.mkstemp(prefix=".ckpt-", dir=str(self.directory))
        try:
            with os.fdopen(handle, "w", encoding="utf-8") as stream:
                json.dump(checkpoint.to_dict(), stream, indent=2, sort_keys=True)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
        except BaseException:
            try:
                os.unlink(temporary)
            except OSError:
                pass
            raise
        return path

    def load(self, scan_id: str) -> Checkpoint:
        path = self.path_for(scan_id)
        if not path.exists():
            raise FileNotFoundError(f"no checkpoint for scan {scan_id}")
        payload = json.loads(path.read_text(encoding="utf-8"))
        expected = payload.get("digest")
        checkpoint = Checkpoint.from_dict(payload)
        if expected and checkpoint.digest() != expected:
            raise ValueError("checkpoint digest mismatch: the file was modified")
        return checkpoint

    def latest(self) -> Checkpoint | None:
        files = sorted(self.directory.glob("*.json"), key=lambda path: path.stat().st_mtime, reverse=True)
        for path in files:
            try:
                return Checkpoint.from_dict(json.loads(path.read_text(encoding="utf-8")))
            except (json.JSONDecodeError, ValueError):
                continue
        return None

    def list(self) -> list[dict[str, Any]]:
        entries: list[dict[str, Any]] = []
        for path in sorted(self.directory.glob("*.json")):
            try:
                checkpoint = Checkpoint.from_dict(json.loads(path.read_text(encoding="utf-8")))
            except (json.JSONDecodeError, ValueError):
                continue
            entries.append(
                {
                    "scan_id": checkpoint.scan_id,
                    "phase": checkpoint.phase,
                    "status": checkpoint.status,
                    "updated_at": checkpoint.updated_at,
                    "findings": len(checkpoint.findings),
                    "path": str(path),
                }
            )
        return entries

    def prune(self, *, keep: int = 20, completed: bool = True) -> int:
        candidates: list[tuple[float, Path]] = []
        for path in self.directory.glob("*.json"):
            try:
                checkpoint = Checkpoint.from_dict(json.loads(path.read_text(encoding="utf-8")))
            except (json.JSONDecodeError, ValueError):
                continue
            if completed and not checkpoint.finished:
                continue
            candidates.append((path.stat().st_mtime, path))
        candidates.sort(reverse=True)
        removed = 0
        for _mtime, path in candidates[keep:]:
            try:
                path.unlink()
                removed += 1
            except OSError:
                continue
        return removed


@dataclass
class ResumePlan:
    checkpoint: Checkpoint
    resume_phase: str
    detectors: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    usable: bool = True
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_id": self.checkpoint.scan_id,
            "resume_phase": self.resume_phase,
            "detectors": list(self.detectors),
            "skipped": list(self.skipped),
            "usable": self.usable,
            "reason": self.reason,
            "age_seconds": round(self.checkpoint.age, 1),
            "findings": len(self.checkpoint.findings),
        }

    def describe(self) -> str:
        if not self.usable:
            return f"cannot resume {self.checkpoint.scan_id}: {self.reason}"
        return (
            f"resume {self.checkpoint.scan_id} at {self.resume_phase} "
            f"({len(self.detectors)} detectors pending, {len(self.checkpoint.findings)} findings kept)"
        )


def plan_resume(checkpoint: Checkpoint, *, max_age_hours: float = 72.0, all_detectors: Iterable[str] = ()) -> ResumePlan:
    if checkpoint.finished:
        return ResumePlan(checkpoint=checkpoint, resume_phase="complete", usable=False, reason="checkpoint belongs to a finished scan")
    if max_age_hours and checkpoint.age > max_age_hours * 3600:
        return ResumePlan(checkpoint=checkpoint, resume_phase=checkpoint.phase, usable=False, reason="checkpoint is stale")
    if not checkpoint.targets:
        return ResumePlan(checkpoint=checkpoint, resume_phase=checkpoint.phase, usable=False, reason="checkpoint has no targets")
    known = list(all_detectors) or list(checkpoint.pending_detectors)
    completed = set(checkpoint.completed_detectors)
    detectors = [item for item in known if item not in completed]
    skipped = [item for item in completed if item not in known]
    phase = "detect" if checkpoint.phase in {"preflight", "recon", "detect"} else checkpoint.phase
    return ResumePlan(checkpoint=checkpoint, resume_phase=phase, detectors=detectors, skipped=skipped)


def checkpoint_from_result(result: Any) -> Checkpoint:
    context = getattr(result, "context", None)
    if context is None:
        raise ValueError("result has no context")
    return Checkpoint(
        scan_id=context.id,
        phase=str(getattr(context, "phase", "detect")),
        status="complete",
        targets=[target.url for target in context.targets],
        profile=str(context.config.get("profile")),
        endpoints=[endpoint.to_dict() for endpoint in context.endpoints][:5000],
        findings=[finding.to_dict(include_evidence=False) for finding in context.findings.sorted()],
        stats=dict(context.stats),
    )
