"""Report builder: turns a scan result into one or more serialized artifacts."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import time
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable

from candix.core.errors import CandixError
from candix.core.severity import Severity
from candix.report.csv_report import render_csv
from candix.report.badge import render as render_badge
from candix.report.export import tracker_csv
from candix.report.html import render_html
from candix.report.junit import render_junit
from candix.report.notebook import render_notebook
from candix.report.slides import render_slides
from candix.report.json_report import render_json, render_jsonl_findings, summary_json
from candix.report.markdown import render_markdown
from candix.report.model import ReportModel, select_min_severity
from candix.report.sarif import render_sarif


class ReportError(CandixError):
    """Raised when a report cannot be produced."""


@dataclass
class ReportArtifact:
    format: str
    path: Path
    size: int
    sha256: str
    media_type: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "format": self.format,
            "path": str(self.path),
            "filename": self.path.name,
            "size": self.size,
            "sha256": self.sha256,
            "media_type": self.media_type,
        }


@dataclass
class ReportBundle:
    model: ReportModel
    artifacts: list[ReportArtifact] = field(default_factory=list)
    manifest_path: Path | None = None
    archive_path: Path | None = None
    warnings: list[str] = field(default_factory=list)

    def get(self, fmt: str) -> ReportArtifact | None:
        for artifact in self.artifacts:
            if artifact.format == fmt:
                return artifact
        return None

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_id": self.model.scan_id,
            "title": self.model.title,
            "generated_at": self.model.generated_at,
            "digest": self.model.digest,
            "artifacts": [artifact.to_dict() for artifact in self.artifacts],
            "manifest": str(self.manifest_path) if self.manifest_path else None,
            "archive": str(self.archive_path) if self.archive_path else None,
            "warnings": list(self.warnings),
            "counts": dict(self.model.counts),
            "risk_score": self.model.risk_score,
        }


@dataclass(frozen=True)
class Renderer:
    name: str
    extension: str
    media_type: str
    render: Callable[[ReportModel], str]
    binary: bool = False


def _html(model: ReportModel) -> str:
    return render_html(model)


def _jsonl(model: ReportModel) -> str:
    return render_jsonl_findings(model)


def _summary(model: ReportModel) -> str:
    return summary_json(model)


def _junit(model: ReportModel) -> str:
    return render_junit(model)


def _notebook(model: ReportModel) -> str:
    return render_notebook(model)


def _slides(model: ReportModel) -> str:
    return render_slides(model)


def _tracker(model: ReportModel) -> str:
    return tracker_csv(model)


def _badge(model: ReportModel) -> str:
    return render_badge(model)


RENDERERS: dict[str, Renderer] = {
    "json": Renderer("json", "json", "application/json", render_json),
    "html": Renderer("html", "html", "text/html; charset=utf-8", _html),
    "markdown": Renderer("markdown", "md", "text/markdown; charset=utf-8", render_markdown),
    "md": Renderer("markdown", "md", "text/markdown; charset=utf-8", render_markdown),
    "sarif": Renderer("sarif", "sarif", "application/sarif+json", render_sarif),
    "csv": Renderer("csv", "csv", "text/csv; charset=utf-8", render_csv),
    "jsonl": Renderer("jsonl", "jsonl", "application/x-ndjson", _jsonl),
    "summary": Renderer("summary", "summary.json", "application/json", _summary),
    "junit": Renderer("junit", "junit.xml", "application/xml", _junit),
    "notebook": Renderer("notebook", "ipynb", "application/x-ipynb+json", _notebook),
    "slides": Renderer("slides", "slides.md", "text/markdown; charset=utf-8", _slides),
    "tracker": Renderer("tracker", "tracker.csv", "text/csv; charset=utf-8", _tracker),
    "badge": Renderer("badge", "badge.svg", "image/svg+xml", _badge),
}

FORMAT_ALIASES = {
    "htm": "html",
    "sarif.json": "sarif",
    "yaml": "json",
    "yml": "json",
    "txt": "markdown",
    "text": "markdown",
    "ndjson": "jsonl",
    "xml": "junit",
    "ipynb": "notebook",
    "deck": "slides",
    "csv.tracker": "tracker",
}

DEFAULT_FORMATS = ("html", "json", "markdown", "sarif")

MEDIA_TYPES = {renderer.name: renderer.media_type for renderer in RENDERERS.values()}


def normalize_format(value: str) -> str:
    name = value.strip().lower().lstrip(".")
    name = FORMAT_ALIASES.get(name, name)
    if name not in RENDERERS:
        raise ReportError(
            f"unknown report format '{value}' (available: {', '.join(sorted(_canonical_formats()))})"
        )
    return RENDERERS[name].name


def _canonical_formats() -> set[str]:
    return {renderer.name for renderer in RENDERERS.values()}


def parse_formats(values: str | Iterable[str] | None) -> list[str]:
    if values is None:
        chosen: Iterable[str] = DEFAULT_FORMATS
    elif isinstance(values, str):
        chosen = [part for part in values.replace(";", ",").split(",") if part.strip()]
    else:
        chosen = values
    formats: list[str] = []
    for value in chosen:
        name = normalize_format(str(value))
        if name not in formats:
            formats.append(name)
    if not formats:
        raise ReportError("no report formats selected")
    return formats


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        with os.fdopen(handle, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


class ReportBuilder:
    """Renders a :class:`ReportModel` into one or more files."""

    def __init__(self, model: ReportModel, *, include_evidence: bool = True) -> None:
        self.model = model
        self.include_evidence = include_evidence

    @classmethod
    def from_result(
        cls,
        result: Any,
        *,
        title: str | None = None,
        min_severity: str | Severity = Severity.INFO,
        include_evidence: bool = True,
    ) -> "ReportBuilder":
        model = ReportModel.from_result(
            result,
            title=title,
            min_severity=select_min_severity(min_severity),
        )
        return cls(model, include_evidence=include_evidence)

    def render(self, fmt: str) -> str:
        name = normalize_format(fmt)
        renderer = RENDERERS[name]
        try:
            return renderer.render(self.model)
        except ReportError:
            raise
        except Exception as exc:  # pragma: no cover - defensive
            raise ReportError(f"failed to render {name} report: {exc}") from exc

    def filename(self, fmt: str) -> str:
        name = normalize_format(fmt)
        renderer = RENDERERS[name]
        return f"candix-{self.model.scan_id}.{renderer.extension}"

    def write(
        self,
        outdir: str | Path,
        formats: str | Iterable[str] | None = None,
        *,
        prefix: str | None = None,
        manifest: bool = True,
        archive: bool = False,
    ) -> ReportBundle:
        directory = Path(outdir)
        try:
            directory.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise ReportError(f"cannot create report directory {directory}: {exc}") from exc
        bundle = ReportBundle(model=self.model)
        for fmt in parse_formats(formats):
            name = normalize_format(fmt)
            renderer = RENDERERS[name]
            stem = prefix or f"candix-{self.model.scan_id}"
            path = directory / f"{stem}.{renderer.extension}"
            payload = self.render(name)
            data = payload.encode("utf-8")
            try:
                _atomic_write(path, data)
            except OSError as exc:
                raise ReportError(f"cannot write {path}: {exc}") from exc
            bundle.artifacts.append(
                ReportArtifact(
                    format=name,
                    path=path,
                    size=len(data),
                    sha256=_sha256(data),
                    media_type=renderer.media_type,
                )
            )
        if manifest:
            bundle.manifest_path = self._write_manifest(directory, bundle, prefix=prefix)
        if archive:
            bundle.archive_path = self._write_archive(directory, bundle, prefix=prefix)
        return bundle

    def _write_manifest(self, directory: Path, bundle: ReportBundle, *, prefix: str | None) -> Path:
        stem = prefix or f"candix-{self.model.scan_id}"
        document = {
            "generator": {"name": "candix", "version": self.model.version},
            "scan_id": self.model.scan_id,
            "title": self.model.title,
            "generated_at": self.model.generated_at,
            "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "digest": self.model.digest,
            "profile": self.model.profile,
            "counts": dict(self.model.counts),
            "risk_score": self.model.risk_score,
            "evidence_records": self.model.evidence_count,
            "targets": list(self.model.targets),
            "artifacts": [artifact.to_dict() for artifact in bundle.artifacts],
            "warnings": list(self.model.warnings),
        }
        path = directory / f"{stem}.manifest.json"
        _atomic_write(path, json.dumps(document, indent=2, sort_keys=True).encode("utf-8"))
        return path

    def _write_archive(self, directory: Path, bundle: ReportBundle, *, prefix: str | None) -> Path:
        stem = prefix or f"candix-{self.model.scan_id}"
        path = directory / f"{stem}.zip"
        temporary = path.with_suffix(".zip.tmp")
        with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for artifact in bundle.artifacts:
                archive.write(artifact.path, arcname=artifact.path.name)
            if bundle.manifest_path:
                archive.write(bundle.manifest_path, arcname=bundle.manifest_path.name)
            archive.writestr(
                "README.txt",
                "Candix report bundle\n"
                f"scan: {self.model.scan_id}\n"
                f"findings: {self.model.counts.get('total', 0)}\n"
                "Every artifact is listed with its SHA-256 in the manifest.\n",
            )
        os.replace(temporary, path)
        return path


def build_report(
    result: Any,
    *,
    outdir: str | Path = "reports",
    formats: str | Iterable[str] | None = None,
    title: str | None = None,
    min_severity: str | Severity = Severity.INFO,
    include_evidence: bool = True,
    manifest: bool = True,
    archive: bool = False,
    prefix: str | None = None,
) -> ReportBundle:
    """Build a report bundle from a scan result (or an existing model)."""

    if isinstance(result, ReportModel):
        builder = ReportBuilder(result, include_evidence=include_evidence)
    else:
        builder = ReportBuilder.from_result(
            result,
            title=title,
            min_severity=min_severity,
            include_evidence=include_evidence,
        )
    return builder.write(outdir, formats, prefix=prefix, manifest=manifest, archive=archive)


def build_reports_in_memory(
    result: Any,
    formats: str | Iterable[str] | None = None,
    *,
    title: str | None = None,
    min_severity: str | Severity = Severity.INFO,
) -> dict[str, str]:
    builder = (
        ReportBuilder(result)
        if isinstance(result, ReportModel)
        else ReportBuilder.from_result(result, title=title, min_severity=min_severity)
    )
    return {fmt: builder.render(fmt) for fmt in parse_formats(formats)}


def verify_bundle(bundle: ReportBundle) -> list[str]:
    problems: list[str] = []
    for artifact in bundle.artifacts:
        try:
            data = artifact.path.read_bytes()
        except OSError as exc:
            problems.append(f"{artifact.format}: unreadable ({exc})")
            continue
        if _sha256(data) != artifact.sha256:
            problems.append(f"{artifact.format}: digest mismatch")
        if len(data) != artifact.size:
            problems.append(f"{artifact.format}: size mismatch")
    return problems


def describe_formats() -> list[dict[str, str]]:
    seen: dict[str, dict[str, str]] = {}
    for alias, renderer in RENDERERS.items():
        seen.setdefault(
            renderer.name,
            {"format": renderer.name, "extension": renderer.extension, "media_type": renderer.media_type},
        )
    return sorted(seen.values(), key=lambda item: item["format"])
