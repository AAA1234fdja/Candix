"""Content discovery with judgement: fewer requests, fewer false positives."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from candix.agent.web import Fetch, fetch, looks_like_soft_404, probe
from candix.catalog.wordlists import DOTFILES, directory_wordlist, file_wordlist
from candix.core.log import get_logger

log = get_logger("candix.agent.probe")

SENSITIVE_MARKERS = {
    ".git": ("git repository metadata", "high"),
    ".env": ("environment file", "high"),
    ".svn": ("subversion metadata", "medium"),
    ".hg": ("mercurial metadata", "medium"),
    "backup": ("backup archive", "medium"),
    ".bak": ("editor backup file", "medium"),
    ".old": ("stale copy of a live file", "low"),
    "dump.sql": ("database dump", "critical"),
    "db.sql": ("database dump", "critical"),
    "server-status": ("server status page", "medium"),
    "actuator": ("management endpoint", "medium"),
    "swagger": ("API documentation", "low"),
    "openapi": ("API documentation", "low"),
    "phpinfo": ("phpinfo page", "high"),
    ".ds_store": ("directory listing artefact", "low"),
    "web.config": ("server configuration", "high"),
    "id_rsa": ("private key", "critical"),
    "credentials": ("credential file", "critical"),
}

INTERESTING_METHODS = ("OPTIONS", "TRACE", "PUT", "DELETE")


@dataclass
class Discovery:
    path: str
    url: str
    status: int
    length: int
    marker: str = ""
    severity: str = ""
    title: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "url": self.url,
            "status": self.status,
            "length": self.length,
            "marker": self.marker,
            "severity": self.severity,
            "title": self.title,
        }


def classify(path: str) -> tuple[str, str]:
    lowered = path.lower()
    for marker, (description, severity) in SENSITIVE_MARKERS.items():
        if marker in lowered:
            return description, severity
    return "", ""


def methods(base: str, ctx: Any) -> dict[str, Any]:
    """Ask the server what it accepts, then try the surprising ones."""

    options = fetch(ctx, base, method="OPTIONS")
    allow = options.headers.get("allow", "")
    advertised = [item.strip().upper() for item in allow.split(",") if item.strip()]
    probed: dict[str, int] = {}
    for method in INTERESTING_METHODS:
        if method == "OPTIONS":
            probed[method] = options.status
            continue
        record = fetch(ctx, base, method=method, max_bytes=4000)
        probed[method] = record.status
    risky = [method for method in ("TRACE", "PUT", "DELETE") if probed.get(method, 0) in (200, 204, 405)]
    return {"allow": advertised, "probed": probed, "risky": risky}


def run(ctx: Any, base: str, *, include_extensions: bool = True, limit: int = 80) -> list[Discovery]:
    reference = fetch(ctx, base)
    candidates: list[str] = list(DOTFILES)
    for path in directory_wordlist(include_extensions=include_extensions):
        candidates.append(path if path.startswith("/") else "/" + path)
    for path in file_wordlist():
        candidates.append(path if path.startswith("/") else "/" + path)
    seen: set[str] = set()
    ordered: list[str] = []
    for path in candidates:
        if path in seen:
            continue
        seen.add(path)
        ordered.append(path)

    rows: list[Discovery] = []
    for row in probe(ctx, base, ordered, reference=reference, limit=limit):
        if looks_like_soft_404(reference, reference) and row["status"] == 200 and row["length"] == reference.length:
            continue
        marker, severity = classify(row["path"])
        rows.append(
            Discovery(
                path=row["path"],
                url=row["url"],
                status=int(row["status"]),
                length=int(row["length"]),
                marker=marker,
                severity=severity,
                title=row.get("title", ""),
            )
        )
    return rows


def findings_for(rows: list[Discovery]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for row in rows:
        if not row.marker:
            continue
        findings.append(
            {
                "title": f"Exposed {row.marker} at {row.path}",
                "severity": row.severity or "low",
                "category": "exposure",
                "detector": "agent.web_probe",
                "url": row.url,
                "description": f"{row.path} returns {row.status} with {row.length} bytes and looks like a {row.marker}.",
                "impact": "Published files can disclose configuration, credentials or source code.",
                "remediation": "Remove the file from the document root and block the path at the edge.",
                "confidence": "observed",
                "verified": True,
                "parameter": row.path,
                "tags": ["discovery", "exposure"],
            }
        )
    return findings


def tool_web_probe(ctx: Any, arguments: dict[str, Any]) -> dict[str, Any]:
    base = str(arguments.get("url", "")).rstrip("/")
    if not base:
        targets = list(ctx.state.get("targets") or [])
        base = targets[0] if targets else ""
    if not base:
        raise ValueError("web.probe needs a base URL")
    rows = run(
        ctx,
        base,
        include_extensions=bool(arguments.get("extensions", True)),
        limit=int(arguments.get("limit", 80)),
    )
    method_info = methods(base, ctx)
    assets = ctx.state.get("assets")
    if assets is not None:
        for row in rows:
            assets.add_endpoint("GET", row.url, status=row.status, source="probe")
    interesting = [row for row in rows if row.marker]
    return {
        "summary": f"{len(rows)} live path(s), {len(interesting)} sensitive, methods {method_info['probed']}",
        "paths": [row.to_dict() for row in rows[:60]],
        "methods": method_info,
        "findings": findings_for(rows),
    }
