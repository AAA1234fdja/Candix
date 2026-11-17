"""Backup and editor artefacts next to live endpoints."""

from __future__ import annotations

from typing import Iterable

from candix.core.finding import Finding
from candix.core.severity import Confidence, Severity
from candix.detectors.base import BaseDetector, DetectorMeta, register_detector
from candix.net.url import join_url

_SUFFIXES = ("~", ".bak", ".old", ".orig", ".save", ".swp", ".swo", ".tmp", ".copy", ".1", ".zip", ".tar.gz")
_TECH_SUFFIXES = {
    "php": (".bak", ".old", ".swp", "~", ".save"),
    "asp": (".bak", ".old", "~"),
    "aspx": (".bak", ".old", "~"),
    "jsp": (".bak", ".old", "~"),
    "js": (".map", ".bak", "~"),
    "json": (".bak", "~"),
    "yml": (".bak", "~"),
    "yaml": (".bak", "~"),
    "env": (".bak", "~", ".old"),
}


@register_detector
class BackupExtensionDetector(BaseDetector):
    meta = DetectorMeta(
        id="backup",
        name="Backup and editor artefacts",
        category="backup",
        description="Requests common editor and backup suffixes for discovered dynamic endpoints and validates the content.",
        severity=Severity.HIGH,
        cwe=("CWE-530", "CWE-538"),
        owasp=("A05:2021 Security Misconfiguration",),
        intrusive=False,
        tags=("exposure", "files"),
        order=30,
        remediation_key="backup",
    )

    def run(self) -> Iterable[Finding]:
        seen: set[str] = set()
        for endpoint in self.endpoints(with_params=False):
            path = endpoint.url.split("?")[0]
            if path in seen or not _interesting(path):
                continue
            seen.add(path)
            finding = self._test(path)
            if finding is not None:
                yield self.emit(finding)

    def _test(self, path: str) -> Finding | None:
        extension = path.rsplit(".", 1)[-1].lower() if "." in path.rsplit("/", 1)[-1] else ""
        suffixes = _TECH_SUFFIXES.get(extension, _SUFFIXES[:6])
        for suffix in suffixes:
            url = path + suffix
            if self.ctx.scope is not None and not self.ctx.scope.matches(url):
                continue
            try:
                response = self.http.get(url, tag="backup")
            except Exception:
                continue
            if self.missing(response) or response.status != 200:
                continue
            text = response.text
            lowered = text.lower()
            if "<html" in lowered[:200] and ("not found" in lowered or "404" in lowered[:400]):
                continue
            if len(response.content) < 32:
                continue
            markers = [marker for marker in ("<?php", "password", "db_", "secret", "define(", "import ", "function ") if marker in lowered]
            if not markers:
                continue
            return self.build_finding(
                title="Backup copy of a live file is downloadable",
                severity=Severity.HIGH,
                url=url,
                method="GET",
                description=(
                    f"{url} returns {len(response.content)} bytes of what appears to be source or configuration "
                    f"(markers: {', '.join(markers[:4])})."
                ),
                impact=(
                    "Backup copies bypass server-side execution and expose source, comments and credentials "
                    "that the live endpoint would otherwise hide."
                ),
                payload=suffix,
                confidence=Confidence.CONFIRMED,
                cwe=("CWE-530",),
                tags=("exposure", "backup"),
                evidence=[self.capture(response, summary="Backup artefact served with source content")],
                metadata={"suffix": suffix, "markers": markers, "size": len(response.content)},
            )
        return None


def _interesting(path: str) -> bool:
    last = path.rsplit("/", 1)[-1]
    if not last or last.endswith((".css", ".png", ".jpg", ".svg", ".woff", ".ico")):
        return False
    return "." in last or last in {"index", "config", "settings", "database", "app"}
