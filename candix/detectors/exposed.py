"""Exposed sensitive files, backups, VCS metadata and directory listings."""

from __future__ import annotations

from typing import Iterable

from candix.analysis.entropy import scan_for_secrets
from candix.catalog.wordlists import file_wordlist
from candix.core.finding import Finding
from candix.core.severity import Confidence, Severity
from candix.detectors.base import BaseDetector, DetectorMeta, register_detector
from candix.net.http import Response
from candix.net.url import join_url

_HIGH_VALUE = {
    ".env": "environment file with credentials",
    ".git/config": "git repository metadata",
    ".git/HEAD": "git repository metadata",
    ".svn/entries": "Subversion metadata",
    ".svn/wc.db": "Subversion database",
    ".hg/requires": "Mercurial metadata",
    ".DS_Store": "macOS file listing",
    "backup.zip": "application backup archive",
    "backup.tar.gz": "application backup archive",
    "backup.sql": "database dump",
    "db.sql": "database dump",
    "dump.sql": "database dump",
    "id_rsa": "private key",
    "credentials.json": "credential file",
    "service-account.json": "cloud service account key",
    "wp-config.php.bak": "WordPress configuration backup",
    "config.php.bak": "application configuration backup",
    "phpinfo.php": "PHP configuration disclosure",
    "server-status": "server status page",
    "actuator/env": "Spring Boot environment endpoint",
    "heapdump": "JVM heap dump",
    "threaddump": "JVM thread dump",
}

_DEBUG_PATHS = ("/server-status", "/server-info", "/phpinfo.php", "/actuator", "/actuator/env", "/heapdump", "/threaddump", "/console", "/debug")


@register_detector
class ExposedFilesDetector(BaseDetector):
    meta = DetectorMeta(
        id="exposed",
        name="Exposed sensitive files and debug endpoints",
        category="dirlisting",
        description="Requests known backup, VCS, environment and debug paths and validates their contents.",
        severity=Severity.HIGH,
        cwe=("CWE-538", "CWE-552"),
        owasp=("A05:2021 Security Misconfiguration",),
        intrusive=False,
        tags=("exposure", "files"),
        order=25,
        remediation_key="backup",
    )

    def run(self) -> Iterable[Finding]:
        for target in self.ctx.targets:
            yield from self._list_directory(target.base_url)
            yield from self._probe_files(target.base_url)

    # ------------------------------------------------------------------
    def _list_directory(self, base_url: str) -> Iterable[Finding]:
        for path in ("/uploads/", "/files/", "/static/", "/assets/", "/backup/", "/logs/"):
            url = join_url(base_url, path).render()
            if self.ctx.scope is not None and not self.ctx.scope.matches(url):
                continue
            try:
                response = self.http.get(url, tag="dirlist")
            except Exception:
                continue
            if self.missing(response) or response.status != 200:
                continue
            lowered = response.text.lower()
            if "index of /" not in lowered and "<title>directory listing" not in lowered:
                continue
            yield self.emit(
                self.build_finding(
                    title="Directory listing enabled",
                    severity=Severity.LOW,
                    url=url,
                    description="The server returns an auto-generated directory index, exposing file names and structure.",
                    impact="Attackers can enumerate backups, source files and administrative scripts.",
                    confidence=Confidence.CONFIRMED,
                    cwe=("CWE-548",),
                    tags=("dirlisting",),
                    evidence=[self.capture(response, summary="Directory index returned")],
                )
            )

    def _probe_files(self, base_url: str) -> Iterable[Finding]:
        candidates = list(dict.fromkeys(list(file_wordlist()) + list(_DEBUG_PATHS)))
        for path in candidates:
            url = join_url(base_url, path).render()
            if self.ctx.scope is not None and not self.ctx.scope.matches(url):
                continue
            try:
                response = self.http.get(url, tag="exposed")
            except Exception:
                continue
            if self.missing(response) or response.status != 200:
                continue
            verdict = self._verify(path, response)
            if verdict is None:
                continue
            kind, severity, detail, extra = verdict
            yield self.emit(
                self.build_finding(
                    title=f"Exposed {_HIGH_VALUE.get(path.lstrip('/'), kind)}",
                    severity=severity,
                    url=url,
                    description=(
                        f"The path {path} is publicly readable and exposes {kind}. {detail}"
                    ),
                    impact=_impact_for(kind),
                    confidence=Confidence.CONFIRMED,
                    cwe=("CWE-538", "CWE-200"),
                    tags=("exposure", kind.replace(" ", "-")),
                    evidence=[
                        self.capture(
                            response,
                            summary=f"Sensitive content retrieved from {path}",
                            data={"path": path, **extra},
                        )
                    ],
                    metadata={"path": path, "kind": kind, **extra},
                )
            )

    def _verify(self, path: str, response: Response) -> tuple[str, Severity, str, dict] | None:
        normalized = path.lstrip("/")
        text = response.text
        lowered = text.lower()
        content_type = response.content_type
        if normalized in {".env", ".env.local", ".env.production"} or "/.env" in path:
            if "=" in text and any(key in text for key in ("_KEY", "_SECRET", "_PASSWORD", "APP_ENV", "DB_")):
                secrets = scan_for_secrets(text)
                return (
                    "environment file",
                    Severity.HIGH,
                    f"Keys observed: {', '.join(sorted({match.kind for match in secrets})) or 'environment variables'}.",
                    {"secrets": [match.to_dict() for match in secrets]},
                )
        if normalized.startswith(".git/") or normalized.startswith(".svn/") or normalized.startswith(".hg/"):
            if "[core]" in lowered or "repositoryformatversion" in lowered or "dir" in lowered:
                return ("version control metadata", Severity.HIGH, "Repository layout and remote URLs may be recoverable.", {})
        if normalized in {"server-status", "server-info"} and ("server version" in lowered or "total accesses" in lowered):
            return ("server status page", Severity.MEDIUM, "Internal request statistics and server version are public.", {})
        if "phpinfo" in normalized and "php version" in lowered:
            return ("PHP configuration", Severity.MEDIUM, "phpinfo() discloses configuration, paths and loaded modules.", {})
        if "actuator" in normalized and ("\"status\"" in lowered or "\"property\"" in lowered or "build" in lowered):
            return ("Spring Boot actuator endpoint", Severity.HIGH, "Actuator endpoints expose configuration, environment and sometimes credentials.", {})
        if normalized.endswith((".zip", ".tar.gz", ".tgz", ".tar", ".sql", ".dump", ".bak", ".old", "~")):
            if response.size > 200 and ("pk" in lowered[:4] or "create table" in lowered or "insert into" in lowered):
                return ("backup or dump archive", Severity.HIGH, "The archive or dump is downloadable and may contain source or data.", {})
            if response.size > 2000 and content_type in {"application/zip", "application/octet-stream"}:
                return ("backup archive", Severity.MEDIUM, "A downloadable archive is exposed.", {})
        if normalized in {"id_rsa", "id_dsa", "id_ecdsa"} and "private key" in lowered:
            return ("private key", Severity.CRITICAL, "A private key is publicly readable and must be rotated immediately.", {})
        if normalized.endswith("service-account.json") and "private_key" in lowered:
            return ("cloud service account key", Severity.CRITICAL, "Cloud credentials are exposed and must be revoked.", {})
        if normalized in {".ds_store"} and text.startswith("\x00\x00\x00\x01Bud1"):
            return ("macOS metadata", Severity.LOW, "The file leaks directory and file names.", {})
        return None


def _impact_for(kind: str) -> str:
    if "credential" in kind or "key" in kind or "environment" in kind:
        return "Direct access to credentials or secrets can lead to full compromise of the application or cloud account."
    if "backup" in kind or "dump" in kind or "repository" in kind:
        return "Source code and data recovery enables further exploitation, including credential discovery."
    return "Internal implementation details are exposed, reducing the effort required for further attacks."
