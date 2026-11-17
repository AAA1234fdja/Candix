"""Secrets and API keys exposed to clients."""

from __future__ import annotations

import re
from typing import Iterable

from candix.analysis.entropy import scan_for_secrets
from candix.analysis.html import HTMLDocument
from candix.core.finding import Finding
from candix.core.severity import Confidence, Severity
from candix.detectors.base import BaseDetector, DetectorMeta, register_detector

_JS_SECRET_RE = re.compile(
    r"(?i)(?:api[_-]?key|apikey|access[_-]?token|secret[_-]?key|auth[_-]?token|client[_-]?secret)\s*[:=]\s*['\"]([A-Za-z0-9_\-./+]{16,})['\"]"
)


@register_detector
class ApiKeyExposureDetector(BaseDetector):
    meta = DetectorMeta(
        id="apikey",
        name="Exposed API keys and secrets",
        category="apikey",
        description="Scans delivered HTML, JavaScript bundles and responses for credential patterns and high-entropy assignments.",
        severity=Severity.HIGH,
        cwe=("CWE-798", "CWE-200"),
        owasp=("A02:2021 Cryptographic Failures",),
        intrusive=False,
        tags=("secrets", "client-side"),
        order=160,
        remediation_key="apikey",
    )

    def run(self) -> Iterable[Finding]:
        seen: set[str] = set()
        for target in self.ctx.targets:
            try:
                page = self.http.get(target.url, tag="apikey")
            except Exception:
                continue
            document = HTMLDocument(page.text, target.url)
            assets = [target.url, *document.script_sources()[:6]]
            for asset in assets:
                if asset in seen or (self.ctx.scope is not None and not self.ctx.scope.matches(asset)):
                    continue
                seen.add(asset)
                try:
                    response = page if asset == target.url else self.http.get(asset, tag="apikey-js")
                except Exception:
                    continue
                if self.missing(response) or response.size > 2_000_000:
                    continue
                secret_matches = scan_for_secrets(response.text)
                pattern_matches = [
                    match.group(1) for match in _JS_SECRET_RE.finditer(response.text)
                ]
                if not secret_matches and not pattern_matches:
                    continue
                severity = Severity.HIGH if secret_matches else Severity.MEDIUM
                previews = [match.to_dict() for match in secret_matches[:10]]
                for value in pattern_matches[:10]:
                    previews.append({"kind": "assigned-secret", "preview": f"{value[:4]}...{value[-4:]}", "severity": "medium"})
                yield self.emit(
                    self.build_finding(
                        title="API keys or secrets exposed in client-delivered content",
                        severity=severity,
                        url=asset,
                        location="body",
                        description=(
                            f"Client-delivered content contains {len(previews)} credential-like value(s), "
                            "including well-known token formats or hard-coded assignments."
                        ),
                        impact=(
                            "Anyone who can load the page can extract the key and use the associated service, "
                            "potentially incurring cost or accessing data."
                        ),
                        confidence=Confidence.CONFIRMED,
                        cwe=("CWE-798",),
                        tags=("secrets", "apikey"),
                        evidence=[
                            self.capture(
                                response,
                                summary="Credential material found in response",
                                kind="artifact",
                                data={"matches": previews},
                            )
                        ],
                        metadata={"matches": previews, "asset": asset},
                    )
                )
                break
