"""JavaScript source maps that expose original source code."""

from __future__ import annotations

import re
from typing import Iterable

from candix.core.finding import Finding
from candix.core.severity import Confidence, Severity
from candix.detectors.base import BaseDetector, DetectorMeta, register_detector
from candix.net.url import join_url

_SCRIPT_RE = re.compile(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', re.IGNORECASE)


@register_detector
class SourceMapDetector(BaseDetector):
    meta = DetectorMeta(
        id="sourcemap",
        name="JavaScript source maps exposed",
        category="sourcemap",
        description="Finds script bundles on the landing page and checks whether their .map files are downloadable.",
        severity=Severity.MEDIUM,
        cwe=("CWE-540", "CWE-200"),
        owasp=("A05:2021 Security Misconfiguration",),
        intrusive=False,
        tags=("exposure", "javascript"),
        order=55,
        remediation_key="exposure",
    )

    def run(self) -> Iterable[Finding]:
        for target in self.ctx.targets:
            finding = self._test(target.base_url)
            if finding is not None:
                yield self.emit(finding)

    def _test(self, base_url: str) -> Finding | None:
        try:
            page = self.http.get(base_url, tag="sourcemap")
        except Exception:
            return None
        if self.missing(page):
            return None
        scripts = _SCRIPT_RE.findall(page.text)[:8]
        for script in scripts:
            url = script if script.startswith("http") else join_url(base_url, script if script.startswith("/") else "/" + script).render()
            if self.ctx.scope is not None and not self.ctx.scope.matches(url):
                continue
            map_url = url.split("?")[0] + ".map"
            try:
                response = self.http.get(map_url, tag="sourcemap-probe")
            except Exception:
                continue
            if self.missing(response) or response.status != 200:
                continue
            document = self.json_body(response)
            if not isinstance(document, dict) or "sources" not in document:
                if '"sources"' not in response.text[:4096]:
                    continue
                sources = []
                version = ""
            else:
                sources = [str(item) for item in (document.get("sources") or [])][:20]
                version = str(document.get("version", ""))
            if not sources and '"sources"' not in response.text[:4096]:
                continue
            return self.build_finding(
                title="Source map exposes original JavaScript",
                severity=Severity.MEDIUM,
                url=map_url,
                method="GET",
                description=(
                    f"{map_url} is publicly readable and lists {len(sources)} source file(s)"
                    + (f", for example {', '.join(sources[:3])}" if sources else "")
                    + "."
                ),
                impact=(
                    "Original source reveals internal API routes, feature flags, comments and sometimes "
                    "embedded keys, which shortens the path to exploitation of client-side flaws."
                ),
                payload=map_url,
                confidence=Confidence.CONFIRMED,
                cwe=("CWE-540",),
                tags=("exposure", "javascript"),
                evidence=[self.capture(response, summary="Source map served without authentication")],
                metadata={"sources": sources, "version": version, "script": url},
            )
        return None
