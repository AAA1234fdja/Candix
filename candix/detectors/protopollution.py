"""Client-side prototype pollution indicators."""

from __future__ import annotations

import re
from typing import Iterable

from candix.core.finding import Finding
from candix.core.severity import Confidence, Severity
from candix.detectors.base import BaseDetector, DetectorMeta, register_detector

_QUERY_PATTERNS = (
    "__proto__[x]=1",
    "constructor[prototype][x]=1",
    "__proto__.x=1",
    "?__proto__=1",
)


@register_detector
class PrototypePollutionDetector(BaseDetector):
    meta = DetectorMeta(
        id="protopollution",
        name="Prototype pollution surface",
        category="protopollution",
        description="Looks for unsafe recursive merge patterns in JavaScript and query strings that reach object assignment.",
        severity=Severity.MEDIUM,
        cwe=("CWE-1321",),
        owasp=("A03:2021 Injection",),
        intrusive=False,
        tags=("javascript", "client-side"),
        order=150,
        remediation_key="protopollution",
    )

    def run(self) -> Iterable[Finding]:
        for target in self.ctx.targets:
            try:
                page = self.http.get(target.url, tag="proto-page")
            except Exception:
                continue
            matches: list[str] = []
            for script in re.findall(r"<script[^>]*>(.*?)</script>", page.text, re.DOTALL | re.IGNORECASE):
                if re.search(r"(\$\.extend|Object\.assign|deepMerge|merge|defaultsDeep)\s*\(", script):
                    if re.search(r"\[[^\]]+\]\s*=", script):
                        matches.append(script.strip()[:300])
            if not matches:
                continue
            yield self.emit(
                self.build_finding(
                    title="Potential prototype pollution sink in client JavaScript",
                    severity=Severity.MEDIUM,
                    url=target.url,
                    location="body",
                    description=(
                        "Client-side code performs recursive merges into objects reached from user input "
                        f"({len(matches)} candidate blocks). Prototype pollution can alter global behaviour."
                    ),
                    impact="Depending on the gadget chain, prototype pollution enables DOM XSS or logic bypass in the browser.",
                    confidence=Confidence.POSSIBLE,
                    cwe=("CWE-1321",),
                    tags=("prototype-pollution", "static-analysis"),
                    evidence=[self.capture(page, summary="Suspicious merge code found", kind="artifact", data={"blocks": matches[:5]})],
                    metadata={"blocks": len(matches)},
                )
            )
