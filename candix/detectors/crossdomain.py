"""Cross-domain policy files that grant excessive trust."""

from __future__ import annotations

from typing import Iterable

from candix.core.finding import Finding
from candix.core.severity import Confidence, Severity
from candix.detectors.base import BaseDetector, DetectorMeta, register_detector
from candix.net.url import join_url


@register_detector
class CrossDomainDetector(BaseDetector):
    meta = DetectorMeta(
        id="crossdomain",
        name="Overly permissive cross-domain policy",
        category="crossdomain",
        description="Fetches crossdomain.xml and clientaccesspolicy.xml and checks for wildcard grants.",
        severity=Severity.MEDIUM,
        cwe=("CWE-942",),
        owasp=("A05:2021 Security Misconfiguration",),
        intrusive=False,
        tags=("configuration", "flash", "silverlight"),
        order=160,
        remediation_key="cors",
    )

    def run(self) -> Iterable[Finding]:
        for target in self.ctx.targets:
            for path, parser in (("/crossdomain.xml", _flash), ("/clientaccesspolicy.xml", _silverlight)):
                finding = self._test(target.base_url, path, parser)
                if finding is not None:
                    yield self.emit(finding)

    def _test(self, base_url: str, path: str, parser: object) -> Finding | None:
        url = join_url(base_url, path).render()
        if self.ctx.scope is not None and not self.ctx.scope.matches(url):
            return None
        try:
            response = self.http.get(url, tag="crossdomain")
        except Exception:
            return None
        if self.missing(response) or response.status != 200:
            return None
        parsed = parser(response.text)  # type: ignore[operator]
        if not parsed.get("wildcard"):
            return None
        severity = Severity.HIGH if parsed.get("wildcard") == "*" and parsed.get("headers") else Severity.MEDIUM
        return self.build_finding(
            title="Permissive cross-domain policy file",
            severity=severity,
            url=url,
            method="GET",
            description=(
                f"{path} grants access to {parsed.get('wildcard')!r}"
                + (f" including headers {', '.join(parsed.get('headers', []))}" if parsed.get("headers") else "")
                + "."
            ),
            impact=(
                "Any website can issue authenticated cross-origin requests to this host and read the responses, "
                "bypassing the same-origin policy for the affected plugin runtimes."
            ),
            payload=path,
            confidence=Confidence.CONFIRMED,
            cwe=("CWE-942",),
            tags=("configuration",),
            evidence=[self.capture(response, summary="Wildcard cross-domain grant")],
            metadata=dict(parsed),
        )


def _flash(text: str) -> dict[str, object]:
    lowered = text.lower()
    wildcard = "*" if "domain=\"*\"" in lowered or "domain='*'" in lowered else ""
    headers = []
    for name in ("Authorization", "X-Requested-With", "Content-Type"):
        if name.lower() in lowered:
            headers.append(name)
    return {"wildcard": wildcard, "headers": headers, "kind": "crossdomain.xml"}


def _silverlight(text: str) -> dict[str, object]:
    lowered = text.lower()
    wildcard = "*" if "uri=\"*\"" in lowered or "uri='*'" in lowered else ""
    headers = ["*"] if "<headers><header name=\"*\" />" in lowered.replace("  ", "") else []
    return {"wildcard": wildcard, "headers": headers, "kind": "clientaccesspolicy.xml"}
