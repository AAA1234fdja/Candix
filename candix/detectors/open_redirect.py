"""Open redirect detection."""

from __future__ import annotations

import re
from typing import Iterable

from candix.core.endpoint import Endpoint, Param
from candix.core.finding import Finding
from candix.core.severity import Confidence, Severity
from candix.detectors.base import BaseDetector, DetectorMeta, register_detector
from candix.net.http import Response

_PARAM_HINTS = (
    "next", "url", "redirect", "redirect_uri", "redirect_url", "return", "returnurl",
    "return_url", "returnto", "continue", "dest", "destination", "target", "goto",
    "forward", "callback", "callbackurl", "checkout", "ref", "referer", "from",
)

_EXTERNAL = "https://candix-external.test/"
_META_REFRESH = re.compile(r"""<meta[^>]+http-equiv=["']?refresh["']?[^>]+url=([^"'>\s]+)""", re.IGNORECASE)


@register_detector
class OpenRedirectDetector(BaseDetector):
    meta = DetectorMeta(
        id="open_redirect",
        name="Open redirect",
        category="open_redirect",
        description="Checks redirect and return parameters for attacker-controlled destinations.",
        severity=Severity.MEDIUM,
        cwe=("CWE-601",),
        owasp=("A01:2021 Broken Access Control",),
        intrusive=True,
        tags=("redirect",),
        order=80,
        remediation_key="open_redirect",
    )

    def run(self) -> Iterable[Finding]:
        for endpoint in self.endpoints():
            for param in self.params_for(endpoint):
                if param.location not in {"query", "body", "json"}:
                    continue
                if param.name.lower() not in _PARAM_HINTS:
                    continue
                finding = self._test(endpoint, param)
                if finding is not None:
                    yield self.emit(finding)

    def _test(self, endpoint: Endpoint, param: Param) -> Finding | None:
        payloads = [_EXTERNAL, "//candix-external.test/", "https://candix-external.test/%2f.."]
        try:
            baseline = self.send(endpoint, {param.name: param.value or "/"}, tag="redirect-baseline")
        except Exception:
            return None
        for payload in payloads:
            try:
                response = self.send(
                    endpoint,
                    {param.name: payload},
                    tag="redirect-probe",
                )
            except Exception:
                continue
            if self.missing(response):
                continue
            location = response.header("Location")
            hit = _is_external(location, "candix-external.test")
            meta_target = ""
            if not hit:
                match = _META_REFRESH.search(response.text)
                if match:
                    meta_target = match.group(1)
                    hit = _is_external(meta_target, "candix-external.test")
            if not hit:
                continue
            if baseline is not None and _is_external(baseline.header("Location"), "candix-external.test"):
                continue
            return self.build_finding(
                title="Open redirect",
                severity=Severity.MEDIUM,
                url=endpoint.url,
                method=endpoint.method,
                parameter=param.name,
                location=param.location,
                description=(
                    f"The parameter '{param.name}' accepted an external destination ({payload!r}); the "
                    f"application redirected to {location or meta_target}."
                ),
                impact=(
                    "Open redirects are used in phishing, OAuth token theft and SSRF filter bypass. "
                    "They undermine trust in the legitimate domain."
                ),
                payload=payload,
                confidence=Confidence.CONFIRMED,
                cwe=("CWE-601",),
                tags=("redirect",),
                evidence=[
                    self.capture(
                        response,
                        summary="Redirect to attacker-controlled destination",
                        control=baseline,
                        data={"location": location, "meta_refresh": meta_target},
                    )
                ],
                metadata={"location": location or meta_target},
            )
        return None


def _is_external(location: str, expected_host: str) -> bool:
    if not location:
        return False
    lowered = location.strip().lower()
    if lowered.startswith(("//", "http://", "https://", "/\\")):
        return expected_host in lowered or "candix-external" in lowered
    return False
