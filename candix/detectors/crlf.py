"""CRLF injection and response splitting."""

from __future__ import annotations

from typing import Iterable

from candix.core.endpoint import Endpoint, Param
from candix.core.finding import Finding
from candix.core.severity import Confidence, Severity
from candix.detectors.base import BaseDetector, DetectorMeta, register_detector

_PARAM_HINTS = ("url", "next", "redirect", "return", "callback", "host", "domain", "file", "path", "name", "lang")


@register_detector
class CrlfDetector(BaseDetector):
    meta = DetectorMeta(
        id="crlf",
        name="CRLF header injection",
        category="crlf",
        description="Injects encoded CRLF sequences and checks whether new headers or body content are produced.",
        severity=Severity.MEDIUM,
        cwe=("CWE-113", "CWE-93"),
        owasp=("A03:2021 Injection",),
        intrusive=True,
        tags=("injection", "headers"),
        order=85,
        remediation_key="crlf",
    )

    def run(self) -> Iterable[Finding]:
        for endpoint in self.endpoints():
            for param in self.params_for(endpoint):
                if param.location not in {"query", "body", "json"}:
                    continue
                if not any(hint in param.name.lower() for hint in _PARAM_HINTS):
                    continue
                finding = self._test(endpoint, param)
                if finding is not None:
                    yield self.emit(finding)

    def _test(self, endpoint: Endpoint, param: Param) -> Finding | None:
        marker = self.marker("cr")
        payloads = [
            f"%0d%0aX-Candix-{marker}: 1",
            f"\r\nX-Candix-{marker}: 1",
            f"%0aX-Candix-{marker}: 1",
            f"%0d%0aSet-Cookie: cdx{marker}=1",
        ]
        try:
            baseline = self.send(endpoint, {param.name: param.value or "/"}, tag="crlf-baseline")
        except Exception:
            return None
        baseline_headers = {name.lower() for name, _ in baseline.headers.items()}
        for payload in payloads:
            try:
                response = self.send(endpoint, {param.name: payload}, tag="crlf-probe")
            except Exception:
                continue
            if self.missing(response):
                continue
            injected = []
            for name, value in response.headers.items():
                lowered = name.lower()
                if marker.lower() in lowered or marker in value:
                    injected.append(f"{name}: {value[:80]}")
            if not injected:
                continue
            if any(marker.lower() in header for header in baseline_headers):
                continue
            return self.build_finding(
                title="CRLF injection allows response header manipulation",
                severity=Severity.MEDIUM,
                url=endpoint.url,
                method=endpoint.method,
                parameter=param.name,
                location=param.location,
                description=(
                    f"Injecting {payload!r} into '{param.name}' caused new response headers to be emitted: "
                    + "; ".join(injected[:3])
                ),
                impact=(
                    "Header injection enables response splitting, cookie fixation, cache poisoning and, "
                    "in some stacks, cross-site scripting."
                ),
                payload=payload,
                confidence=Confidence.CONFIRMED,
                cwe=("CWE-113",),
                tags=("crlf", "headers"),
                evidence=[self.capture(response, summary="Injected header observed", control=baseline)],
                metadata={"injected_headers": injected},
            )
        return None
