"""XPath injection."""

from __future__ import annotations

from typing import Iterable

from candix.core.endpoint import Endpoint, Param
from candix.core.finding import Finding
from candix.core.severity import Confidence, Severity
from candix.detectors.base import BaseDetector, DetectorMeta, register_detector


@register_detector
class XPathDetector(BaseDetector):
    meta = DetectorMeta(
        id="xpath",
        name="XPath injection",
        category="xpath",
        description="Uses quote-breaking and tautology payloads against XML-backed search parameters.",
        severity=Severity.MEDIUM,
        cwe=("CWE-643",),
        owasp=("A03:2021 Injection",),
        intrusive=True,
        tags=("injection", "xml"),
        order=140,
        remediation_key="xpath",
    )

    def run(self) -> Iterable[Finding]:
        for endpoint in self.endpoints():
            for param in self.params_for(endpoint):
                if param.location not in {"query", "body"}:
                    continue
                finding = self._test(endpoint, param)
                if finding is not None:
                    yield self.emit(finding)

    def _test(self, endpoint: Endpoint, param: Param) -> Finding | None:
        try:
            baseline = self.send(endpoint, {param.name: "candix"}, tag="xpath-baseline")
        except Exception:
            return None
        if self.missing(baseline):
            return None
        for payload in ("' or '1'='1", "' or 1=1 or ''='", "\" or \"1\"=\"1", "x' or name()='a' or 'x'='y"):
            try:
                response = self.send(endpoint, {param.name: payload}, tag="xpath-probe")
            except Exception:
                continue
            if self.missing(response):
                continue
            if response.text == baseline.text:
                continue
            if response.status != baseline.status or abs(response.size - baseline.size) > max(64, baseline.size // 8):
                control = self.send(endpoint, {param.name: "' and '1'='2"}, tag="xpath-control")
                if control is not None and control.text == baseline.text:
                    return self.build_finding(
                        title="XPath injection",
                        severity=Severity.MEDIUM,
                        url=endpoint.url,
                        method=endpoint.method,
                        parameter=param.name,
                        location=param.location,
                        description=f"The tautology payload {payload!r} altered the XML query result while a false condition behaved like the baseline.",
                        impact="Disclosure of XML document contents or authentication bypass.",
                        payload=payload,
                        confidence=Confidence.LIKELY,
                        cwe=("CWE-643",),
                        tags=("xpath",),
                        evidence=[self.capture(response, summary="Tautology changed the query result", control=control)],
                    )
        return None
