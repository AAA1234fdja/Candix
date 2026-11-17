"""NoSQL injection (MongoDB-style operators and JavaScript injection)."""

from __future__ import annotations

from typing import Iterable

from candix.analysis.diff import similarity
from candix.core.endpoint import Endpoint, Param
from candix.core.finding import Finding
from candix.core.severity import Confidence, Severity
from candix.detectors.base import BaseDetector, DetectorMeta, register_detector


@register_detector
class NoSqlDetector(BaseDetector):
    meta = DetectorMeta(
        id="nosqli",
        name="NoSQL injection",
        category="nosqli",
        description="Injects query operators into JSON and form parameters and compares responses against controls.",
        severity=Severity.HIGH,
        cwe=("CWE-943",),
        owasp=("A03:2021 Injection",),
        intrusive=True,
        tags=("injection", "database"),
        order=130,
        remediation_key="nosqli",
    )

    def run(self) -> Iterable[Finding]:
        for endpoint in self.endpoints():
            for param in self.params_for(endpoint):
                if param.location not in {"query", "body", "json"}:
                    continue
                finding = self._test(endpoint, param)
                if finding is not None:
                    yield self.emit(finding)

    def _test(self, endpoint: Endpoint, param: Param) -> Finding | None:
        payloads = self.load_payloads("nosqli")[:8]
        try:
            baseline = self.send(endpoint, {param.name: param.value or "candix"}, tag="nosqli-baseline")
        except Exception:
            return None
        if self.missing(baseline):
            return None
        for payload in payloads:
            try:
                response = self.send(endpoint, {param.name: payload}, tag="nosqli-probe")
            except Exception:
                continue
            if self.missing(response):
                continue
            if response.status != baseline.status and response.status in {200, 500}:
                control_payload = payload.replace("1", "0").replace("true", "false")
                control = self.send(endpoint, {param.name: control_payload}, tag="nosqli-control")
                if control is not None and control.status == baseline.status:
                    return self.build_finding(
                        title="NoSQL injection",
                        severity=Severity.HIGH,
                        url=endpoint.url,
                        method=endpoint.method,
                        parameter=param.name,
                        location=param.location,
                        description=(
                            f"Injecting the operator payload {payload!r} into '{param.name}' changed the "
                            f"response (HTTP {baseline.status} -> {response.status}), while a benign control did not."
                        ),
                        impact="Authentication bypass, data exfiltration and in some configurations server-side JavaScript execution.",
                        payload=payload,
                        confidence=Confidence.LIKELY,
                        cwe=("CWE-943",),
                        tags=("nosqli", "injection"),
                        evidence=[
                            self.capture(response, summary="Response changed after operator injection", control=baseline),
                            self.capture(control, summary="Control payload did not reproduce the change"),
                        ],
                        vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                        metadata={"technique": "operator"},
                    )
            delta = similarity(baseline.text, response.text)
            if delta < 0.6 and response.status == baseline.status and len(response.text) != len(baseline.text):
                return self.build_finding(
                    title="Possible NoSQL injection (response divergence)",
                    severity=Severity.MEDIUM,
                    url=endpoint.url,
                    method=endpoint.method,
                    parameter=param.name,
                    location=param.location,
                    description=f"An operator payload changed the response body substantially (similarity {delta:.2f}).",
                    impact="May allow query manipulation and data disclosure.",
                    payload=payload,
                    confidence=Confidence.POSSIBLE,
                    cwe=("CWE-943",),
                    tags=("nosqli",),
                    evidence=[self.capture(response, summary="Divergent response for operator payload", control=baseline)],
                )
        return None
