"""Server-side template injection."""

from __future__ import annotations

import re
from typing import Iterable

from candix.core.endpoint import Endpoint, Param
from candix.core.finding import Finding
from candix.core.severity import Confidence, Severity
from candix.detectors.base import BaseDetector, DetectorMeta, register_detector

_SSTI_OUTPUT = re.compile(r"(?<![\d.])49(?![\d.])")
_ENGINE_HINTS = {
    "jinja2": ("{{7*7}}", "49"),
    "twig": ("{{7*7}}", "49"),
    "freemarker": ("${7*7}", "49"),
    "velocity": ("#set($x=7*7)$x", "49"),
    "smarty": ("{7*7}", "49"),
    "razor": ("@(7*7)", "49"),
    "erb": ("<%= 7*7 %>", "49"),
    "spring": ("*{7*7}", "49"),
    "mako": ("${7*7}", "49"),
}


@register_detector
class SstiDetector(BaseDetector):
    meta = DetectorMeta(
        id="ssti",
        name="Server-side template injection",
        category="ssti",
        description="Submits arithmetic expressions in common template syntaxes and looks for the evaluated result.",
        severity=Severity.CRITICAL,
        cwe=("CWE-1336", "CWE-94"),
        owasp=("A03:2021 Injection",),
        intrusive=True,
        tags=("injection", "template"),
        order=60,
        remediation_key="ssti",
    )

    def run(self) -> Iterable[Finding]:
        for endpoint in self.endpoints():
            for param in self.params_for(endpoint):
                if param.location not in {"query", "body", "json", "path"}:
                    continue
                finding = self._test(endpoint, param)
                if finding is not None:
                    yield self.emit(finding)

    def _test(self, endpoint: Endpoint, param: Param) -> Finding | None:
        try:
            baseline = self.send(endpoint, {param.name: param.value or "candix"}, tag="ssti-baseline")
        except Exception:
            return None
        if self.missing(baseline):
            return None
        for engine, (payload, expected) in _ENGINE_HINTS.items():
            try:
                response = self.send(endpoint, {param.name: payload}, tag="ssti-probe")
            except Exception:
                continue
            if self.missing(response) or payload in response.text:
                continue
            if expected not in response.text:
                continue
            if _SSTI_OUTPUT.search(response.text) is None:
                continue
            # Confirm with a second expression so a static "49" on the page
            # cannot create a false positive.
            confirm_payload = payload.replace("7*7", "7*8")
            try:
                confirm = self.send(endpoint, {param.name: confirm_payload}, tag="ssti-confirm")
            except Exception:
                continue
            if confirm is None or "56" not in confirm.text:
                continue
            control = self.send(endpoint, {param.name: "{{7*7}}"}, tag="ssti-control") if engine != "jinja2" else baseline
            return self.build_finding(
                title="Server-side template injection",
                severity=Severity.CRITICAL,
                url=endpoint.url,
                method=endpoint.method,
                parameter=param.name,
                location=param.location,
                description=(
                    f"The parameter '{param.name}' is evaluated as a {engine} template expression: "
                    f"{payload!r} rendered as {expected} and the control expression rendered as 56."
                ),
                impact=(
                    "Template injection typically leads to remote code execution, full server compromise "
                    "and access to application secrets."
                ),
                payload=payload,
                confidence=Confidence.CONFIRMED,
                cwe=("CWE-1336", "CWE-94"),
                tags=("ssti", engine),
                evidence=[
                    self.capture(response, summary=f"Template expression {payload!r} evaluated", control=control),
                    self.capture(confirm, summary="Second expression confirms evaluation"),
                ],
                vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                metadata={"engine": engine, "expected": expected},
            )
        return None
