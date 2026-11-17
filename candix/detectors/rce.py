"""OS command injection.

Detection uses unique markers echoed by a benign command. No payload writes
files, spawns long-lived processes or changes system state. Confirmation
requires the marker to appear twice with independent syntax and to be absent
from the baseline.
"""

from __future__ import annotations

from typing import Iterable

from candix.core.endpoint import Endpoint, Param
from candix.core.finding import Finding
from candix.core.severity import Confidence, Severity
from candix.detectors.base import BaseDetector, DetectorMeta, register_detector

_PARAM_HINTS = (
    "cmd", "command", "exec", "execute", "run", "shell", "ping", "host", "ip", "addr",
    "address", "hostname", "domain", "target", "server", "query", "process", "daemon",
)


@register_detector
class CommandInjectionDetector(BaseDetector):
    meta = DetectorMeta(
        id="rce",
        name="OS command injection",
        category="rce",
        description="Injects shell metacharacters with a unique echo marker to prove command execution.",
        severity=Severity.CRITICAL,
        cwe=("CWE-78",),
        owasp=("A03:2021 Injection",),
        intrusive=True,
        tags=("injection", "shell"),
        order=70,
        remediation_key="rce",
    )

    def run(self) -> Iterable[Finding]:
        for endpoint in self.endpoints():
            for param in self.params_for(endpoint):
                if param.location not in {"query", "body", "json"}:
                    continue
                if not self._interesting(param):
                    continue
                finding = self._test(endpoint, param)
                if finding is not None:
                    yield self.emit(finding)

    def _interesting(self, param: Param) -> bool:
        name = param.name.lower()
        if any(hint in name for hint in _PARAM_HINTS):
            return True
        value = (param.value or "").lower()
        return any(token in value for token in ("127.0.0.1", "localhost", ".com", "http://"))

    def _test(self, endpoint: Endpoint, param: Param) -> Finding | None:
        marker = self.marker("rc")
        try:
            baseline = self.send(endpoint, {param.name: param.value or "127.0.0.1"}, tag="rce-baseline")
        except Exception:
            return None
        if self.missing(baseline) or marker in baseline.text:
            return None
        templates = [";echo {m}", "|echo {m}", "$(echo {m})", "&&echo {m}", "`echo {m}`"]
        hits: list[tuple[str, object]] = []
        for template in templates:
            payload = template.format(m=marker)
            try:
                response = self.send(endpoint, {param.name: payload}, tag="rce-probe")
            except Exception:
                continue
            if self.missing(response):
                continue
            if marker in response.text and marker not in baseline.text:
                hits.append((payload, response))
            if len(hits) >= 2:
                break
        if not hits:
            return None
        payload, response = hits[0]
        second_payload, second_response = hits[1] if len(hits) > 1 else (payload, response)
        if len(hits) < 2:
            confidence = Confidence.LIKELY
        else:
            confidence = Confidence.CONFIRMED
        return self.build_finding(
            title="OS command injection",
            severity=Severity.CRITICAL,
            url=endpoint.url,
            method=endpoint.method,
            parameter=param.name,
            location=param.location,
            description=(
                f"The parameter '{param.name}' is passed to a shell. Injecting {payload!r} caused the "
                "unique marker to be echoed by the server."
            ),
            impact=(
                "Arbitrary command execution as the web user. This usually enables full host compromise, "
                "credential theft and lateral movement."
            ),
            payload=payload,
            confidence=confidence,
            cwe=("CWE-78",),
            tags=("rce", "command-injection"),
            evidence=[
                self.capture(response, summary=f"Marker echoed after {payload!r}", control=baseline),
                self.capture(second_response, summary=f"Second injection syntax {second_payload!r} reproduces execution"),
            ],
            vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            metadata={"marker": marker, "techniques": len(hits)},
        )
