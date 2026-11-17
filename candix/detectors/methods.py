"""HTTP method handling, TRACE and dangerous verbs."""

from __future__ import annotations

from typing import Iterable

from candix.core.finding import Finding
from candix.core.severity import Confidence, Severity
from candix.detectors.base import BaseDetector, DetectorMeta, register_detector


@register_detector
class HttpMethodsDetector(BaseDetector):
    meta = DetectorMeta(
        id="methods",
        name="HTTP method handling",
        category="headers",
        description="Checks the Allow response header, TRACE support and whether destructive verbs are exposed without authentication.",
        severity=Severity.LOW,
        cwe=("CWE-650", "CWE-749"),
        owasp=("A05:2021 Security Misconfiguration",),
        intrusive=True,
        tags=("configuration", "http"),
        order=35,
        remediation_key="misconfig",
    )

    def run(self) -> Iterable[Finding]:
        for target in self.ctx.targets:
            try:
                response = self.http.options(target.url, tag="methods-options")
            except Exception:
                continue
            allow = response.header("Allow") or response.header("Access-Control-Allow-Methods")
            if allow:
                verbs = {verb.strip().upper() for verb in allow.replace(",", " ").split()}
                risky = verbs & {"PUT", "DELETE", "TRACE", "CONNECT", "PATCH"}
                if risky:
                    yield self.emit(
                        self.build_finding(
                            title="Risky HTTP methods advertised",
                            severity=Severity.LOW,
                            url=target.url,
                            location="header",
                            description=f"The endpoint advertises methods that are rarely required: {', '.join(sorted(risky))}.",
                            impact="Unnecessary verbs widen the attack surface and sometimes bypass authorisation filters.",
                            confidence=Confidence.CONFIRMED,
                            cwe=("CWE-650",),
                            tags=("http", "methods"),
                            evidence=[self.capture(response, summary="Allowed methods disclosed")],
                            metadata={"allow": allow},
                        )
                    )
            try:
                trace = self.http.request("TRACE", target.url, tag="methods-trace")
            except Exception:
                continue
            if trace.status == 200 and ("TRACE" in trace.text or target.host in trace.text):
                yield self.emit(
                    self.build_finding(
                        title="HTTP TRACE method enabled",
                        severity=Severity.LOW,
                        url=target.url,
                        location="config",
                        description="The server responds to TRACE requests, reflecting request headers (Cross-Site Tracing).",
                        impact="Combined with a browser bug or misconfiguration, TRACE can be used to read credentials from headers.",
                        confidence=Confidence.CONFIRMED,
                        cwe=("CWE-749",),
                        tags=("http", "trace"),
                        evidence=[self.capture(trace, summary="TRACE request echoed by the server")],
                    )
                )
