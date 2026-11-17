"""Cross-Origin Resource Sharing misconfiguration."""

from __future__ import annotations

from typing import Iterable

from candix.core.finding import Finding
from candix.core.severity import Confidence, Severity
from candix.detectors.base import BaseDetector, DetectorMeta, register_detector

_EVIL_ORIGINS = (
    "https://candix-test.example",
    "null",
    "https://target.example",
)


@register_detector
class CorsDetector(BaseDetector):
    meta = DetectorMeta(
        id="cors",
        name="CORS origin reflection",
        category="cors",
        description="Checks whether the application reflects arbitrary Origin headers, especially with credentials enabled.",
        severity=Severity.HIGH,
        cwe=("CWE-942", "CWE-346"),
        owasp=("A05:2021 Security Misconfiguration",),
        intrusive=False,
        tags=("passive", "cors"),
        order=20,
        remediation_key="cors",
    )

    def run(self) -> Iterable[Finding]:
        for target in self.ctx.targets:
            base = self.http.get(target.url, tag="cors-baseline")
            if self.missing(base):
                continue
            for origin in _EVIL_ORIGINS:
                response = self.http.get(
                    target.url,
                    headers={"Origin": origin},
                    tag="cors-probe",
                )
                allow_origin = response.header("Access-Control-Allow-Origin")
                allow_credentials = response.header("Access-Control-Allow-Credentials").lower() == "true"
                if not allow_origin:
                    continue
                reflected = allow_origin == origin or allow_origin == "*"
                if not reflected:
                    continue
                if allow_origin == "*" and allow_credentials:
                    severity = Severity.HIGH
                    detail = "wildcard origin combined with credentials"
                elif origin == "null" and allow_credentials:
                    severity = Severity.HIGH
                    detail = "null origin accepted with credentials"
                elif allow_credentials:
                    severity = Severity.HIGH
                    detail = "arbitrary origin reflected with credentials"
                else:
                    severity = Severity.MEDIUM
                    detail = "arbitrary origin reflected without credentials"
                yield self.emit(
                    self.build_finding(
                        title="CORS policy reflects arbitrary origins",
                        severity=severity,
                        url=target.url,
                        location="header",
                        description=(
                            f"The endpoint returned Access-Control-Allow-Origin: {allow_origin} for the "
                            f"attacker-controlled Origin '{origin}' ({detail})."
                        ),
                        impact=(
                            "A malicious site can read authenticated responses from the application, "
                            "leading to account data theft and actions on behalf of the victim."
                        ),
                        confidence=Confidence.CONFIRMED,
                        cwe=("CWE-942",),
                        tags=("cors",),
                        evidence=[self.capture(response, summary=f"CORS reflection for Origin: {origin}")],
                        metadata={
                            "origin": origin,
                            "allow_origin": allow_origin,
                            "allow_credentials": allow_credentials,
                            "detail": detail,
                        },
                    )
                )
                break
