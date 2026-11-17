"""Rate limiting and anti-automation on sensitive endpoints."""

from __future__ import annotations

from typing import Iterable

from candix.core.finding import Finding
from candix.core.severity import Confidence, Severity
from candix.detectors.base import BaseDetector, DetectorMeta, register_detector

_SENSITIVE_HINTS = ("login", "signin", "auth", "register", "signup", "reset", "forgot", "otp", "verify", "coupon", "redeem", "search", "export", "report")


@register_detector
class RateLimitDetector(BaseDetector):
    meta = DetectorMeta(
        id="ratelimit",
        name="Missing rate limiting on sensitive endpoints",
        category="ratelimit",
        description="Sends a short, bounded burst to authentication and expensive endpoints and checks for throttling responses.",
        severity=Severity.MEDIUM,
        cwe=("CWE-770", "CWE-307"),
        owasp=("A04:2021 Insecure Design",),
        intrusive=True,
        tags=("rate-limit", "automation"),
        order=170,
        remediation_key="ratelimit",
    )

    def run(self) -> Iterable[Finding]:
        candidates = [
            endpoint
            for endpoint in self.ctx.endpoints
            if any(hint in endpoint.url.lower() for hint in _SENSITIVE_HINTS)
        ][:3]
        for endpoint in candidates:
            try:
                finding = self._test(endpoint)
            except Exception:
                continue
            if finding is not None:
                yield self.emit(finding)

    def _test(self, endpoint) -> Finding | None:
        burst = 10
        responses = []
        for index in range(burst):
            if index > 0:
                import time

                time.sleep(0.05)
            try:
                response = self.http.request_endpoint(endpoint, tag="ratelimit")
            except Exception:
                return None
            responses.append(response)
            if self.rate_limited(response):
                return None
        if len(responses) < burst:
            return None
        server_headers = {name.lower() for name, _ in responses[0].headers.items()}
        if server_headers & {"x-ratelimit-limit", "ratelimit-limit", "x-rate-limit-limit", "retry-after"}:
            return None
        return self.build_finding(
            title="Sensitive endpoint not rate limited",
            severity=Severity.LOW,
            url=endpoint.url,
            method=endpoint.method,
            description=(
                f"{burst} rapid requests were accepted without HTTP 429, Retry-After or rate-limit headers. "
                "Automated abuse of this endpoint is therefore unrestricted at the application layer."
            ),
            impact="Credential stuffing, enumeration, OTP guessing and resource exhaustion are easier to carry out.",
            confidence=Confidence.CONFIRMED,
            cwe=("CWE-770",),
            tags=("rate-limit",),
            evidence=[
                self.capture(responses[-1], summary="Final request of the burst was not throttled", control=responses[0])
            ],
            metadata={"burst": burst, "statuses": sorted({response.status for response in responses})},
        )
