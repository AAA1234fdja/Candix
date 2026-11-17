"""Cross-site request forgery protections on state-changing forms."""

from __future__ import annotations

import re
from typing import Iterable

from candix.core.endpoint import Endpoint
from candix.core.finding import Finding
from candix.core.severity import Confidence, Severity
from candix.detectors.base import BaseDetector, DetectorMeta, register_detector

_TOKEN_HINTS = ("csrf", "xsrf", "_token", "authenticity_token", "requestverificationtoken", "nonce")


@register_detector
class CsrfDetector(BaseDetector):
    meta = DetectorMeta(
        id="csrf",
        name="Missing anti-CSRF protection",
        category="csrf",
        description="Inspects state-changing forms for anti-CSRF tokens and SameSite cookie protection.",
        severity=Severity.MEDIUM,
        cwe=("CWE-352",),
        owasp=("A01:2021 Broken Access Control",),
        intrusive=False,
        tags=("csrf", "session"),
        order=110,
        remediation_key="csrf",
    )

    def run(self) -> Iterable[Finding]:
        for endpoint in self.ctx.endpoints:
            if endpoint.method.upper() not in {"POST", "PUT", "PATCH", "DELETE"}:
                continue
            has_token = any(
                any(hint in param.name.lower() for hint in _TOKEN_HINTS) for param in endpoint.params
            ) or any(
                any(hint in field.get("name", "").lower() for hint in _TOKEN_HINTS)
                for form in endpoint.forms
                for field in form.get("fields", [])
            )
            if has_token:
                continue
            if not endpoint.params:
                continue
            protected = self._samesite_protected(endpoint)
            severity = Severity.LOW if protected else Severity.MEDIUM
            try:
                response = self.http.request_endpoint(endpoint, tag="csrf-evidence")
            except Exception:
                continue
            yield self.emit(
                self.build_finding(
                    title="State-changing request lacks anti-CSRF token",
                    severity=severity,
                    url=endpoint.url,
                    method=endpoint.method,
                    location="body",
                    description=(
                        f"The {endpoint.method} endpoint accepts {len(endpoint.params)} parameters but no "
                        f"anti-CSRF token was found in the form or request."
                        + (" Session cookies use SameSite, which mitigates browser-driven attacks." if protected else " No SameSite protection was observed, so cross-site submission is possible.")
                    ),
                    impact="An attacker can make a victim perform unintended state changes (password, email, permissions, transfers).",
                    confidence=Confidence.LIKELY,
                    cwe=("CWE-352",),
                    tags=("csrf",),
                    evidence=[self.capture(response, summary="State-changing request without a CSRF token")],
                    metadata={"params": [param.name for param in endpoint.params], "samesite": protected},
                )
            )

    def _samesite_protected(self, endpoint: Endpoint) -> bool:
        try:
            response = self.http.get(endpoint.url, tag="csrf-cookie")
        except Exception:
            return False
        for cookie in response.cookies():
            if cookie.same_site.lower() in {"lax", "strict"}:
                return True
        return False
