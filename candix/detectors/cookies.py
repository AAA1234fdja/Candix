"""Cookie hardening checks."""

from __future__ import annotations

from typing import Iterable

from candix.core.finding import Finding
from candix.core.severity import Confidence, Severity
from candix.detectors.base import BaseDetector, DetectorMeta, register_detector
from candix.net.cookies import analyze_cookies


@register_detector
class CookieHardeningDetector(BaseDetector):
    meta = DetectorMeta(
        id="cookies",
        name="Cookie attribute hardening",
        category="cookies",
        description="Checks session and non-session cookies for missing Secure, HttpOnly and SameSite attributes and weak identifiers.",
        severity=Severity.MEDIUM,
        cwe=("CWE-614", "CWE-1004", "CWE-1275"),
        owasp=("A07:2021 Identification and Authentication Failures", "A05:2021 Security Misconfiguration"),
        intrusive=False,
        tags=("passive", "session"),
        order=15,
        remediation_key="cookies",
    )

    def run(self) -> Iterable[Finding]:
        for target in self.ctx.targets:
            response = self.http.get(target.url, tag="cookies")
            if self.missing(response):
                continue
            cookies = response.cookies()
            if not cookies:
                continue
            issues = analyze_cookies(cookies, https=target.url.startswith("https://"))
            if not issues:
                continue
            by_cookie: dict[str, list[str]] = {}
            for issue in issues:
                by_cookie.setdefault(issue.cookie, []).append(f"{issue.problem}: {issue.detail}")
            evidence = self.capture(
                response,
                summary="Cookie attributes observed in response",
                data={"cookies": [cookie.to_dict() for cookie in cookies]},
            )
            severity = Severity.MEDIUM if any(issue.severity == "medium" for issue in issues) else Severity.LOW
            yield self.emit(
                self.build_finding(
                    title="Session cookies lack hardening attributes",
                    severity=severity,
                    url=target.url,
                    location="cookie",
                    description=(
                        "Cookies returned by the application are missing security attributes: "
                        + "; ".join(f"{name} ({', '.join(problems)})" for name, problems in by_cookie.items())
                    ),
                    impact="Tokens can be stolen through XSS or plaintext transport, and cross-site requests may carry the session automatically.",
                    confidence=Confidence.CONFIRMED,
                    cwe=("CWE-614", "CWE-1004"),
                    tags=("cookies", "session"),
                    evidence=[evidence],
                    metadata={"issues": [issue.to_dict() for issue in issues]},
                )
            )
