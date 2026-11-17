"""Session fixation and cookie rotation checks."""

from __future__ import annotations

from typing import Iterable

from candix.auth.session import analyse_cookies, compare_sessions, parse_set_cookie
from candix.core.finding import Finding
from candix.core.severity import Confidence, Severity
from candix.detectors.base import BaseDetector, DetectorMeta, register_detector


@register_detector
class SessionFixationDetector(BaseDetector):
    meta = DetectorMeta(
        id="sessionfix",
        name="Session fixation and cookie weakness",
        category="sessionfix",
        description="Collects Set-Cookie headers from public pages and checks flags, entropy and identifier reuse.",
        severity=Severity.MEDIUM,
        cwe=("CWE-384", "CWE-614"),
        owasp=("A07:2021 Identification and Authentication Failures",),
        intrusive=False,
        tags=("auth", "cookies"),
        order=125,
        remediation_key="session",
    )

    def run(self) -> Iterable[Finding]:
        for target in self.ctx.targets:
            yield from self._inspect(target.base_url)

    def _inspect(self, base_url: str) -> Iterable[Finding]:
        responses = []
        for path in ("/", "/login", "/account"):
            if self.ctx.scope is not None and not self.ctx.scope.matches(base_url.rstrip("/") + path):
                continue
            try:
                responses.append(self.http.get(base_url.rstrip("/") + path, tag="sessionfix"))
            except Exception:
                continue
        if not responses:
            return
        cookies = []
        for response in responses:
            for header_value in response.headers.get_all("Set-Cookie"):
                cookie = parse_set_cookie(header_value, host=response.url)
                if cookie.name:
                    cookies.append(cookie)
        if not cookies:
            return
        report = analyse_cookies(cookies)
        if report.issues:
            severity = Severity.MEDIUM
            if any("weak value" in issue or "low entropy" in issue or "sequential" in issue for issue in report.issues):
                severity = Severity.HIGH
            yield self.emit(
                self.build_finding(
                    title="Session cookie weaknesses",
                    severity=severity,
                    url=base_url,
                    method="GET",
                    description=" ".join(report.issues[:5]),
                    impact=(
                        "Cookies without HttpOnly/Secure or with predictable values allow session theft "
                        "through script injection, network interception or simple guessing."
                    ),
                    payload="",
                    confidence=Confidence.CONFIRMED,
                    cwe=("CWE-614", "CWE-1004"),
                    tags=("cookies", "session"),
                    evidence=[self.capture(responses[-1], summary="Set-Cookie headers reviewed")],
                    metadata=report.to_dict(),
                )
            )
        elif any(cookie.looks_like_session for cookie in cookies):
            yield self.emit(
                self.build_finding(
                    title="Session identifier issued on an anonymous request",
                    severity=Severity.LOW,
                    url=base_url,
                    method="GET",
                    description=(
                        "The application issues a session identifier before authentication; "
                        "verify that it rotates after login to prevent fixation."
                    ),
                    impact="If the identifier is reused after login, an attacker who plants it keeps access to the victim's session.",
                    payload="",
                    confidence=Confidence.POSSIBLE,
                    cwe=("CWE-384",),
                    tags=("cookies", "session"),
                    evidence=[self.capture(responses[0], summary="Anonymous session cookie issued")],
                    metadata={"cookies": [cookie.to_dict() for cookie in cookies]},
                )
            )

    def _rotation(self, before: list[str], after: list[str]) -> Finding | None:
        old = [parse_set_cookie(item) for item in before]
        new = [parse_set_cookie(item) for item in after]
        report = compare_sessions(old, new)
        if not report.fixation_suspected:
            return None
        return self.build_finding(
            title="Session identifier is not rotated after authentication",
            severity=Severity.HIGH,
            url=self.ctx.base_url,
            method="GET",
            description="The session cookie kept the same value across the authentication step.",
            impact="An attacker who fixes a session identifier before login can reuse the authenticated session.",
            confidence=Confidence.LIKELY,
            cwe=("CWE-384",),
            tags=("session",),
            metadata=report.to_dict(),
        )
