"""JWT weaknesses: weak secrets, alg=none and missing claims."""

from __future__ import annotations

from typing import Iterable

from candix.auth.jwt import (
    crack_hs256,
    decode_unverified,
    find_tokens,
    forge_none,
    inspect_token,
    token_summary,
)
from candix.core.finding import Finding
from candix.core.severity import Confidence, Severity
from candix.detectors.base import BaseDetector, DetectorMeta, register_detector


@register_detector
class JwtDetector(BaseDetector):
    meta = DetectorMeta(
        id="jwt",
        name="JSON Web Token weaknesses",
        category="jwt",
        description="Extracts JWTs from cookies and headers, audits claims, attempts offline secret cracking and tests alg=none acceptance.",
        severity=Severity.HIGH,
        cwe=("CWE-347", "CWE-522"),
        owasp=("A02:2021 Cryptographic Failures", "A07:2021 Identification and Authentication Failures"),
        intrusive=True,
        tags=("authentication", "token"),
        order=95,
        remediation_key="jwt",
    )

    def run(self) -> Iterable[Finding]:
        tokens: dict[str, str] = {}
        for target in self.ctx.targets:
            try:
                response = self.http.get(target.url, tag="jwt-scan")
            except Exception:
                continue
            for header in response.headers.get_all("Set-Cookie"):
                for token in find_tokens(header):
                    tokens.setdefault("cookie", token)
            for name, value in response.headers.items():
                if name.lower() == "authorization":
                    for token in find_tokens(value):
                        tokens.setdefault("authorization", token)
            for token in find_tokens(response.text):
                tokens.setdefault("body", token)
            for token in find_tokens(" ".join(target.headers.values())):
                tokens.setdefault("request-header", token)
        for location, token in tokens.items():
            yield from self._analyse(location, token)

    def _analyse(self, location: str, token: str) -> Iterable[Finding]:
        try:
            header, payload, _ = decode_unverified(token)
        except ValueError:
            return
        issues = inspect_token(token)
        weak_secret = None
        if str(header.get("alg", "")).upper().startswith("HS"):
            weak_secret = crack_hs256(token, self.load_payloads("jwt_weak_secrets"))
        if weak_secret:
            issues.append(
                type(issues[0])(
                    kind="weak_secret",
                    severity="critical",
                    detail=f"The HMAC secret is a common word ({weak_secret!r}) and can be brute-forced offline.",
                    metadata={"secret": weak_secret},
                )
            )
        accepted_none = False
        if self.ctx.scope is not None and self.ctx.scope.allows_exploit():
            accepted_none = self._test_none(token)
        if not issues and not accepted_none:
            return
        severity = Severity.HIGH
        if weak_secret or accepted_none:
            severity = Severity.CRITICAL
        descriptions = [issue.detail for issue in issues]
        if accepted_none:
            descriptions.append("A token with alg=none was accepted by the application.")
        evidence = None
        try:
            page = self.http.get(self.ctx.primary_target.url, tag="jwt-evidence")
            evidence = self.capture(
                page,
                summary="JWT observed and analysed",
                kind="artifact",
                data={"token_summary": token_summary(token), "issues": [issue.to_dict() for issue in issues]},
            )
        except Exception:
            pass
        yield self.emit(
            self.build_finding(
                title="JWT can be forged or lacks required claims",
                severity=severity,
                url=self.ctx.primary_target.url,
                location="cookie" if location == "cookie" else "header",
                description="Token analysis found: " + " ".join(descriptions),
                impact=(
                    "An attacker can mint tokens with arbitrary roles or bypass signature verification, "
                    "leading to account takeover and privilege escalation."
                ),
                confidence=Confidence.CONFIRMED if (weak_secret or accepted_none) else Confidence.LIKELY,
                cwe=("CWE-347",),
                tags=("jwt", location),
                evidence=[evidence] if evidence else [],
                vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N" if (weak_secret or accepted_none) else "",
                metadata={
                    "location": location,
                    "issues": [issue.to_dict() for issue in issues],
                    "weak_secret": weak_secret or "",
                    "accepted_none": accepted_none,
                    "claims": sorted(payload),
                },
            )
        )

    def _test_none(self, token: str) -> bool:
        try:
            header, payload, _ = decode_unverified(token)
        except ValueError:
            return False
        forged = forge_none(payload)
        baseline = None
        try:
            baseline = self.http.get(self.ctx.primary_target.url, tag="jwt-baseline")
            response = self.http.get(
                self.ctx.primary_target.url,
                headers={"Authorization": f"Bearer {forged}"},
                cookies={"jwt": forged},
                tag="jwt-none",
            )
        except Exception:
            return False
        if self.missing(response):
            return False
        if baseline is not None and response.text == baseline.text:
            return False
        protected_markers = ("unauthorized", "forbidden", "invalid token", "login")
        baseline_protected = any(marker in baseline.text.lower() for marker in protected_markers) if baseline else False
        response_protected = any(marker in response.text.lower() for marker in protected_markers)
        return response.status == 200 and not response_protected and (baseline_protected or response.status != (baseline.status if baseline else 0))
