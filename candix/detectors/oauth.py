"""OAuth 2.0 / OpenID Connect configuration weaknesses."""

from __future__ import annotations

from typing import Iterable

from candix.auth.oauth import OidcMetadata, discovery_urls
from candix.core.finding import Finding
from candix.core.severity import Confidence, Severity
from candix.detectors.base import BaseDetector, DetectorMeta, register_detector
from candix.net.url import join_url


@register_detector
class OAuthConfigDetector(BaseDetector):
    meta = DetectorMeta(
        id="oauth",
        name="OAuth/OIDC configuration weaknesses",
        category="oauth",
        description="Fetches OpenID Connect discovery documents and reviews the advertised flows, grants and PKCE support.",
        severity=Severity.MEDIUM,
        cwe=("CWE-287", "CWE-522"),
        owasp=("A07:2021 Identification and Authentication Failures",),
        intrusive=False,
        tags=("auth", "oidc"),
        order=120,
        remediation_key="auth",
    )

    def run(self) -> Iterable[Finding]:
        seen_issuers: set[str] = set()
        for target in self.ctx.targets:
            for candidate in discovery_urls(target.base_url) + [join_url(target.base_url, "/.well-known/openid-configuration").render()]:
                if candidate in seen_issuers:
                    continue
                seen_issuers.add(candidate)
                finding = self._test(candidate)
                if finding is not None:
                    yield self.emit(finding)

    def _test(self, url: str) -> Finding | None:
        if self.ctx.scope is not None and not self.ctx.scope.matches(url):
            return None
        try:
            response = self.http.get(url, tag="oauth-discovery")
        except Exception:
            return None
        if self.missing(response) or response.status != 200:
            return None
        document = self.json_body(response)
        if not isinstance(document, dict) or "authorization_endpoint" not in document:
            return None
        metadata = OidcMetadata.from_document(document)
        issues = metadata.findings()
        if not issues:
            return None
        severity = Severity.HIGH if any("password" in item or "implicit" in item for item in issues) else Severity.MEDIUM
        return self.build_finding(
            title="Identity provider advertises risky OAuth settings",
            severity=severity,
            url=url,
            method="GET",
            description=" ".join(issues),
            impact=(
                "Weak flows and missing PKCE make code interception and token theft practical, "
                "especially for public or mobile clients registered with this provider."
            ),
            payload="",
            confidence=Confidence.CONFIRMED,
            cwe=("CWE-287",),
            tags=("auth", "oidc"),
            evidence=[self.capture(response, summary="OIDC discovery document with weak settings")],
            metadata={"metadata": metadata.to_dict(), "issues": issues},
        )
