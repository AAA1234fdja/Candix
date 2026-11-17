"""Administrative interfaces reachable without authentication."""

from __future__ import annotations

from typing import Iterable

from candix.core.finding import Finding
from candix.core.severity import Confidence, Severity
from candix.detectors.base import BaseDetector, DetectorMeta, register_detector
from candix.net.url import join_url

_ADMIN_PATHS = (
    "/admin",
    "/admin/",
    "/administrator",
    "/admin/login",
    "/wp-admin/",
    "/phpmyadmin/",
    "/manager/html",
    "/console",
    "/jenkins",
    "/adminer.php",
    "/_admin",
    "/backoffice",
    "/dashboard",
    "/manage",
)

_LOGIN_MARKERS = ("password", "login", "sign in", "username")
_DASHBOARD_MARKERS = ("dashboard", "logout", "sign out", "users", "settings", "admin")


@register_detector
class AdminPanelDetector(BaseDetector):
    meta = DetectorMeta(
        id="adminpanel",
        name="Exposed administrative interface",
        category="adminpanel",
        description="Probes common admin prefixes and classifies the response as login-protected or already authenticated.",
        severity=Severity.MEDIUM,
        cwe=("CWE-284", "CWE-668"),
        owasp=("A05:2021 Security Misconfiguration",),
        intrusive=False,
        tags=("exposure", "admin"),
        order=35,
        remediation_key="access",
    )

    def run(self) -> Iterable[Finding]:
        for target in self.ctx.targets:
            findings = list(self._test(target.base_url))
            for finding in findings[:2]:
                yield self.emit(finding)

    def _test(self, base_url: str) -> Iterable[Finding]:
        for path in _ADMIN_PATHS:
            url = join_url(base_url, path).render()
            if self.ctx.scope is not None and not self.ctx.scope.matches(url):
                continue
            try:
                response = self.http.get(url, tag="admin")
            except Exception:
                continue
            if self.missing(response) or response.status not in {200, 401, 403}:
                continue
            if url == base_url.rstrip("/") + "/":
                continue
            lowered = response.text.lower()
            if response.status in {401, 403}:
                if any(marker in lowered for marker in _LOGIN_MARKERS):
                    continue
                yield self.build_finding(
                    title=f"Administrative path responds at {path}",
                    severity=Severity.LOW,
                    url=url,
                    method="GET",
                    description=f"{path} returns HTTP {response.status}; the path exists and may be worth brute-force monitoring.",
                    impact="Enumeration of administrative surfaces helps attackers focus credential attacks.",
                    payload=path,
                    confidence=Confidence.LIKELY,
                    cwe=("CWE-668",),
                    tags=("exposure", "admin"),
                    evidence=[self.capture(response, summary=f"Admin path returned {response.status}")],
                    metadata={"path": path, "status": response.status},
                )
                continue
            dashboard = [marker for marker in _DASHBOARD_MARKERS if marker in lowered]
            login = [marker for marker in _LOGIN_MARKERS if marker in lowered]
            if not dashboard:
                continue
            if login and not any(marker in lowered for marker in ("logout", "sign out")):
                yield self.build_finding(
                    title=f"Administrative login exposed at {path}",
                    severity=Severity.LOW,
                    url=url,
                    method="GET",
                    description=f"{path} serves an administrative login form without network restrictions.",
                    impact="The panel is reachable from the internet, so credential attacks and product-specific flaws apply.",
                    payload=path,
                    confidence=Confidence.LIKELY,
                    cwe=("CWE-284",),
                    tags=("exposure", "admin"),
                    evidence=[self.capture(response, summary="Admin login form is reachable")],
                    metadata={"path": path, "markers": login},
                )
            elif "logout" in lowered or "sign out" in lowered:
                yield self.build_finding(
                    title=f"Administrative dashboard reachable without authentication at {path}",
                    severity=Severity.HIGH,
                    url=url,
                    method="GET",
                    description=f"{path} returned dashboard content including logout or user management controls.",
                    impact="Direct administrative access allows configuration changes and data export without credentials.",
                    payload=path,
                    confidence=Confidence.LIKELY,
                    cwe=("CWE-284",),
                    tags=("exposure", "admin"),
                    evidence=[self.capture(response, summary="Dashboard content served anonymously")],
                    metadata={"path": path, "markers": dashboard[:5]},
                )
