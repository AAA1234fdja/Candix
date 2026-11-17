"""HTTP security header and transport posture checks."""

from __future__ import annotations

import re
from typing import Iterable

from candix.core.finding import Finding
from candix.core.severity import Confidence, Severity
from candix.detectors.base import BaseDetector, DetectorMeta, register_detector
from candix.net.http import Response

_CSP_UNSAFE = ("unsafe-inline", "unsafe-eval", "unsafe-hashes", "*", "data:", "http:")
_REQUIRED_HEADERS = {
    "content-security-policy": (
        "Content-Security-Policy",
        Severity.MEDIUM,
        "The page can load or execute resources from arbitrary origins, which turns any injection into code execution.",
        "https://cwe.mitre.org/data/definitions/693.html",
    ),
    "x-content-type-options": (
        "X-Content-Type-Options",
        Severity.LOW,
        "Browsers may sniff responses as a different content type, enabling content-type confusion attacks.",
        "https://cwe.mitre.org/data/definitions/16.html",
    ),
    "referrer-policy": (
        "Referrer-Policy",
        Severity.LOW,
        "URLs and query strings may leak to third parties through the Referer header.",
        "https://cwe.mitre.org/data/definitions/200.html",
    ),
    "permissions-policy": (
        "Permissions-Policy",
        Severity.INFO,
        "Powerful browser features remain available to embedded content.",
        "https://cwe.mitre.org/data/definitions/16.html",
    ),
    "x-frame-options": (
        "X-Frame-Options",
        Severity.MEDIUM,
        "The page can be framed by an attacker, enabling clickjacking.",
        "https://cwe.mitre.org/data/definitions/1021.html",
    ),
}

_VERSION_HEADERS = ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator", "x-drupal-cache", "x-varnish")


@register_detector
class SecurityHeadersDetector(BaseDetector):
    meta = DetectorMeta(
        id="headers",
        name="Security headers and banner disclosure",
        category="headers",
        description="Checks response headers for missing security controls, weak CSP directives and version disclosure.",
        severity=Severity.LOW,
        cwe=("CWE-693", "CWE-1021", "CWE-200"),
        owasp=("A05:2021 Security Misconfiguration",),
        intrusive=False,
        tags=("passive", "configuration"),
        order=10,
        remediation_key="headers",
    )

    def run(self) -> Iterable[Finding]:
        seen: set[str] = set()
        for target in self.ctx.targets:
            if target.host in seen:
                continue
            seen.add(target.host)
            response = self.http.get(target.url, tag="headers-baseline")
            if self.missing(response):
                self.ctx.warn(f"headers: target unreachable: {target.url}")
                continue
            yield from self._analyse(target.url, response)

    def _analyse(self, url: str, response: Response) -> Iterable[Finding]:
        headers = {name.lower(): value for name, value in response.headers.items()}
        missing: list[str] = []
        for key, (display, severity, impact, cwe) in _REQUIRED_HEADERS.items():
            if key == "x-frame-options" and "content-security-policy" in headers and "frame-ancestors" in headers["content-security-policy"].lower():
                continue
            if key not in headers:
                missing.append(display)
        if "content-security-policy" not in headers and "content-security-policy-report-only" in headers:
            missing.append("Content-Security-Policy (report-only only)")
        if missing:
            evidence = self.capture(response, summary="Response missing security headers")
            yield self.emit(
                self.build_finding(
                    title="Missing HTTP security headers",
                    severity=Severity.LOW,
                    url=url,
                    location="header",
                    method="GET",
                    description=(
                        "The response does not set the following security headers: "
                        + ", ".join(missing)
                        + ". Missing headers remove defence-in-depth controls that limit the impact of "
                        "other vulnerabilities such as XSS and clickjacking."
                    ),
                    impact="Increased likelihood and impact of content injection, clickjacking and MIME confusion attacks.",
                    confidence=Confidence.CONFIRMED,
                    cwe=("CWE-693",),
                    tags=("headers", "configuration"),
                    evidence=[evidence],
                    metadata={"missing_headers": missing, "status": response.status},
                )
            )
        csp = headers.get("content-security-policy", "")
        if csp:
            weak = [token for token in _CSP_UNSAFE if token in csp.lower()]
            if weak:
                evidence = self.capture(response, summary="Weak Content-Security-Policy directives")
                yield self.emit(
                    self.build_finding(
                        title="Weak Content-Security-Policy allows unsafe sources",
                        severity=Severity.MEDIUM,
                        url=url,
                        location="header",
                        description=(
                            "The Content-Security-Policy contains permissive directives: "
                            + ", ".join(weak)
                            + ". These weaken the browser's ability to block injected scripts."
                        ),
                        impact="An XSS payload may execute despite the policy, and data exfiltration to third-party origins may be permitted.",
                        confidence=Confidence.CONFIRMED,
                        cwe=("CWE-693",),
                        tags=("headers", "csp"),
                        evidence=[evidence],
                        metadata={"csp": csp, "weak_tokens": weak},
                    )
                )
            if "default-src" not in csp.lower() and "script-src" not in csp.lower():
                yield self.emit(
                    self.build_finding(
                        title="Content-Security-Policy does not restrict scripts",
                        severity=Severity.MEDIUM,
                        url=url,
                        location="header",
                        description="The CSP does not define default-src or script-src, so script loading is unrestricted.",
                        impact="The policy provides little protection against injected scripts.",
                        confidence=Confidence.CONFIRMED,
                        cwe=("CWE-693",),
                        tags=("headers", "csp"),
                        evidence=[self.capture(response, summary="CSP without script restrictions")],
                    )
                )
        if url.startswith("https://") and "strict-transport-security" not in headers:
            yield self.emit(
                self.build_finding(
                    title="Missing HTTP Strict Transport Security",
                    severity=Severity.MEDIUM,
                    url=url,
                    location="header",
                    description="Responses over HTTPS do not set Strict-Transport-Security, so browsers may fall back to plaintext HTTP.",
                    impact="SSL stripping and cookie theft over downgraded connections become feasible on hostile networks.",
                    confidence=Confidence.CONFIRMED,
                    cwe=("CWE-319",),
                    tags=("headers", "tls"),
                    evidence=[self.capture(response, summary="No HSTS header on HTTPS response")],
                )
            )
        elif "strict-transport-security" in headers:
            hsts = headers["strict-transport-security"].lower()
            match = re.search(r"max-age=(\d+)", hsts)
            if not match or int(match.group(1)) < 15552000:
                yield self.emit(
                    self.build_finding(
                        title="HTTP Strict Transport Security max-age is too short",
                        severity=Severity.LOW,
                        url=url,
                        location="header",
                        description=f"The HSTS policy is '{headers['strict-transport-security']}', below the recommended minimum of 15552000 seconds (180 days).",
                        impact="Short HSTS windows leave users exposed to downgrade attacks between visits.",
                        confidence=Confidence.CONFIRMED,
                        cwe=("CWE-319",),
                        tags=("headers", "tls"),
                        evidence=[self.capture(response, summary="Short HSTS max-age")],
                    )
                )
        for name in _VERSION_HEADERS:
            value = headers.get(name)
            if value and _looks_versioned(value):
                yield self.emit(
                    self.build_finding(
                        title=f"Version disclosure in {name} header",
                        severity=Severity.LOW,
                        url=url,
                        location="header",
                        description=f"The {name} header discloses the deployed software version: {value}.",
                        impact="Attackers can map the exact component version to known vulnerabilities, reducing reconnaissance cost.",
                        confidence=Confidence.CONFIRMED,
                        cwe=("CWE-200",),
                        tags=("headers", "fingerprint"),
                        evidence=[self.capture(response, summary=f"Version disclosed via {name}")],
                        metadata={"header": name, "value": value},
                    )
                )


def _looks_versioned(value: str) -> bool:
    return bool(re.search(r"\d+\.\d+", value)) or bool(
        re.search(r"(?:nginx|apache|iis|express|php|asp\.net|tomcat|jetty|gunicorn|werkzeug)", value, re.IGNORECASE)
    )
