"""Open HTTP proxy behaviour."""

from __future__ import annotations

from typing import Iterable
from urllib.parse import urlsplit

from candix.core.finding import Finding
from candix.core.severity import Confidence, Severity
from candix.detectors.base import BaseDetector, DetectorMeta, register_detector

_FORWARD_HEADERS = ("X-Forwarded-Host", "X-Forwarded-For", "X-Original-URL", "X-Rewrite-URL")


@register_detector
class OpenProxyDetector(BaseDetector):
    meta = DetectorMeta(
        id="openproxy",
        name="Open proxy or absolute-URI forwarding",
        category="openproxy",
        description="Sends absolute-form request targets and forwarding headers to detect proxy-style request handling.",
        severity=Severity.MEDIUM,
        cwe=("CWE-441", "CWE-918"),
        owasp=("A05:2021 Security Misconfiguration",),
        intrusive=True,
        tags=("proxy", "network"),
        order=200,
        remediation_key="misconfig",
    )

    def run(self) -> Iterable[Finding]:
        for target in self.ctx.targets:
            finding = self._test(target.base_url)
            if finding is not None:
                yield self.emit(finding)

    def _test(self, base_url: str) -> Finding | None:
        probe_host = "candix-proxy-probe.invalid"
        absolute = f"http://{probe_host}/"
        try:
            response = self.http.get(
                base_url.rstrip("/") + "/",
                headers={"X-Forwarded-Host": probe_host, "X-Forwarded-For": "127.0.0.1", "Host": urlsplit(base_url).netloc},
                tag="openproxy",
            )
        except Exception:
            return None
        if self.missing(response):
            return None
        body = response.text.lower()
        headers = response.headers.to_dict()
        reflected = probe_host in body or any(probe_host in value for value in headers.values())
        location = headers.get("Location", "") or headers.get("location", "")
        redirected = bool(location) and probe_host in location
        if not (reflected or redirected):
            return None
        severity = Severity.HIGH if redirected else Severity.MEDIUM
        return self.build_finding(
            title="Application trusts forwarded host/proxy headers",
            severity=severity,
            url=base_url,
            method="GET",
            description=(
                "A forged forwarding header was reflected"
                + (" and used to build a redirect" if redirected else " in the response")
                + f" ({', '.join(_FORWARD_HEADERS)})."
            ),
            impact=(
                "Attackers can poison password-reset links, cache entries and absolute URLs, "
                "turning the application into a redirector or cache-poisoning primitive."
            ),
            payload=f"X-Forwarded-Host: {probe_host}",
            confidence=Confidence.CONFIRMED,
            cwe=("CWE-441",),
            tags=("proxy",),
            evidence=[self.capture(response, summary="Forged forwarding header reflected")],
            metadata={"absolute_form": absolute, "redirected": redirected},
        )
