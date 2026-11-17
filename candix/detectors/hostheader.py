"""Host header injection and routing header trust."""

from __future__ import annotations

from typing import Iterable

from candix.core.finding import Finding
from candix.core.severity import Confidence, Severity
from candix.detectors.base import BaseDetector, DetectorMeta, register_detector
from candix.net.url import URL

_EVIL = "candix-host-header.test"


@register_detector
class HostHeaderDetector(BaseDetector):
    meta = DetectorMeta(
        id="hostheader",
        name="Host header injection",
        category="hostheader",
        description="Sends spoofed Host and X-Forwarded-Host values and checks whether they are reflected or trusted.",
        severity=Severity.MEDIUM,
        cwe=("CWE-644", "CWE-20"),
        owasp=("A05:2021 Security Misconfiguration",),
        intrusive=True,
        tags=("headers", "routing"),
        order=115,
        remediation_key="hostheader",
    )

    def run(self) -> Iterable[Finding]:
        for target in self.ctx.targets:
            try:
                baseline = self.http.get(target.url, tag="host-baseline")
            except Exception:
                continue
            if self.missing(baseline):
                continue
            tests = [
                ({"Host": _EVIL}, "Host"),
                ({"X-Forwarded-Host": _EVIL}, "X-Forwarded-Host"),
                ({"X-Forwarded-Host": f"{_EVIL}:443"}, "X-Forwarded-Host with port"),
                ({"X-Original-URL": "/candix-admin-probe"}, "X-Original-URL"),
            ]
            for headers, label in tests:
                try:
                    response = self.http.get(target.url, headers=headers, tag="host-probe")
                except Exception:
                    continue
                if self.missing(response):
                    continue
                reflected = _EVIL in response.text or _EVIL in response.header("Location")
                bypass = False
                if "X-Original-URL" in label:
                    bypass = response.status == 200 and response.size != baseline.size and "admin" in response.text.lower()
                if not reflected and not bypass:
                    continue
                yield self.emit(
                    self.build_finding(
                        title="Host header value is trusted and reflected",
                        severity=Severity.MEDIUM,
                        url=target.url,
                        location="header",
                        description=(
                            f"Supplying {label}: {_EVIL} caused the value to appear in the response"
                            + (" and changed the response body." if bypass else ".")
                        ),
                        impact=(
                            "Password-reset links and absolute URLs can be poisoned to point at an attacker, "
                            "enabling account takeover. Cache poisoning may also be possible."
                        ),
                        confidence=Confidence.CONFIRMED,
                        cwe=("CWE-644",),
                        tags=("host-header", "routing"),
                        evidence=[self.capture(response, summary=f"{label} reflected in the response", control=baseline)],
                        metadata={"header": label, "value": _EVIL, "bypass": bypass},
                    )
                )
                break
