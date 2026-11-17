"""Web cache poisoning via unkeyed input."""

from __future__ import annotations

from typing import Iterable

from candix.core.finding import Finding
from candix.core.severity import Confidence, Severity
from candix.detectors.base import BaseDetector, DetectorMeta, register_detector

_POISON_HEADERS = (
    ("X-Forwarded-Host", "candix-cache-poison.test"),
    ("X-Forwarded-Scheme", "http"),
    ("X-Original-URL", "/candix-poison"),
    ("X-Rewrite-URL", "/candix-poison"),
)


@register_detector
class CachePoisoningDetector(BaseDetector):
    meta = DetectorMeta(
        id="cache",
        name="Web cache poisoning",
        category="cache",
        description="Sends unkeyed routing headers, then re-requests the clean URL to see whether the poisoned response was cached.",
        severity=Severity.HIGH,
        cwe=("CWE-524", "CWE-525"),
        owasp=("A05:2021 Security Misconfiguration",),
        intrusive=True,
        tags=("cache", "headers"),
        order=120,
        remediation_key="cache",
    )

    def run(self) -> Iterable[Finding]:
        for target in self.ctx.targets:
            base = target.url.split("?")[0]
            cache_buster = f"candixcb={self.marker('cb')}"
            probe_url = f"{base}?{cache_buster}"
            try:
                clean = self.http.get(probe_url, tag="cache-clean")
            except Exception:
                continue
            if self.missing(clean) or clean.header("X-Cache", "").lower() not in {"hit", "miss"} and "cf-cache-status" not in {k.lower() for k, _ in clean.headers.items()}:
                # Without cache indicators, poisoning cannot be confirmed
                # reliably; a single reflection is not enough evidence.
                continue
            for header, value in _POISON_HEADERS:
                try:
                    poisoned = self.http.get(probe_url, headers={header: value}, tag="cache-poison")
                    verification = self.http.get(probe_url, tag="cache-verify")
                except Exception:
                    continue
                if self.missing(poisoned) or self.missing(verification):
                    continue
                if value in verification.text and value not in clean.text:
                    yield self.emit(
                        self.build_finding(
                            title="Web cache poisoning via unkeyed header",
                            severity=Severity.HIGH,
                            url=probe_url,
                            location="header",
                            description=(
                                f"Setting {header}: {value} on one request changed the response served to a "
                                "subsequent clean request, proving the header is not part of the cache key."
                            ),
                            impact=(
                                "An attacker can serve malicious content or redirects to all users of the "
                                "affected cache entry."
                            ),
                            confidence=Confidence.CONFIRMED,
                            cwe=("CWE-524",),
                            tags=("cache", "poisoning"),
                            evidence=[
                                self.capture(poisoned, summary="Poisoned response", control=clean),
                                self.capture(verification, summary="Clean request served the poisoned response"),
                            ],
                            vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N",
                            metadata={"header": header, "value": value},
                        )
                    )
                    break
