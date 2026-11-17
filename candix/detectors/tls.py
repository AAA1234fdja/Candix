"""TLS configuration checks."""

from __future__ import annotations

from typing import Iterable

from candix.core.finding import Finding
from candix.core.severity import Confidence, Severity
from candix.detectors.base import BaseDetector, DetectorMeta, register_detector
from candix.net.tls import inspect_tls
from candix.net.url import URL


@register_detector
class TlsDetector(BaseDetector):
    meta = DetectorMeta(
        id="tls",
        name="TLS configuration and certificate health",
        category="tls",
        description="Tests protocol versions, cipher negotiation, certificate validity and self-signed certificates.",
        severity=Severity.MEDIUM,
        cwe=("CWE-326", "CWE-327", "CWE-295"),
        owasp=("A02:2021 Cryptographic Failures",),
        intrusive=False,
        tags=("tls", "cryptography"),
        order=30,
        remediation_key="tls",
    )

    def run(self) -> Iterable[Finding]:
        seen: set[str] = set()
        for target in self.ctx.targets:
            parsed = URL.parse(target.url)
            if parsed.scheme != "https":
                continue
            key = f"{parsed.host}:{parsed.effective_port}"
            if key in seen:
                continue
            seen.add(key)
            if self.ctx.scope is not None and not self.ctx.scope.matches(target.url):
                continue
            report = inspect_tls(parsed.host, parsed.effective_port or 443, timeout=self.request_timeout())
            if report.error:
                self.logger.debug("TLS inspection failed", host=key, error=report.error)
                continue
            if report.weak_protocols:
                yield self.emit(
                    self.build_finding(
                        title="Legacy TLS protocol versions enabled",
                        severity=Severity.MEDIUM if "TLSv1" in report.weak_protocols else Severity.HIGH,
                        url=target.url,
                        location="config",
                        description=(
                            f"The endpoint negotiated deprecated protocol versions: {', '.join(report.weak_protocols)}. "
                            f"Preferred configuration: {report.preferred_version} with {report.preferred_cipher}."
                        ),
                        impact="Legacy TLS versions have known cryptographic weaknesses that enable downgrade and decryption attacks.",
                        confidence=Confidence.CONFIRMED,
                        cwe=("CWE-326", "CWE-327"),
                        tags=("tls", "protocol"),
                        evidence=[
                            self.capture(
                                self.http.get(target.url, tag="tls-evidence"),
                                summary="TLS handshake metadata",
                                kind="tls",
                                data=report.to_dict(),
                            )
                        ],
                        metadata=report.to_dict(),
                    )
                )
            certificate = report.certificate
            if certificate is None:
                continue
            if certificate.expired:
                yield self.emit(
                    self.build_finding(
                        title="TLS certificate expired",
                        severity=Severity.HIGH,
                        url=target.url,
                        location="config",
                        description=f"The certificate expired {abs(certificate.days_remaining)} days ago ({certificate.not_after}).",
                        impact="Browsers and API clients reject the connection, and users are trained to click through warnings.",
                        confidence=Confidence.CONFIRMED,
                        cwe=("CWE-298",),
                        tags=("tls", "certificate"),
                        metadata=certificate.to_dict(),
                    )
                )
            elif certificate.expiring_soon:
                yield self.emit(
                    self.build_finding(
                        title="TLS certificate expires soon",
                        severity=Severity.LOW,
                        url=target.url,
                        location="config",
                        description=f"The certificate expires in {certificate.days_remaining} days ({certificate.not_after}).",
                        impact="An outage is likely unless renewal automation is working.",
                        confidence=Confidence.CONFIRMED,
                        cwe=("CWE-298",),
                        tags=("tls", "certificate"),
                        metadata=certificate.to_dict(),
                    )
                )
            if certificate.self_signed:
                yield self.emit(
                    self.build_finding(
                        title="Self-signed TLS certificate",
                        severity=Severity.MEDIUM,
                        url=target.url,
                        location="config",
                        description=f"The certificate is self-signed (subject equals issuer: {certificate.subject}).",
                        impact="Clients cannot verify the server identity, enabling man-in-the-middle attacks.",
                        confidence=Confidence.CONFIRMED,
                        cwe=("CWE-295",),
                        tags=("tls", "certificate"),
                        metadata=certificate.to_dict(),
                    )
                )
