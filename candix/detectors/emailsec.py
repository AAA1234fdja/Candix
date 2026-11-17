"""Email authentication records (SPF, DMARC, DKIM, MTA-STS)."""

from __future__ import annotations

import ipaddress
from typing import Iterable

from candix.core.finding import Finding
from candix.core.severity import Confidence, Severity
from candix.detectors.base import BaseDetector, DetectorMeta, register_detector
from candix.net.dns import txt_records


@register_detector
class EmailSecurityDetector(BaseDetector):
    meta = DetectorMeta(
        id="emailsec",
        name="Email authentication configuration",
        category="emailsec",
        description="Reads SPF, DMARC and MTA-STS records for the target domain and flags spoofable configurations.",
        severity=Severity.MEDIUM,
        cwe=("CWE-290", "CWE-345"),
        owasp=("A05:2021 Security Misconfiguration",),
        intrusive=False,
        tags=("dns", "email"),
        order=210,
        remediation_key="email",
    )

    def run(self) -> Iterable[Finding]:
        domains = {target.host for target in self.ctx.targets if _is_domain(target.host)}
        for domain in sorted(domains):
            finding = self._test(domain)
            if finding is not None:
                yield self.emit(finding)

    def _test(self, domain: str) -> Finding | None:
        try:
            root_txt = txt_records(domain)
            dmarc_txt = txt_records(f"_dmarc.{domain}")
            mta_sts = txt_records(f"_mta-sts.{domain}")
        except Exception:
            return None
        spf = next((record for record in root_txt if record.lower().startswith("v=spf1")), "")
        dmarc = next((record for record in dmarc_txt if record.lower().startswith("v=dmarc1")), "")
        issues: list[str] = []
        severity = Severity.MEDIUM
        if not spf:
            issues.append("no SPF record is published")
        elif "all" not in spf or spf.strip().endswith(("+all", "?all")):
            issues.append(f"SPF does not hard-fail (`{spf[:80]}`)")
            severity = Severity.HIGH
        if not dmarc:
            issues.append("no DMARC record is published")
        else:
            lowered = dmarc.lower()
            if "p=none" in lowered:
                issues.append("DMARC policy is p=none (monitor only)")
            if "sp=" not in lowered and "p=reject" not in lowered:
                issues.append("DMARC does not enforce rejection")
        if not mta_sts:
            issues.append("MTA-STS is not published")
        if not issues:
            return None
        return self.build_finding(
            title=f"Email authentication gaps for {domain}",
            severity=severity,
            url=f"dns:{domain}",
            method="DNS",
            description="; ".join(issues),
            impact=(
                "Missing or permissive records let an attacker send mail that appears to come from this domain, "
                "which is the basis of phishing and password-reset abuse against staff and customers."
            ),
            payload="",
            confidence=Confidence.CONFIRMED,
            cwe=("CWE-290",),
            tags=("email", "dns"),
            metadata={"domain": domain, "spf": spf, "dmarc": dmarc, "mta_sts": bool(mta_sts), "issues": issues},
        )


def _is_domain(host: str) -> bool:
    """Email records only exist for real DNS names, never for IP literals."""

    if not host or "." not in host:
        return False
    if host in {"localhost", "localhost.localdomain"}:
        return False
    try:
        ipaddress.ip_address(host)
        return False
    except ValueError:
        return True
