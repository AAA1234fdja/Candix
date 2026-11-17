"""Outdated and end-of-life components detected by fingerprinting."""

from __future__ import annotations

from typing import Iterable

from candix.catalog.advisories import advisories_for
from candix.core.finding import Finding
from candix.core.severity import Confidence, Severity
from candix.detectors.base import BaseDetector, DetectorMeta, register_detector
from candix.recon.tech import fingerprint_response

_SEVERITY = {"critical": Severity.CRITICAL, "high": Severity.HIGH, "medium": Severity.MEDIUM, "low": Severity.LOW}


@register_detector
class OutdatedComponentDetector(BaseDetector):
    meta = DetectorMeta(
        id="dependency",
        name="Outdated software components",
        category="dependency",
        description="Matches fingerprinted component versions against the local advisory table and reports unsupported or vulnerable releases.",
        severity=Severity.MEDIUM,
        cwe=("CWE-1104", "CWE-1035"),
        owasp=("A06:2021 Vulnerable and Outdated Components",),
        intrusive=False,
        tags=("fingerprint", "dependency"),
        order=165,
        remediation_key="dependency",
    )

    def run(self) -> Iterable[Finding]:
        for target in self.ctx.targets:
            try:
                response = self.http.get(target.url, tag="dependency")
            except Exception:
                continue
            if self.missing(response):
                continue
            fingerprint = fingerprint_response(response)
            for technology in fingerprint.technologies:
                if not technology.version:
                    continue
                for advisory in advisories_for(technology.name, technology.version):
                    severity = _SEVERITY.get(advisory.severity, Severity.MEDIUM)
                    yield self.emit(
                        self.build_finding(
                            title=f"Outdated {technology.name} {technology.version}",
                            severity=severity,
                            url=target.url,
                            location="config",
                            description=(
                                f"{technology.name} {technology.version} is older than the advised "
                                f"{advisory.fixed_version}. {advisory.summary}"
                            ),
                            impact="Known defects in the deployed version may be exploitable without authentication.",
                            confidence=Confidence.LIKELY,
                            cwe=tuple(item.replace("CWE-", "CWE-") for item in advisory.cwe),
                            tags=("dependency", technology.name.lower().replace(" ", "-")),
                            evidence=[
                                self.capture(
                                    response,
                                    summary=f"Fingerprint indicates {technology.name} {technology.version}",
                                    kind="artifact",
                                    data={"technology": technology.to_dict(), "advisory": advisory.to_dict()},
                                )
                            ],
                            references=[advisory.reference] if advisory.reference else [],
                            metadata={"component": technology.name, "version": technology.version, "fixed": advisory.fixed_version},
                        )
                    )
