"""Spring Boot Actuator exposure."""

from __future__ import annotations

from typing import Iterable

from candix.analysis.entropy import scan_for_secrets
from candix.core.finding import Finding
from candix.core.severity import Confidence, Severity
from candix.detectors.base import BaseDetector, DetectorMeta, register_detector
from candix.net.url import join_url

_ENDPOINTS = (
    ("/actuator", ("_links", "self", "health")),
    ("/actuator/env", ("propertySources", "systemProperties", "activeProfiles")),
    ("/actuator/heapdump", ("JAVA PROFILE",)),
    ("/actuator/threaddump", ("threadName", "threadState")),
    ("/actuator/mappings", ("dispatcherServlets", "requestMappingConditions")),
    ("/actuator/beans", ("beans", "singleton")),
    ("/actuator/configprops", ("contexts", "properties")),
    ("/actuator/loggers", ("loggers", "configuredLevel")),
    ("/trace", ("traces", "timestamp")),
    ("/env", ("propertySources",)),
)


@register_detector
class ActuatorDetector(BaseDetector):
    meta = DetectorMeta(
        id="actuator",
        name="Exposed Spring Boot Actuator endpoints",
        category="actuator",
        description="Requests common Actuator paths and confirms the response shape of a live management endpoint.",
        severity=Severity.HIGH,
        cwe=("CWE-200", "CWE-497"),
        owasp=("A05:2021 Security Misconfiguration",),
        intrusive=False,
        tags=("exposure", "java", "spring"),
        order=40,
        remediation_key="debug",
    )

    def run(self) -> Iterable[Finding]:
        for target in self.ctx.targets:
            for path, needles in _ENDPOINTS:
                finding = self._test(target.base_url, path, needles)
                if finding is not None:
                    yield self.emit(finding)

    def _test(self, base_url: str, path: str, needles: tuple[str, ...]) -> Finding | None:
        url = join_url(base_url, path).render()
        if self.ctx.scope is not None and not self.ctx.scope.matches(url):
            return None
        try:
            response = self.http.get(url, tag="actuator")
        except Exception:
            return None
        if self.missing(response) or response.status != 200:
            return None
        text = response.text
        lowered = text.lower()
        if "<html" in lowered[:400] and "whitelabel" in lowered:
            return None
        matched = [needle for needle in needles if needle.lower() in lowered]
        if not matched:
            return None
        severity = Severity.HIGH
        if path.endswith(("env", "/env", "heapdump", "configprops")):
            severity = Severity.CRITICAL
        secrets = scan_for_secrets(text)
        detail = "Actuator endpoint is reachable and returned expected fields: " + ", ".join(matched[:4])
        if secrets:
            detail += f". The response also exposed {len(secrets)} secret-like value(s)."
        return self.build_finding(
            title=f"Spring Boot Actuator exposed at {path}",
            severity=severity,
            url=url,
            method="GET",
            description=detail,
            impact=(
                "Actuator endpoints disclose configuration, environment variables and thread state; "
                "some versions also allow changing log levels or shutting the application down."
            ),
            payload=path,
            confidence=Confidence.CONFIRMED,
            cwe=("CWE-200",),
            tags=("exposure", "spring"),
            evidence=[self.capture(response, summary=f"Actuator fields matched: {', '.join(matched[:4])}")],
            metadata={"path": path, "matched": matched, "secrets": len(secrets)},
        )
