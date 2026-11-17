"""LDAP injection."""

from __future__ import annotations

from typing import Iterable

from candix.core.endpoint import Endpoint, Param
from candix.core.finding import Finding
from candix.core.severity import Confidence, Severity
from candix.detectors.base import BaseDetector, DetectorMeta, register_detector

_HINTS = ("user", "username", "login", "uid", "cn", "dn", "filter", "search", "account", "email", "group", "role")


@register_detector
class LdapDetector(BaseDetector):
    meta = DetectorMeta(
        id="ldap",
        name="LDAP injection",
        category="ldap",
        description="Injects filter metacharacters into identity-like parameters and looks for authentication or filter bypass.",
        severity=Severity.HIGH,
        cwe=("CWE-90",),
        owasp=("A03:2021 Injection",),
        intrusive=True,
        tags=("injection", "directory"),
        order=135,
        remediation_key="ldap",
    )

    def run(self) -> Iterable[Finding]:
        for endpoint in self.endpoints():
            for param in self.params_for(endpoint):
                if not any(hint in param.name.lower() for hint in _HINTS):
                    continue
                finding = self._test(endpoint, param)
                if finding is not None:
                    yield self.emit(finding)

    def _test(self, endpoint: Endpoint, param: Param) -> Finding | None:
        baseline_value = param.value or "candix"
        try:
            baseline = self.send(endpoint, {param.name: baseline_value}, tag="ldap-baseline")
        except Exception:
            return None
        if self.missing(baseline):
            return None
        for payload in ("*", "*)(&", "admin*", "*)(uid=*))(|(uid=*", "x)(|(cn=*"):
            try:
                response = self.send(endpoint, {param.name: payload}, tag="ldap-probe")
            except Exception:
                continue
            if self.missing(response):
                continue
            changed = response.status != baseline.status or abs(response.size - baseline.size) > max(48, baseline.size // 10)
            error = any(token in response.text.lower() for token in ("ldap", "invalid dn", "protocol error", "filter"))
            if not (changed and (error or response.status == 200)):
                continue
            control = self.send(endpoint, {param.name: "candix-no-match-zz"}, tag="ldap-control")
            if control is not None and control.status == response.status and abs(control.size - response.size) < 32:
                continue
            return self.build_finding(
                title="LDAP injection",
                severity=Severity.HIGH,
                url=endpoint.url,
                method=endpoint.method,
                parameter=param.name,
                location=param.location,
                description=(
                    f"The wildcard/filter payload {payload!r} changed the directory lookup result "
                    f"(HTTP {baseline.status} -> {response.status}, {baseline.size} -> {response.size} bytes)."
                ),
                impact="Authentication bypass or disclosure of directory entries, depending on how the filter is built.",
                payload=payload,
                confidence=Confidence.LIKELY,
                cwe=("CWE-90",),
                tags=("ldap",),
                evidence=[self.capture(response, summary="Directory response changed after filter injection", control=baseline)],
                metadata={"control_status": control.status if control else None},
            )
        return None
