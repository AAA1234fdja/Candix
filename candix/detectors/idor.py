"""Insecure direct object references and horizontal privilege escalation."""

from __future__ import annotations

import re
from typing import Iterable

from candix.core.endpoint import Endpoint, Param
from candix.core.finding import Finding
from candix.core.severity import Confidence, Severity
from candix.detectors.base import BaseDetector, DetectorMeta, register_detector
from candix.net.http import Response

_ID_PARAMS = ("id", "user_id", "account_id", "order_id", "item_id", "post_id", "profile_id", "uid", "pid", "document_id", "invoice_id")
_SENSITIVE_FIELDS = ("email", "phone", "address", "token", "api_key", "ssn", "password", "hash", "balance", "card", "iban")


@register_detector
class IdorDetector(BaseDetector):
    meta = DetectorMeta(
        id="idor",
        name="Insecure direct object reference",
        category="idor",
        description="Enumerates adjacent object identifiers and flags responses that disclose another record to the same caller.",
        severity=Severity.HIGH,
        cwe=("CWE-639", "CWE-284"),
        owasp=("A01:2021 Broken Access Control",),
        intrusive=True,
        tags=("access-control", "enumeration"),
        order=100,
        remediation_key="idor",
    )

    def run(self) -> Iterable[Finding]:
        for endpoint in self.endpoints():
            for param in self.params_for(endpoint):
                if not self._interesting(param):
                    continue
                finding = self._test(endpoint, param)
                if finding is not None:
                    yield self.emit(finding)

    def _interesting(self, param: Param) -> bool:
        name = param.name.lower()
        if name in _ID_PARAMS:
            return True
        return bool(re.fullmatch(r"\d{1,8}", (param.value or "").strip())) and name.endswith(("id", "_id"))

    def _test(self, endpoint: Endpoint, param: Param) -> Finding | None:
        try:
            original_value = int(param.value or "1")
        except ValueError:
            original_value = 1
        candidates = [value for value in (original_value + 1, original_value - 1, 2, 1, 3, 100) if value != original_value and value > 0]
        try:
            baseline = self.send(endpoint, {param.name: str(original_value)}, tag="idor-baseline")
        except Exception:
            return None
        if self.missing(baseline) or baseline.status != 200:
            return None
        random_probe = self.send(endpoint, {param.name: "99999999"}, tag="idor-404")
        if random_probe is not None and random_probe.status == 200:
            # The endpoint returns 200 for unknown identifiers, so status alone
            # cannot distinguish records.
            return None
        for candidate in candidates:
            try:
                response = self.send(endpoint, {param.name: str(candidate)}, tag="idor-probe")
            except Exception:
                continue
            if self.missing(response) or response.status != 200:
                continue
            if response.text == baseline.text:
                continue
            verdict = self._discloses_other(response, baseline, candidate)
            if verdict is None:
                continue
            detail, sensitivity = verdict
            severity = Severity.HIGH if sensitivity == "high" else Severity.MEDIUM
            return self.build_finding(
                title="Insecure direct object reference",
                severity=severity,
                url=endpoint.url,
                method=endpoint.method,
                parameter=param.name,
                location=param.location,
                description=(
                    f"Changing '{param.name}' from {original_value} to {candidate} returned a different "
                    f"record to the same unauthenticated caller. {detail}"
                ),
                impact=(
                    "An attacker can enumerate identifiers to read or modify other users' data, "
                    "including personal information and account details."
                ),
                payload=str(candidate),
                confidence=Confidence.LIKELY,
                cwe=("CWE-639",),
                tags=("idor", "access-control", sensitivity),
                evidence=[
                    self.capture(response, summary=f"Record {candidate} disclosed to the same caller", control=baseline),
                    self.capture(random_probe, summary="Unknown identifier returns 404, confirming enumeration"),
                ],
                vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                metadata={"original": original_value, "accessed": candidate, "sensitivity": sensitivity},
            )
        return None

    def _discloses_other(self, response: Response, baseline: Response, candidate: int) -> tuple[str, str] | None:
        body = response.text
        lowered = body.lower()
        identifiers = set(re.findall(r'"(?:id|user_id|account_id)"\s*:\s*(\d+)', body))
        identifiers.update(re.findall(r"\bid=(\d+)", body))
        if identifiers and str(candidate) not in identifiers:
            return None
        sensitive = [field for field in _SENSITIVE_FIELDS if field in lowered]
        if sensitive:
            return (f"The response exposed fields: {', '.join(sorted(set(sensitive))[:5])}.", "high")
        if "email" in lowered and "@" in body and "@" not in baseline.text:
            return ("A different email address was returned.", "high")
        if identifiers:
            return (f"The response belongs to object {candidate}.", "medium")
        return None
