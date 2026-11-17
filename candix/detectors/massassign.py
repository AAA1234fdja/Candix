"""Mass assignment / excessive data binding."""

from __future__ import annotations

import json
from typing import Iterable

from candix.core.endpoint import Endpoint
from candix.core.finding import Finding
from candix.core.severity import Confidence, Severity
from candix.detectors.base import BaseDetector, DetectorMeta, register_detector

_PRIVILEGED_FIELDS = {
    "role": "admin",
    "roles": ["admin"],
    "is_admin": True,
    "isadmin": True,
    "admin": True,
    "is_staff": True,
    "is_superuser": True,
    "permissions": ["*"],
    "verified": True,
    "email_verified": True,
    "balance": 999999,
    "credit": 999999,
    "tenant_id": 1,
    "org_id": 1,
    "active": True,
    "status": "active",
}


@register_detector
class MassAssignmentDetector(BaseDetector):
    meta = DetectorMeta(
        id="massassign",
        name="Mass assignment of privileged fields",
        category="massassign",
        description="Adds privileged properties to JSON request bodies and checks whether they are accepted or reflected.",
        severity=Severity.HIGH,
        cwe=("CWE-915",),
        owasp=("A01:2021 Broken Access Control",),
        intrusive=True,
        tags=("api", "access-control"),
        order=175,
        remediation_key="massassign",
    )

    def run(self) -> Iterable[Finding]:
        for endpoint in self.ctx.endpoints:
            if endpoint.method.upper() not in {"POST", "PUT", "PATCH"}:
                continue
            if not (endpoint.body and endpoint.body.kind == "json"):
                continue
            finding = self._test(endpoint)
            if finding is not None:
                yield self.emit(finding)

    def _test(self, endpoint: Endpoint) -> Finding | None:
        original = endpoint.body.json if endpoint.body else None
        if not isinstance(original, dict):
            return None
        baseline = dict(original)
        try:
            baseline_response = self.http.request_endpoint(endpoint, tag="massassign-baseline")
        except Exception:
            return None
        for field, value in list(_PRIVILEGED_FIELDS.items())[:8]:
            mutated = dict(baseline)
            mutated[field] = value
            try:
                response = self.http.request(json_body=mutated, method=endpoint.method, url=endpoint.url, headers=endpoint.headers, tag="massassign")
            except Exception:
                continue
            if self.missing(response) or response.status >= 400:
                continue
            data = response.try_json()
            accepted = False
            if isinstance(data, dict):
                blob = json.dumps(data).lower()
                accepted = field in blob and str(value).lower() in blob
            if not accepted and response.status == 200 and response.text != baseline_response.text:
                accepted = field in response.text.lower()
            if not accepted:
                continue
            control = self.http.request(json_body={**baseline, field: "candix-value"}, method=endpoint.method, url=endpoint.url, headers=endpoint.headers, tag="massassign-control")
            if control is not None and str(value).lower() in control.text.lower() and str(value).lower() not in baseline_response.text.lower():
                continue
            return self.build_finding(
                title="Mass assignment accepts privileged fields",
                severity=Severity.HIGH,
                url=endpoint.url,
                method=endpoint.method,
                location="body",
                description=(
                    f"Adding the field '{field}' with value {value!r} to the JSON body was accepted and "
                    "reflected by the API, indicating the server binds request properties directly to the model."
                ),
                impact="An attacker can set roles, ownership, verification flags or balances they should not control.",
                payload=json.dumps({field: value}),
                confidence=Confidence.LIKELY,
                cwe=("CWE-915",),
                tags=("mass-assignment", "api"),
                evidence=[
                    self.capture(response, summary=f"Privileged field {field!r} accepted", control=baseline_response),
                    self.capture(control, summary="Control value did not reproduce the privileged value"),
                ],
                metadata={"field": field, "value": value},
            )
        return None
