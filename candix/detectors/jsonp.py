"""JSONP-style callbacks that leak data across origins."""

from __future__ import annotations

import re
from typing import Iterable

from candix.core.finding import Finding
from candix.core.severity import Confidence, Severity
from candix.detectors.base import BaseDetector, DetectorMeta, register_detector

_CALLBACK_PARAMS = ("callback", "jsonp", "jsonpcallback", "cb", "json_callback")
_JSONP_RE = re.compile(r"^\s*([A-Za-z_$][\w$.]{0,64})\s*\(\s*[\[{]", re.DOTALL)


@register_detector
class JsonpDetector(BaseDetector):
    meta = DetectorMeta(
        id="jsonp",
        name="JSONP callback accepted on sensitive data",
        category="jsonp",
        description="Supplies a callback parameter to JSON endpoints and checks whether the response is wrapped.",
        severity=Severity.MEDIUM,
        cwe=("CWE-79", "CWE-200"),
        owasp=("A03:2021 Injection",),
        intrusive=True,
        tags=("api", "browser"),
        order=68,
        remediation_key="jsonp",
    )

    def run(self) -> Iterable[Finding]:
        for endpoint in self.endpoints():
            if self.missing_type(endpoint.response_hint):
                continue
            for name in _CALLBACK_PARAMS:
                finding = self._test(endpoint, name)
                if finding is not None:
                    yield self.emit(finding)
                    break

    def missing_type(self, hint: object) -> bool:
        if not isinstance(hint, dict):
            return True
        content_type = str(hint.get("content_type", "")).lower()
        return "html" in content_type and "json" not in content_type

    def _test(self, endpoint: object, name: str) -> Finding | None:
        marker = self.marker("jp")
        payload = f"{marker}Callback"
        try:
            response = self.send(endpoint, {name: payload}, tag="jsonp")
        except Exception:
            return None
        if self.missing(response):
            return None
        text = response.text
        if payload not in text:
            return None
        match = _JSONP_RE.match(text)
        if match is None and not text.lstrip().startswith(payload):
            return None
        return self.build_finding(
            title="JSONP endpoint reflects an attacker-controlled callback",
            severity=Severity.MEDIUM,
            url=getattr(endpoint, "url", ""),
            method=getattr(endpoint, "method", "GET"),
            parameter=name,
            location="query",
            description=(
                f"Supplying {name}={payload} wraps the JSON response in a script callback, "
                "so any origin can read the data by loading it as a script."
            ),
            impact=(
                "Authenticated users visiting an attacker page can have their data read cross-origin; "
                "the callback is also a script injection sink when the value is not validated."
            ),
            payload=payload,
            confidence=Confidence.CONFIRMED,
            cwe=("CWE-79",),
            tags=("jsonp",),
            evidence=[self.capture(response, summary="Callback reflected and evaluated as JSONP")],
            metadata={"param": name},
        )
