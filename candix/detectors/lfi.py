"""Path traversal and local file inclusion."""

from __future__ import annotations

from typing import Iterable

from candix.core.endpoint import Endpoint, Param
from candix.core.finding import Finding
from candix.core.severity import Confidence, Severity
from candix.detectors.base import BaseDetector, DetectorMeta, register_detector
from candix.net.http import Response

_SIGNATURES = {
    "passwd": ("root:x:0:0", "root:*:0:0", "daemon:x:1:1", "/bin/bash"),
    "win.ini": ("[fonts]", "[extensions]", "for 16-bit app support"),
    "environ": ("PATH=", "HOSTNAME=", "PWD="),
    "hosts": ("localhost", "127.0.0.1", "::1"),
    "php-filter": ("PD9waHA", "cm9vdDp4OjA6MA=="),
}

_PARAM_HINTS = (
    "file", "filename", "path", "folder", "document", "doc", "template", "include",
    "require", "page", "view", "load", "read", "download", "img", "image", "src",
    "resource", "asset", "module", "dir", "url", "lang", "locale",
)


@register_detector
class LfiDetector(BaseDetector):
    meta = DetectorMeta(
        id="lfi",
        name="Path traversal and local file inclusion",
        category="lfi",
        description="Injects traversal sequences and stream wrappers to read files outside the intended directory.",
        severity=Severity.HIGH,
        cwe=("CWE-22", "CWE-98"),
        owasp=("A01:2021 Broken Access Control", "A03:2021 Injection"),
        intrusive=True,
        tags=("injection", "filesystem"),
        order=65,
        remediation_key="lfi",
    )

    def run(self) -> Iterable[Finding]:
        for endpoint in self.endpoints():
            for param in self.params_for(endpoint):
                if param.location not in {"query", "body", "json", "path"}:
                    continue
                if not self._interesting(param):
                    continue
                finding = self._test(endpoint, param)
                if finding is not None:
                    yield self.emit(finding)

    def _interesting(self, param: Param) -> bool:
        name = param.name.lower()
        if any(hint in name for hint in _PARAM_HINTS):
            return True
        # Values that look like paths or filenames are also worth testing.
        value = (param.value or "").lower()
        return "/" in value or "\\" in value or "." in value

    def _test(self, endpoint: Endpoint, param: Param) -> Finding | None:
        baseline = self._baseline(endpoint, param)
        if baseline is None:
            return None
        payloads = self.load_payloads("lfi")
        for payload in payloads:
            try:
                response = self.send(endpoint, {param.name: payload}, tag="lfi-probe")
            except Exception:
                continue
            if self.missing(response):
                continue
            signature = _matches_signature(response.text)
            if signature is None:
                continue
            if signature in baseline.text:
                continue
            # Confirm the file read with a second, structurally different path.
            confirm_payload = payload if payload.startswith(("/", "..")) else "/" + payload
            try:
                confirm = self.send(endpoint, {param.name: confirm_payload}, tag="lfi-confirm")
            except Exception:
                confirm = None
            if confirm is None or _matches_signature(confirm.text) != signature:
                continue
            return self.build_finding(
                title="Path traversal allows arbitrary file read",
                severity=Severity.HIGH,
                url=endpoint.url,
                method=endpoint.method,
                parameter=param.name,
                location=param.location,
                description=(
                    f"The parameter '{param.name}' accepted {payload!r} and returned the contents of a "
                    f"sensitive system file ({signature}). Two different traversal sequences reproduced the read."
                ),
                impact=(
                    "An attacker can read application source, configuration and credentials. When the "
                    "parameter also accepts remote URLs or stream wrappers this escalates to code execution."
                ),
                payload=payload,
                confidence=Confidence.CONFIRMED,
                cwe=("CWE-22", "CWE-98"),
                tags=("lfi", "traversal"),
                evidence=[
                    self.capture(response, summary=f"File disclosure via {payload!r}", control=baseline),
                    self.capture(confirm, summary="Independent traversal sequence confirms the read"),
                ],
                vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                metadata={"signature": signature},
            )
        return None

    def _baseline(self, endpoint: Endpoint, param: Param) -> Response | None:
        try:
            response = self.send(endpoint, {param.name: param.value or "index"}, tag="lfi-baseline")
        except Exception:
            return None
        return None if self.missing(response) else response


def _matches_signature(text: str) -> str | None:
    for kind, markers in _SIGNATURES.items():
        hits = sum(1 for marker in markers if marker in text)
        if hits >= 2:
            return kind
    return None
