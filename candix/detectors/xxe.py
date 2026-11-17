"""XML external entity injection."""

from __future__ import annotations

import re
from typing import Iterable

from candix.core.endpoint import Body, Endpoint, Param
from candix.core.finding import Finding
from candix.core.severity import Confidence, Severity
from candix.detectors.base import BaseDetector, DetectorMeta, register_detector
from candix.net.http import Response

_XML_INDICATORS = ("<xml", "<?xml", "soap:", "<rss", "<feed", "<saml", "application/xml", "text/xml")


@register_detector
class XxeDetector(BaseDetector):
    meta = DetectorMeta(
        id="xxe",
        name="XML external entity injection",
        category="xxe",
        description="Submits DOCTYPE payloads to XML-accepting endpoints and looks for file disclosure or entity expansion.",
        severity=Severity.HIGH,
        cwe=("CWE-611",),
        owasp=("A05:2021 Security Misconfiguration",),
        intrusive=True,
        tags=("injection", "xml"),
        order=90,
        remediation_key="xxe",
    )

    def run(self) -> Iterable[Finding]:
        for endpoint in self.endpoints():
            if not self._xml_endpoint(endpoint):
                continue
            finding = self._test(endpoint)
            if finding is not None:
                yield self.emit(finding)

    def _xml_endpoint(self, endpoint: Endpoint) -> bool:
        blob = f"{endpoint.url} {endpoint.body.content_type if endpoint.body else ''} {endpoint.headers}".lower()
        if any(indicator in blob for indicator in _XML_INDICATORS):
            return True
        return any(param.name.lower() in {"xml", "document", "payload", "body", "data"} for param in endpoint.params)

    def _test(self, endpoint: Endpoint) -> Finding | None:
        marker = self.marker("xx")
        netloc = ""
        if self.ctx.targets:
            from candix.net.url import URL

            netloc = URL.parse(self.ctx.targets[0].url).netloc
        payloads = [payload.format(marker=marker, target=netloc) for payload in self.load_payloads("xxe")]
        baseline = None
        try:
            baseline = self.send(endpoint, {}, tag="xxe-baseline")
        except Exception:
            pass
        for payload in payloads:
            headers = {"Content-Type": "application/xml"}
            try:
                response = self.send(
                    endpoint,
                    {},
                    headers=headers,
                    body=payload,
                    tag="xxe-probe",
                )
            except Exception:
                continue
            if self.missing(response):
                continue
            signature = _xxe_signature(response, marker)
            if signature is None:
                continue
            if baseline is not None and _xxe_signature(baseline, marker) == signature:
                continue
            return self.build_finding(
                title="XML external entity injection",
                severity=Severity.HIGH,
                url=endpoint.url,
                method=endpoint.method,
                location="body",
                description=(
                    "The XML parser resolved a DOCTYPE-declared external entity. Evidence: " + signature
                ),
                impact=(
                    "An attacker can read local files, perform SSRF, and in some parsers achieve remote "
                    "code execution via parameter entities."
                ),
                payload=payload,
                confidence=Confidence.CONFIRMED,
                cwe=("CWE-611",),
                tags=("xxe", "xml"),
                evidence=[self.capture(response, summary="External entity resolved", control=baseline)],
                vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                metadata={"signature": signature},
            )
        return None


def _xxe_signature(response: Response, marker: str) -> str | None:
    text = response.text
    if "root:x:0:0" in text or "daemon:x:1:1" in text:
        return "file-disclosure:/etc/passwd"
    if "[fonts]" in text or "[extensions]" in text:
        return "file-disclosure:win.ini"
    if marker and marker in text and "<!ENTITY" not in text:
        return "entity-expansion"
    if re.search(r"<result>\s*(root|daemon):", text):
        return "file-disclosure:passwd"
    return None
