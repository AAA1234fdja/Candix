"""Server-side request forgery."""

from __future__ import annotations

from typing import Iterable

from candix.core.endpoint import Endpoint, Param
from candix.core.finding import Finding
from candix.core.severity import Confidence, Severity
from candix.detectors.base import BaseDetector, DetectorMeta, register_detector
from candix.net.url import URL

_PARAM_HINTS = (
    "url", "uri", "link", "src", "source", "target", "dest", "destination", "redirect",
    "next", "return", "callback", "webhook", "image", "img", "fetch", "proxy", "host",
    "domain", "endpoint", "path", "file", "load", "feed", "avatar", "import",
)

_METADATA_MARKERS = (
    "ami-",
    "instance-id",
    "iam/security-credentials",
    "AccessKeyId",
    "securityCredentials",
    "computeMetadata",
    "metadata.google.internal",
    "100.100.100.200",
    "privateIp",
    "cluster_name",
)


@register_detector
class SsrfDetector(BaseDetector):
    meta = DetectorMeta(
        id="ssrf",
        name="Server-side request forgery",
        category="ssrf",
        description="Substitutes internal, loopback and metadata URLs into URL-like parameters and inspects the response.",
        severity=Severity.HIGH,
        cwe=("CWE-918",),
        owasp=("A10:2021 Server-Side Request Forgery",),
        intrusive=True,
        tags=("injection", "network"),
        order=75,
        remediation_key="ssrf",
    )

    def run(self) -> Iterable[Finding]:
        for endpoint in self.endpoints():
            for param in self.params_for(endpoint):
                if param.location not in {"query", "body", "json"}:
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
        value = (param.value or "").lower()
        return value.startswith(("http://", "https://", "//")) or ("." in value and "/" in value)

    def _test(self, endpoint: Endpoint, param: Param) -> Finding | None:
        target_url = self._callback_url()
        try:
            baseline = self.send(endpoint, {param.name: param.value or target_url}, tag="ssrf-baseline")
        except Exception:
            return None
        if self.missing(baseline):
            return None
        netloc = URL.parse(target_url).netloc if "://" in target_url else target_url
        payloads = [payload.format(target=netloc) for payload in self.load_payloads("ssrf")]
        payloads = [
            f"http://{netloc}/internal/metadata",
            f"http://{netloc}/latest/meta-data/",
            f"http://{netloc}/",
            *payloads,
        ]
        for payload in payloads:
            if payload.startswith(("file://", "gopher://", "dict://", "ftp://", "ldap://")):
                continue
            try:
                response = self.send(
                    endpoint,
                    {param.name: payload},
                    tag="ssrf-probe",
                )
            except Exception:
                continue
            if self.missing(response) or response.status >= 500:
                continue
            if 300 <= response.status < 400:
                # A redirect is not proof of a server-side fetch; the client
                # would be the one following it.
                continue
            if response.redirected:
                continue
            marker = _metadata_match(response.text)
            if marker is None:
                continue
            control = baseline
            if marker in control.text:
                continue
            return self.build_finding(
                title="Server-side request forgery",
                severity=Severity.HIGH,
                url=endpoint.url,
                method=endpoint.method,
                parameter=param.name,
                location=param.location,
                description=(
                    f"The parameter '{param.name}' fetched the attacker-supplied destination {payload!r}. "
                    f"The response contained internal service data ({marker})."
                ),
                impact=(
                    "An attacker can reach internal services, cloud metadata endpoints and administrative "
                    "interfaces that are not exposed to the internet, often leading to credential theft."
                ),
                payload=payload,
                confidence=Confidence.CONFIRMED,
                cwe=("CWE-918",),
                tags=("ssrf", "network"),
                evidence=[self.capture(response, summary=f"Internal data returned for {payload!r}", control=control)],
                vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
                metadata={"target": payload, "marker": marker},
            )
        return None

    def _callback_url(self) -> str:
        configured = str(self.config.get("detect.blind_callback_host", "") or "")
        if configured:
            return configured.rstrip("/")
        for target in self.ctx.targets:
            return URL.parse(target.url).netloc
        return "127.0.0.1"


def _metadata_match(text: str) -> str | None:
    lowered = text.lower()
    for marker in _METADATA_MARKERS:
        if marker.lower() in lowered:
            return marker
    return None
