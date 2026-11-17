"""Cross-site scripting detection (reflected and DOM-based).

Reflected XSS requires three facts, each observed independently:

1. the marker survives into the response (no full sanitisation),
2. it lands in an executable context (HTML text, attribute, script block),
3. the dangerous characters are not encoded (payload appears verbatim).

Only then is the finding marked confirmed. A reflected-but-encoded parameter is
reported as informational, which is useful for tracking defence-in-depth
regressions without inflating the risk register.
"""

from __future__ import annotations

import re
from typing import Iterable

from candix.analysis.html import HTMLDocument
from candix.analysis.reflection import (
    CONTEXT_HTML,
    CONTEXT_SCRIPT,
    classify_context,
    find_reflection,
)
from candix.analysis.sinks import analyze_script
from candix.core.endpoint import Endpoint, Param
from candix.core.finding import Finding
from candix.core.severity import Confidence, Severity
from candix.detectors.base import BaseDetector, DetectorMeta, register_detector
from candix.net.http import Response

_SKIP_PARAMS = ("csrf", "xsrf", "_token", "authenticity_token", "submit", "captcha")


@register_detector
class ReflectedXssDetector(BaseDetector):
    meta = DetectorMeta(
        id="xss",
        name="Reflected cross-site scripting",
        category="xss",
        description="Injects unique markers into every parameter and analyses the reflection context and encoding.",
        severity=Severity.HIGH,
        cwe=("CWE-79",),
        owasp=("A03:2021 Injection",),
        intrusive=True,
        tags=("injection", "browser"),
        order=50,
        remediation_key="xss",
    )

    def run(self) -> Iterable[Finding]:
        for endpoint in self.endpoints():
            for param in self.params_for(endpoint):
                if param.name.lower() in _SKIP_PARAMS:
                    continue
                if param.location not in {"query", "body", "json", "path"}:
                    continue
                finding = self._test(endpoint, param)
                if finding is not None:
                    yield self.emit(finding)

    def _test(self, endpoint: Endpoint, param: Param) -> Finding | None:
        marker = self.marker("x")
        discovery_payload = f"\"><cdx{marker}>"
        try:
            baseline = self.send(endpoint, {param.name: param.value or "candix"}, tag="xss-baseline")
            response = self.send(endpoint, {param.name: discovery_payload}, tag="xss-reflect")
        except Exception:
            return None
        if self.missing(response):
            return None
        reflection = find_reflection(response.text, discovery_payload, payload=discovery_payload, window=160)
        if not reflection.found:
            plain = f"cdx{marker}"
            try:
                plain_response = self.send(endpoint, {param.name: plain}, tag="xss-reflect-plain")
            except Exception:
                plain_response = None
            if plain_response is not None and plain in plain_response.text:
                encoded = "&lt;cdx" in plain_response.text or "%3Ccdx" in plain_response.text.lower()
                self.logger.debug(
                    "marker reflected but special characters are encoded",
                    url=endpoint.url,
                    parameter=param.name,
                    encoded=encoded,
                )
            return None
        # A second, structurally different marker rules out coincidence (for
        # example a cached page containing the previous value).
        second_marker = self.marker("y")
        try:
            second = self.send(endpoint, {param.name: f"\"><cdx{second_marker}>"}, tag="xss-confirm")
        except Exception:
            second = response
        if not second or f"\"><cdx{second_marker}>" not in second.text:
            return None
        context = reflection.context
        if context in {CONTEXT_HTML, CONTEXT_SCRIPT} or context.startswith("attribute"):
            pass
        execution_payload = self._execution_payload(context)
        try:
            execution = self.send(endpoint, {param.name: execution_payload}, tag="xss-exec")
        except Exception:
            execution = response
        executable = bool(execution) and execution_payload in (execution.text if execution else "")
        if executable:
            evidence = [
                self.capture(baseline, summary="Baseline response"),
                self.capture(
                    execution,
                    summary="Unencoded XSS payload reflected in an executable context",
                    control=baseline,
                    data={"context": context, "payload": execution_payload},
                ),
            ]
            return self.build_finding(
                title="Reflected cross-site scripting",
                severity=Severity.HIGH,
                url=endpoint.url,
                method=endpoint.method,
                parameter=param.name,
                location=param.location,
                description=(
                    f"The parameter '{param.name}' reflects attacker-controlled input without encoding in a "
                    f"{context} context. The payload {execution_payload!r} appears verbatim in the response."
                ),
                impact=(
                    "An attacker can execute JavaScript in the victim's browser, steal session cookies, "
                    "perform actions as the victim and modify page content."
                ),
                payload=execution_payload,
                confidence=Confidence.CONFIRMED,
                cwe=("CWE-79",),
                tags=("xss", "reflected"),
                evidence=evidence,
                vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                metadata={"context": context, "reflection": reflection.to_dict()},
            )
        if reflection.raw_specials and not reflection.encoded_specials:
            evidence = self.capture(
                response,
                summary="Marker reflected but full payload was filtered or encoded",
                control=baseline,
                data={"context": context, "reflection": reflection.to_dict()},
            )
            return self.build_finding(
                title="Potential cross-site scripting (reflection with filtering)",
                severity=Severity.LOW,
                url=endpoint.url,
                method=endpoint.method,
                parameter=param.name,
                location=param.location,
                description=(
                    f"Input is reflected in a {context} context. The payload was partially filtered, "
                    "but the reflection context is fragile and may be exploitable with an encoding bypass."
                ),
                impact="Depending on the filter, script execution may still be achievable in some browsers.",
                payload=discovery_payload,
                confidence=Confidence.POSSIBLE,
                cwe=("CWE-79",),
                tags=("xss", "reflection"),
                evidence=[evidence],
                metadata={"context": context, "reflection": reflection.to_dict()},
            )
        return None

    def _execution_payload(self, context: str) -> str:
        marker = self.marker("p")
        if context == "script":
            return f"</script><svg onload=alert({marker})>"
        if context.startswith("attribute"):
            return f"\"><svg onload=alert({marker})>"
        if context == "url":
            return f"javascript:alert({marker})"
        return f"<svg onload=alert({marker})>"


@register_detector
class DomXssDetector(BaseDetector):
    meta = DetectorMeta(
        id="xss_dom",
        name="DOM-based cross-site scripting",
        category="xss",
        description="Statically inspects inline and external JavaScript for source-to-sink flows that enable DOM XSS.",
        severity=Severity.MEDIUM,
        cwe=("CWE-79",),
        owasp=("A03:2021 Injection",),
        intrusive=False,
        tags=("browser", "javascript"),
        order=55,
        remediation_key="xss",
    )

    def run(self) -> Iterable[Finding]:
        for target in self.ctx.targets:
            try:
                page = self.http.get(target.url, tag="domxss-page")
            except Exception:
                continue
            if self.missing(page) or "html" not in page.content_type:
                continue
            document = HTMLDocument(page.text, target.url)
            scripts: list[tuple[str, str]] = [(source, source) for source in document.inline_scripts()]
            external = document.script_sources()[:10]
            for url in external:
                if self.ctx.scope is not None and not self.ctx.scope.matches(url):
                    continue
                try:
                    asset = self.http.get(url, tag="domxss-js")
                except Exception:
                    continue
                if self.missing(asset) or asset.size > 2_000_000:
                    continue
                scripts.append((url, asset.text))
            matches: list[dict[str, object]] = []
            endpoints: list[str] = []
            for location, code in scripts:
                analysis = analyze_script(code)
                for match in analysis.matches:
                    item = match.to_dict()
                    item["script"] = location
                    matches.append(item)
                endpoints.extend(analysis.endpoints)
            if not matches:
                continue
            yield self.emit(
                self.build_finding(
                    title="DOM-based cross-site scripting sink with attacker-controlled source",
                    severity=Severity.MEDIUM,
                    url=target.url,
                    location="body",
                    description=(
                        "Static analysis found data flowing from attacker-controllable browser sources "
                        "(location, referrer, postMessage) into dangerous DOM sinks."
                    ),
                    impact="Crafted links may execute JavaScript in the victim's browser without any server-side reflection.",
                    confidence=Confidence.LIKELY,
                    cwe=("CWE-79",),
                    tags=("xss", "dom", "static-analysis"),
                    evidence=[
                        self.capture(
                            page,
                            summary="Page containing the vulnerable script",
                            kind="artifact",
                            data={"matches": matches[:20], "scripts": endpoints[:50]},
                        )
                    ],
                    metadata={"sinks": matches[:20], "endpoints": sorted(set(endpoints))[:50]},
                )
            )
