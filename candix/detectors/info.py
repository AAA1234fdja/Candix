"""Information disclosure through verbose errors and internal identifiers."""

from __future__ import annotations

import re
from typing import Iterable

from candix.core.endpoint import Endpoint, Param
from candix.core.finding import Finding
from candix.core.severity import Confidence, Severity
from candix.detectors.base import BaseDetector, DetectorMeta, register_detector

_LEAK_PATTERNS = {
    "stack-trace": (r"traceback \(most recent call last\)", r"java\.lang\.[A-Za-z.]+exception", r"system\.nullreferenceexception", r"at [A-Za-z0-9_.]+\([A-Za-z0-9_.]+\.java:\d+\)"),
    "filesystem-path": (r"(?:/var/www/[\w./-]+)", r"(?:/home/[\w./-]+)", r"[A-Z]:\\\\?inetpub\\\\?[\w./-]+"),
    "internal-url": (r"https?://(?:10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)[:/\w.-]*",),
    "sql-error": (r"sql syntax", r"unclosed quotation mark", r"pg_query", r"ora-\d{5}"),
    "framework-debug": (r"whitelabel error page", r"werkzeug debugger", r"django technical 500", r"whoops", r"stack trace"),
    "secret-like": (r"(?i)(api[_-]?key|secret|password)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{8,}",),
}


@register_detector
class InformationDisclosureDetector(BaseDetector):
    meta = DetectorMeta(
        id="info",
        name="Verbose error and internal information disclosure",
        category="info",
        description="Sends malformed parameter values and inspects error responses for stack traces, paths, internal hosts and secrets.",
        severity=Severity.LOW,
        cwe=("CWE-209", "CWE-200"),
        owasp=("A05:2021 Security Misconfiguration",),
        intrusive=True,
        tags=("information-disclosure", "errors"),
        order=155,
        remediation_key="info",
    )

    def run(self) -> Iterable[Finding]:
        for endpoint in self.endpoints():
            params = self.params_for(endpoint)
            if not params:
                continue
            for param in params[:3]:
                finding = self._test(endpoint, param)
                if finding is not None:
                    yield self.emit(finding)
                    break

    def _test(self, endpoint: Endpoint, param: Param) -> Finding | None:
        try:
            baseline = self.send(endpoint, {param.name: param.value or "1"}, tag="info-baseline")
        except Exception:
            return None
        if self.missing(baseline):
            return None
        probes = ["[]", "{}", "'", "null", "0x7fffffff", "A" * 2048, "%00", "-1"]
        for probe in probes:
            try:
                response = self.send(endpoint, {param.name: probe}, tag="info-probe")
            except Exception:
                continue
            if self.missing(response):
                continue
            leaks = _find_leaks(response.text)
            baseline_leaks = {kind for kind, _ in _find_leaks(baseline.text)}
            new_leaks = {kind: value for kind, value in leaks if kind not in baseline_leaks}
            if not new_leaks:
                continue
            kind = next(iter(new_leaks))
            if kind == "secret-like":
                severity = Severity.HIGH
            elif kind in {"stack-trace", "filesystem-path", "internal-url"}:
                severity = Severity.MEDIUM
            else:
                severity = Severity.LOW
            return self.build_finding(
                title=f"Information disclosure via verbose error ({kind})",
                severity=severity,
                url=endpoint.url,
                method=endpoint.method,
                parameter=param.name,
                location=param.location,
                description=(
                    f"Sending {probe[:40]!r} produced a response containing {kind}: "
                    f"{self.truncate(new_leaks[kind], 180)}"
                ),
                impact="Error details reveal internal paths, frameworks and sometimes credentials, shortening the path to exploitation.",
                payload=probe[:200],
                confidence=Confidence.CONFIRMED,
                cwe=("CWE-209",),
                tags=("information-disclosure", kind),
                evidence=[self.capture(response, summary=f"{kind} disclosed in error response", control=baseline)],
                metadata={"leak_kind": kind},
            )
        return None


def _find_leaks(text: str) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    for kind, patterns in _LEAK_PATTERNS.items():
        for pattern in patterns:
            match = re.search(pattern, text or "", re.IGNORECASE)
            if match:
                found.append((kind, match.group(0)[:200]))
                break
    return found
