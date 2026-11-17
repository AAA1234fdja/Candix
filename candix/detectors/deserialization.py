"""Insecure deserialization indicators."""

from __future__ import annotations

import base64
import binascii
from typing import Iterable

from candix.core.finding import Finding
from candix.core.severity import Confidence, Severity
from candix.detectors.base import BaseDetector, DetectorMeta, register_detector

_MAGIC = {
    "java": (b"\xac\xed\x00\x05", "Java serialized object"),
    "php": (b"O:", "PHP serialized object"),
    "python": (b"\x80\x04", "Python pickle"),
    "dotnet": (b"\x00\x01\x00\x00\x00", ".NET BinaryFormatter"),
    "ruby": (b"\x04\x08", "Ruby Marshal"),
}


@register_detector
class DeserializationDetector(BaseDetector):
    meta = DetectorMeta(
        id="deserialization",
        name="Insecure deserialization surface",
        category="deserialization",
        description="Detects serialized object formats in cookies, parameters and bodies and reports unsafe parsers.",
        severity=Severity.HIGH,
        cwe=("CWE-502",),
        owasp=("A08:2021 Software and Data Integrity Failures",),
        intrusive=False,
        tags=("deserialization", "parsing"),
        order=145,
        remediation_key="deserialization",
    )

    def run(self) -> Iterable[Finding]:
        for target in self.ctx.targets:
            try:
                response = self.http.get(target.url, tag="deser")
            except Exception:
                continue
            for header in response.headers.get_all("Set-Cookie"):
                for name, value in _cookie_pairs(header):
                    finding = self._inspect("cookie", name, value, target.url, response)
                    if finding is not None:
                        yield self.emit(finding)
            for param in _params(target.url):
                finding = self._inspect("query", param[0], param[1], target.url, response)
                if finding is not None:
                    yield self.emit(finding)
        for endpoint in self.ctx.endpoints:
            if endpoint.body is None:
                continue
            raw = endpoint.body.raw or ""
            payloads = {"body": raw, **{key: value for key, value in endpoint.body.form.items()}}
            for name, value in payloads.items():
                finding = self._inspect(endpoint.method.lower(), name, value, endpoint.url, None)
                if finding is not None:
                    yield self.emit(finding)

    def _inspect(self, location: str, name: str, value: str, url: str, response) -> Finding | None:
        if not value:
            return None
        candidates = [value]
        if len(value) < 4000 and _looks_base64(value):
            try:
                candidates.append(base64.b64decode(value + "=" * (-len(value) % 4)).decode("latin-1"))
            except (binascii.Error, ValueError):
                pass
        for candidate in candidates:
            raw = candidate.encode("latin-1", "ignore")
            for kind, (magic, description) in _MAGIC.items():
                if kind == "php":
                    if not (candidate.startswith(("O:", "a:", "s:")) and b'"' in raw):
                        continue
                if not raw.startswith(magic):
                    continue
                return self.build_finding(
                    title=f"Serialized {kind} object accepted in {location}",
                    severity=Severity.MEDIUM,
                    url=url,
                    parameter=name,
                    location="cookie" if location == "cookie" else "body",
                    description=(
                        f"The {description} format was observed in '{name}'. If the server deserialises this "
                        "value without an integrity check, a crafted object can achieve code execution."
                    ),
                    impact="Gadget chains in the application classpath can turn deserialisation into remote code execution.",
                    confidence=Confidence.POSSIBLE,
                    cwe=("CWE-502",),
                    tags=("deserialization", kind),
                    evidence=[self.capture(response, summary="Serialized object detected", kind="artifact", data={"format": kind, "parameter": name})]
                    if response is not None
                    else [],
                    metadata={"format": kind, "parameter": name},
                )
        return None


def _cookie_pairs(header: str) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    for chunk in (header or "").split(";"):
        name, _, value = chunk.strip().partition("=")
        if name and value:
            pairs.append((name, value))
    return pairs[:1]


def _params(url: str) -> list[tuple[str, str]]:
    from candix.net.url import URL

    try:
        parsed = URL.parse(url)
    except ValueError:
        return []
    return parsed.query.get_all()


def _looks_base64(value: str) -> bool:
    if len(value) < 12:
        return False
    alphabet = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=_-")
    return set(value) <= alphabet and len(value) % 4 in {0, 2, 3}
