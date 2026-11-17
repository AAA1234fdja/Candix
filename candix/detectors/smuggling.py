"""HTTP request smuggling probes (opt-in).

Desynchronisation testing can affect shared proxies, so Candix only runs it
when ``detect.smuggling`` is explicitly enabled and the profile is not ``safe``.
The probe sends a single ambiguous request and inspects the framing response; it
never attempts to poison another user's request.
"""

from __future__ import annotations

from typing import Iterable

from candix.core.finding import Finding
from candix.core.severity import Confidence, Severity
from candix.detectors.base import BaseDetector, DetectorMeta, register_detector
from candix.net.url import URL


@register_detector
class RequestSmugglingDetector(BaseDetector):
    meta = DetectorMeta(
        id="smuggling",
        name="HTTP request smuggling indicators",
        category="smuggling",
        description="Sends CL.TE and TE.CL probes and inspects the server's framing behaviour.",
        severity=Severity.HIGH,
        cwe=("CWE-444",),
        owasp=("A05:2021 Security Misconfiguration",),
        intrusive=True,
        tags=("http", "protocol"),
        order=195,
        remediation_key="smuggling",
    )

    def applicable(self) -> bool:
        if not super().applicable():
            return False
        return bool(self.config.get("detect.smuggling", False)) and str(self.config.get("profile")) != "safe"

    def run(self) -> Iterable[Finding]:
        for target in self.ctx.targets:
            parsed = URL.parse(target.url)
            port = parsed.effective_port or (443 if parsed.is_https() else 80)
            scheme_tls = parsed.is_https()
            probes = [
                (
                    "CL.TE",
                    (
                        f"POST {parsed.path or '/'} HTTP/1.1\r\nHost: {parsed.netloc}\r\n"
                        "Content-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n"
                        "0\r\n\r\nG"
                    ).encode(),
                ),
                (
                    "TE.CL",
                    (
                        f"POST {parsed.path or '/'} HTTP/1.1\r\nHost: {parsed.netloc}\r\n"
                        "Content-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n"
                        "5c\r\nGPOST / HTTP/1.1\r\n\r\n0\r\n\r\n"
                    ).encode(),
                ),
            ]
            baseline = None
            try:
                baseline = self.http.get(target.url, tag="smuggling-baseline")
            except Exception:
                pass
            for label, payload in probes:
                try:
                    raw = self.http.send_raw(parsed.host, port, payload, timeout=6.0, use_tls=scheme_tls)
                except Exception:
                    continue
                if not raw:
                    continue
                first_line = raw.split(b"\r\n", 1)[0].decode("latin-1", "replace")
                indicator = _framing_indicator(raw, first_line)
                if indicator is None:
                    continue
                yield self.emit(
                    self.build_finding(
                        title=f"Possible HTTP request smuggling ({label})",
                        severity=Severity.MEDIUM,
                        url=target.url,
                        location="header",
                        description=(
                            f"The {label} probe produced an ambiguous framing response ({indicator}). "
                            "This indicates the front-end and back-end disagree about request boundaries."
                        ),
                        impact=(
                            "Request smuggling can bypass access controls, poison caches and hijack other "
                            "users' requests. Confirmation requires controlled differential testing."
                        ),
                        confidence=Confidence.POSSIBLE,
                        cwe=("CWE-444",),
                        tags=("smuggling", "http"),
                        evidence=[
                            self.capture(
                                baseline,
                                summary="Baseline response",
                                kind="artifact",
                                data={"probe": label, "raw_response": raw[:2000].decode("latin-1", "replace")},
                            )
                        ]
                        if baseline is not None
                        else [],
                        metadata={"probe": label, "indicator": indicator, "status_line": first_line},
                    )
                )
                break


def _framing_indicator(raw: bytes, status_line: str) -> str | None:
    responses = raw.count(b"HTTP/1.")
    if responses >= 2:
        return f"{responses} HTTP responses to a single request"
    lowered = raw[:2000].lower()
    if b"bad request" in lowered and b"transfer-encoding" in lowered:
        return "edge rejects ambiguous framing with a transfer-encoding error"
    if b"400 bad request" in lowered and b"content-length" in lowered:
        return "content-length conflict reported by the server"
    if b"501 not implemented" in lowered and b"transfer-encoding" in lowered:
        return "transfer-encoding handling differs between hops"
    if "200" in status_line and b"g" == raw[-1:] and b"transfer-encoding" in lowered:
        return "trailing byte after the response body"
    return None
