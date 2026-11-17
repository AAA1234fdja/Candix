"""TLS inspection without third-party libraries.

The harness needs to know which protocol versions a host accepts, whether the
certificate is valid and what cipher suites are negotiated. ``ssl`` exposes
enough for all three; certificate fields are decoded through the private
``_test_decode_cert`` helper, which is stable across CPython 3.x and avoids a
dependency on ``cryptography``.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import socket
import ssl
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class CertificateInfo:
    subject: str = ""
    issuer: str = ""
    common_name: str = ""
    san: list[str] = field(default_factory=list)
    not_before: str = ""
    not_after: str = ""
    serial: str = ""
    fingerprint_sha256: str = ""
    expired: bool = False
    expiring_soon: bool = False
    self_signed: bool = False
    days_remaining: int = 0
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "subject": self.subject,
            "issuer": self.issuer,
            "common_name": self.common_name,
            "san": list(self.san),
            "not_before": self.not_before,
            "not_after": self.not_after,
            "serial": self.serial,
            "fingerprint_sha256": self.fingerprint_sha256,
            "expired": self.expired,
            "expiring_soon": self.expiring_soon,
            "self_signed": self.self_signed,
            "days_remaining": self.days_remaining,
        }


@dataclass
class ProtocolSupport:
    version: str
    supported: bool
    cipher: str = ""
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"version": self.version, "supported": self.supported, "cipher": self.cipher, "error": self.error}


@dataclass
class TlsReport:
    host: str
    port: int
    certificate: CertificateInfo | None = None
    protocols: list[ProtocolSupport] = field(default_factory=list)
    preferred_cipher: str = ""
    preferred_version: str = ""
    error: str = ""

    @property
    def weak_protocols(self) -> list[str]:
        return [item.version for item in self.protocols if item.supported and item.version in {"TLSv1", "TLSv1.1", "SSLv3", "SSLv2"}]

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "port": self.port,
            "certificate": self.certificate.to_dict() if self.certificate else None,
            "protocols": [item.to_dict() for item in self.protocols],
            "preferred_cipher": self.preferred_cipher,
            "preferred_version": self.preferred_version,
            "weak_protocols": self.weak_protocols,
            "error": self.error,
        }


def inspect_tls(host: str, port: int = 443, *, timeout: float = 5.0, server_name: str | None = None, verify: bool = False) -> TlsReport:
    report = TlsReport(host=host, port=port)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE if not verify else ssl.CERT_REQUIRED
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=server_name or host) as tls:
                report.preferred_version = tls.version() or ""
                cipher = tls.cipher()
                report.preferred_cipher = f"{cipher[0]} ({cipher[1]}, {cipher[2]} bits)" if cipher else ""
                binary = tls.getpeercert(binary_form=True)
                if binary:
                    report.certificate = _parse_der_certificate(binary, host)
    except (OSError, ssl.SSLError) as exc:
        report.error = f"{type(exc).__name__}: {exc}"
    report.protocols = _probe_protocols(host, port, timeout=timeout)
    return report


def _parse_der_certificate(binary: bytes, host: str) -> CertificateInfo:
    info = CertificateInfo()
    info.fingerprint_sha256 = hashlib.sha256(binary).hexdigest()
    try:
        pem = ssl.DER_cert_to_PEM_cert(binary)
        with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as handle:
            handle.write(pem)
            path = handle.name
        try:
            decoded = ssl._ssl._test_decode_cert(path)  # type: ignore[attr-defined]
        finally:
            Path(path).unlink(missing_ok=True)
        info.subject = _flatten(decoded.get("subject", ()))
        info.issuer = _flatten(decoded.get("issuer", ()))
        info.common_name = _common_name(decoded.get("subject", ()))
        info.san = [value for kind, value in decoded.get("subjectAltName", ()) if kind.lower() == "dns"]
        info.not_before = decoded.get("notBefore", "")
        info.not_after = decoded.get("notAfter", "")
        info.serial = decoded.get("serialNumber", "")
        info.self_signed = bool(info.subject) and info.subject == info.issuer
        info.days_remaining, info.expired, info.expiring_soon = _validity(info.not_after)
    except Exception as exc:  # pragma: no cover - platform dependent
        info.error = str(exc)
    return info


def _flatten(name: Any) -> str:
    parts: list[str] = []
    for rdn in name or ():
        for key, value in rdn:
            parts.append(f"{key}={value}")
    return ", ".join(parts)


def _common_name(name: Any) -> str:
    for rdn in name or ():
        for key, value in rdn:
            if key == "commonName":
                return str(value)
    return ""


def _validity(not_after: str) -> tuple[int, bool, bool]:
    try:
        expiry = _dt.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=_dt.timezone.utc)
    except ValueError:
        return 0, False, False
    now = _dt.datetime.now(tz=_dt.timezone.utc)
    remaining = (expiry - now).days
    return remaining, remaining < 0, remaining <= 30


def _probe_protocols(host: str, port: int, *, timeout: float) -> list[ProtocolSupport]:
    versions = [
        ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
        ("TLSv1.3", ssl.TLSVersion.TLSv1_3),
        ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
        ("TLSv1", ssl.TLSVersion.TLSv1),
    ]
    results: list[ProtocolSupport] = []
    for name, version in versions:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        try:
            context.minimum_version = version
            context.maximum_version = version
        except (ValueError, OSError):
            results.append(ProtocolSupport(version=name, supported=False, error="unsupported by local OpenSSL"))
            continue
        try:
            with socket.create_connection((host, port), timeout=timeout) as raw:
                with context.wrap_socket(raw, server_hostname=host) as tls:
                    cipher = tls.cipher()
                    results.append(ProtocolSupport(version=name, supported=True, cipher=cipher[0] if cipher else ""))
        except (ssl.SSLError, OSError) as exc:
            results.append(ProtocolSupport(version=name, supported=False, error=_short_error(exc)))
    return results


def _short_error(exc: Exception) -> str:
    text = str(exc)
    return text[:120] if text else type(exc).__name__


def check_tls(host: str, port: int = 443, *, timeout: float = 5.0) -> dict[str, Any]:
    return inspect_tls(host, port, timeout=timeout).to_dict()
