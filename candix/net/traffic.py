"""Traffic proxy helpers — Python mirror of engine/traffic.

Provides URL validation, proxy address resolution, and request header
sanitisation used by WebFetch / http custom tools.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from urllib.parse import urlparse


@dataclass(frozen=True)
class ProxyConfig:
    addr: str = ""
    ca_cert: str = ""

    @classmethod
    def from_env(cls) -> ProxyConfig:
        return cls(addr=os.getenv("CANDIX_ENGINE_PROXY_ADDR", "").strip(),
                   ca_cert=os.getenv("CANDIX_ENGINE_PROXY_CA_CERT", "").strip())

    def enabled(self) -> bool:
        return bool(self.addr)


def is_valid_http_url(url: str) -> bool:
    try:
        p = urlparse(url.strip())
        return p.scheme in {"http", "https"} and bool(p.hostname)
    except Exception:
        return False


def sanitize_headers(headers: dict) -> dict:
    """Strip hop-by-hop and auth leakage; keep safe subset."""
    hop = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
           "te", "trailers", "transfer-encoding", "upgrade"}
    out: dict = {}
    for k, v in (headers or {}).items():
        lk = k.lower()
        if lk in hop:
            continue
        out[k] = v
    return out


def proxy_addr() -> str:
    return os.getenv("CANDIX_ENGINE_PROXY_ADDR", "").strip()
