"""Favicon hashing used to fingerprint frameworks and products."""

from __future__ import annotations

import base64
import hashlib
import struct
from dataclasses import dataclass
from typing import Any

# Shodan-compatible hashes (mmh3 of the base64 favicon without padding).
KNOWN_FAVICONS: dict[int, str] = {
    708578229: "Jenkins",
    999357577: "Grafana",
    1462987285: "GitLab",
    116323821: "Spring Boot",
    2160611344: "Jupyter",
    130233907: "Kibana",
    8158632: "SonarQube",
    1768726119: "phpMyAdmin",
    1485247935: "Apache Tomcat",
    1085862796: "Drupal",
}


@dataclass
class FaviconResult:
    url: str
    status: int = 0
    length: int = 0
    mmh3: int = 0
    sha256: str = ""
    product: str = ""
    content_type: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "status": self.status,
            "length": self.length,
            "mmh3": self.mmh3,
            "sha256": self.sha256,
            "product": self.product,
            "content_type": self.content_type,
        }


def murmur3_32(data: bytes, seed: int = 0) -> int:
    """Pure-python murmur3 implementation (matches mmh3.hash with signed=False)."""

    length = len(data)
    c1, c2 = 0xCC9E2D51, 0x1B873593
    h1 = seed & 0xFFFFFFFF
    rounded = length & ~0x3
    for index in range(0, rounded, 4):
        k1 = struct.unpack_from("<I", data, index)[0]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
        h1 = (h1 * 5 + 0xE6546B64) & 0xFFFFFFFF
    tail = data[rounded:]
    k1 = 0
    if len(tail) >= 3:
        k1 ^= tail[2] << 16
    if len(tail) >= 2:
        k1 ^= tail[1] << 8
    if tail:
        k1 ^= tail[0]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
    h1 ^= length
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85EBCA6B) & 0xFFFFFFFF
    h1 ^= h1 >> 13
    h1 = (h1 * 0xC2B2AE35) & 0xFFFFFFFF
    h1 ^= h1 >> 16
    return h1


def favicon_hash(content: bytes) -> tuple[int, str]:
    encoded = base64.b64encode(content)
    digest = murmur3_32(encoded, 0) & 0xFFFFFFFF
    return digest, hashlib.sha256(content).hexdigest()


def identify(content: bytes) -> str:
    digest, _sha = favicon_hash(content)
    return KNOWN_FAVICONS.get(digest, "")


def analyse(response: Any, url: str = "") -> FaviconResult:
    content = getattr(response, "content", b"") or b""
    status = int(getattr(response, "status", 0) or 0)
    headers = getattr(response, "headers", None)
    content_type = ""
    if headers is not None and hasattr(headers, "get"):
        content_type = str(headers.get("Content-Type", "") or "")
    result = FaviconResult(url=url or str(getattr(response, "url", "")), status=status, length=len(content), content_type=content_type)
    if content and status == 200:
        result.mmh3, result.sha256 = favicon_hash(content)
        result.product = KNOWN_FAVICONS.get(result.mmh3, "")
    return result


def load_hashes(document: dict[str, Any]) -> dict[int, str]:
    mapping: dict[int, str] = {}
    for key, value in document.items():
        try:
            mapping[int(key)] = str(value)
        except (TypeError, ValueError):
            continue
    return mapping


def merge_known(mapping: dict[int, str]) -> int:
    added = 0
    for key, value in mapping.items():
        if key not in KNOWN_FAVICONS:
            KNOWN_FAVICONS[key] = value
            added += 1
    return added


def export_known() -> dict[int, str]:
    return dict(KNOWN_FAVICONS)
