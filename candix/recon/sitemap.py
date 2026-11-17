"""sitemap.xml parsing without an XML dependency."""

from __future__ import annotations

import re

_LOC_RE = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.IGNORECASE)
_SITEMAP_INDEX_RE = re.compile(r"<sitemapindex", re.IGNORECASE)


def parse_sitemap(text: str) -> list[str]:
    if not text:
        return []
    urls = [match.group(1).strip() for match in _LOC_RE.finditer(text)]
    return [url for url in dict.fromkeys(urls) if url.startswith(("http://", "https://", "/"))]


def is_sitemap_index(text: str) -> bool:
    return bool(_SITEMAP_INDEX_RE.search(text or ""))


def sitemap_stats(text: str) -> dict[str, object]:
    urls = parse_sitemap(text)
    return {
        "urls": len(urls),
        "is_index": is_sitemap_index(text),
        "sample": urls[:10],
    }
