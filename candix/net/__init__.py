"""Network primitives: URLs, HTTP, TLS, DNS and encodings."""

from __future__ import annotations

from candix.net.url import URL, QueryParams, join_url, normalize_url

__all__ = ["URL", "QueryParams", "join_url", "normalize_url"]
