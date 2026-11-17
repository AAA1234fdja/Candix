"""URL parsing, normalisation and manipulation.

``urllib.parse`` is a fine parser but it loses ordering of duplicate query
parameters and offers no structured way to rewrite a single parameter while
preserving everything else. Security testing depends on both, so Candix uses a
small immutable-ish URL model with an ordered multi-value query.
"""

from __future__ import annotations

import ipaddress
import posixpath
import re
from dataclasses import dataclass, field
from typing import Any, Iterable, Iterator, Sequence
from urllib.parse import quote, unquote, unquote_plus

DEFAULT_PORTS: dict[str, int] = {"http": 80, "https": 443, "ws": 80, "wss": 443, "ftp": 21}

_PERCENT_RE = re.compile(r"%[0-9a-fA-F]{2}")
_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*$")
_HOST_PORT_RE = re.compile(r"^(?P<host>\[[0-9a-fA-F:]+\]|[^:]+)(?::(?P<port>\d+))?$")


def _normalise_percent(text: str) -> str:
    """Upper-case percent escapes without decoding them."""

    return _PERCENT_RE.sub(lambda match: match.group(0).upper(), text)


class QueryParams:
    """Ordered multi-value query string."""

    __slots__ = ("_items",)

    def __init__(self, items: Iterable[tuple[str, str]] | None = None) -> None:
        self._items: list[tuple[str, str]] = [
            (str(name), "" if value is None else str(value)) for name, value in (items or [])
        ]

    @classmethod
    def parse(cls, raw: str | bytes | None) -> "QueryParams":
        if not raw:
            return cls()
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8", "replace")
        raw = raw.lstrip("?")
        if not raw:
            return cls()
        items: list[tuple[str, str]] = []
        for chunk in raw.split("&"):
            if not chunk:
                continue
            name, _, value = chunk.partition("=")
            items.append((unquote_plus(name), unquote_plus(value.replace("+", " "))))
        return cls(items)

    @classmethod
    def from_mapping(cls, mapping: dict[str, Any]) -> "QueryParams":
        items: list[tuple[str, str]] = []
        for name, value in mapping.items():
            if isinstance(value, (list, tuple)):
                items.extend((str(name), str(item)) for item in value)
            else:
                items.append((str(name), "" if value is None else str(value)))
        return cls(items)

    def __iter__(self) -> Iterator[tuple[str, str]]:
        return iter(self._items)

    def __len__(self) -> int:
        return len(self._items)

    def __contains__(self, name: object) -> bool:
        return any(key == name for key, _ in self._items)

    def __getitem__(self, name: str) -> str:
        for key, value in self._items:
            if key == name:
                return value
        raise KeyError(name)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, QueryParams):
            return self._items == other._items
        return NotImplemented

    def keys(self) -> list[str]:
        seen: dict[str, None] = {}
        for key, _ in self._items:
            seen.setdefault(key, None)
        return list(seen)

    def values(self, name: str) -> list[str]:
        return [value for key, value in self._items if key == name]

    def get(self, name: str, default: str | None = None) -> str | None:
        for key, value in self._items:
            if key == name:
                return value
        return default

    def get_all(self) -> list[tuple[str, str]]:
        return list(self._items)

    def set(self, name: str, value: str) -> "QueryParams":
        found = False
        result: list[tuple[str, str]] = []
        for key, existing in self._items:
            if key == name:
                if not found:
                    result.append((key, value))
                    found = True
                continue
            result.append((key, existing))
        if not found:
            result.append((name, value))
        return QueryParams(result)

    def add(self, name: str, value: str) -> "QueryParams":
        return QueryParams([*self._items, (name, value)])

    def remove(self, name: str) -> "QueryParams":
        return QueryParams([(key, value) for key, value in self._items if key != name])

    def rename(self, old: str, new: str) -> "QueryParams":
        return QueryParams([(new if key == old else key, value) for key, value in self._items])

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in self._items:
            if key in result:
                existing = result[key]
                if isinstance(existing, list):
                    existing.append(value)
                else:
                    result[key] = [existing, value]
            else:
                result[key] = value
        return result

    def render(self, *, keep_blank: bool = True) -> str:
        parts: list[str] = []
        for key, value in self._items:
            if not keep_blank and value == "":
                parts.append(quote(key, safe=""))
                continue
            parts.append(f"{quote(key, safe='')}={quote(value, safe='')}")
        return "&".join(parts)

    def copy(self) -> "QueryParams":
        return QueryParams(list(self._items))

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"QueryParams({self._items!r})"


@dataclass
class URL:
    """Structured absolute URL."""

    scheme: str = "https"
    host: str = ""
    port: int | None = None
    path: str = "/"
    query: QueryParams = field(default_factory=QueryParams)
    fragment: str = ""
    username: str | None = None
    password: str | None = None

    # ------------------------------------------------------------------
    # construction
    # ------------------------------------------------------------------
    @classmethod
    def parse(cls, raw: str | "URL") -> "URL":
        if isinstance(raw, URL):
            return raw.copy()
        text = (raw or "").strip()
        if not text:
            raise ValueError("empty URL")
        if "://" not in text:
            text = "https://" + text
        scheme, _, remainder = text.partition("://")
        if not _SCHEME_RE.match(scheme):
            raise ValueError(f"invalid URL scheme: {scheme!r}")
        scheme = scheme.lower()
        fragment = ""
        if "#" in remainder:
            remainder, _, fragment = remainder.partition("#")
        path = "/"
        query = QueryParams()
        if "?" in remainder:
            remainder, _, raw_query = remainder.partition("?")
            query = QueryParams.parse(raw_query)
        authority, slash, raw_path = remainder.partition("/")
        if slash:
            path = "/" + raw_path
        username = password = None
        if "@" in authority:
            userinfo, _, authority = authority.rpartition("@")
            username, _, password = userinfo.partition(":")
            username = unquote(username) if username else None
            password = unquote(password) if password else None
        match = _HOST_PORT_RE.match(authority)
        if not match:
            raise ValueError(f"invalid URL authority: {authority!r}")
        host = match.group("host").strip("[]")
        port_text = match.group("port")
        port = int(port_text) if port_text else None
        if not host:
            raise ValueError("missing host")
        if scheme not in DEFAULT_PORTS and port is None:
            port = None
        return cls(
            scheme=scheme,
            host=host.lower(),
            port=port,
            path=_normalise_percent(path or "/"),
            query=query,
            fragment=fragment,
            username=username,
            password=password,
        )

    def copy(self) -> "URL":
        return URL(
            scheme=self.scheme,
            host=self.host,
            port=self.port,
            path=self.path,
            query=self.query.copy(),
            fragment=self.fragment,
            username=self.username,
            password=self.password,
        )

    # ------------------------------------------------------------------
    # rendering
    # ------------------------------------------------------------------
    @property
    def effective_port(self) -> int | None:
        return self.port or DEFAULT_PORTS.get(self.scheme)

    @property
    def netloc(self) -> str:
        host = f"[{self.host}]" if ":" in self.host and not self.host.startswith("[") else self.host
        if self.port and self.port != DEFAULT_PORTS.get(self.scheme):
            return f"{host}:{self.port}"
        return host

    @property
    def origin(self) -> str:
        return f"{self.scheme}://{self.netloc}"

    @property
    def hostname(self) -> str:
        return self.host

    @property
    def is_ip(self) -> bool:
        try:
            ipaddress.ip_address(self.host)
            return True
        except ValueError:
            return False

    @property
    def fragment_params(self) -> QueryParams:
        return QueryParams.parse(self.fragment) if "=" in self.fragment else QueryParams()

    def with_host(self, host: str, port: int | None = None) -> "URL":
        clone = self.copy()
        clone.host = host.lower()
        if port is not None:
            clone.port = port
        return clone

    def with_scheme(self, scheme: str) -> "URL":
        clone = self.copy()
        clone.scheme = scheme
        return clone

    def with_path(self, path: str) -> "URL":
        clone = self.copy()
        clone.path = path if path.startswith("/") else "/" + path
        return clone

    def with_query(self, query: QueryParams | dict[str, Any] | str) -> "URL":
        clone = self.copy()
        if isinstance(query, QueryParams):
            clone.query = query
        elif isinstance(query, str):
            clone.query = QueryParams.parse(query)
        else:
            clone.query = QueryParams.from_mapping(query)
        return clone

    def set_param(self, name: str, value: str) -> "URL":
        clone = self.copy()
        clone.query = self.query.set(name, value)
        return clone

    def add_param(self, name: str, value: str) -> "URL":
        clone = self.copy()
        clone.query = self.query.add(name, value)
        return clone

    def remove_param(self, name: str) -> "URL":
        clone = self.copy()
        clone.query = self.query.remove(name)
        return clone

    def with_fragment(self, fragment: str) -> "URL":
        clone = self.copy()
        clone.fragment = fragment.lstrip("#")
        return clone

    def render(self, *, include_fragment: bool = True, include_userinfo: bool = True) -> str:
        prefix = self.scheme + "://"
        if include_userinfo and self.username:
            credentials = quote(self.username, safe="")
            if self.password:
                credentials += ":" + quote(self.password, safe="")
            prefix += credentials + "@"
        rendered = prefix + self.netloc + (self.path or "/")
        query = self.query.render()
        if query:
            rendered += "?" + query
        if include_fragment and self.fragment:
            rendered += "#" + self.fragment
        return rendered

    def __str__(self) -> str:
        return self.render()

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"URL({self.render()!r})"

    def __eq__(self, other: object) -> bool:
        if isinstance(other, URL):
            return self.dedupe_key() == other.dedupe_key()
        if isinstance(other, str):
            try:
                return self.dedupe_key() == URL.parse(other).dedupe_key()
            except ValueError:
                return False
        return NotImplemented

    def __hash__(self) -> int:
        return hash(self.dedupe_key())

    # ------------------------------------------------------------------
    # comparison helpers
    # ------------------------------------------------------------------
    def dedupe_key(self) -> str:
        """Canonical identity used for de-duplication.

        Query parameter order matters for cache keys and some frameworks but
        not for "have I already scanned this endpoint" bookkeeping, so sorted
        parameters are used here.
        """

        items = sorted(self.query.get_all())
        query = "&".join(f"{key}={value}" for key, value in items)
        return f"{self.scheme}://{self.netloc}{self.path}?{query}"

    def same_origin(self, other: "URL | str") -> bool:
        if isinstance(other, str):
            other = URL.parse(other)
        return self.origin.lower() == other.origin.lower()

    def same_host(self, other: "URL | str") -> bool:
        if isinstance(other, str):
            try:
                other = URL.parse(other)
            except ValueError:
                return self.host == other.lower()
        return self.host == other.host

    def is_https(self) -> bool:
        return self.scheme in {"https", "wss"}

    def depth(self) -> int:
        return len([segment for segment in self.path.split("/") if segment])

    def parent(self) -> "URL":
        parent = posixpath.dirname(self.path.rstrip("/")) or "/"
        clone = self.copy()
        clone.path = parent if parent.startswith("/") else "/" + parent
        clone.query = QueryParams()
        clone.fragment = ""
        return clone

    def with_suffix(self, suffix: str) -> "URL":
        clone = self.copy()
        clone.path = self.path.rstrip("/") + suffix
        return clone


# ----------------------------------------------------------------------
# module level helpers
# ----------------------------------------------------------------------
def normalize_url(raw: str | URL, *, keep_query: bool = True) -> str:
    url = URL.parse(raw)
    if not keep_query:
        url.query = QueryParams()
    url.scheme = url.scheme.lower()
    url.host = url.host.lower()
    url.path = _normalise_percent(url.path)
    if url.path != "/" and url.path.endswith("/"):
        url.path = url.path.rstrip("/")
    return url.render()


def join_url(base: str | URL, reference: str, *, keep_fragment: bool = False) -> URL:
    """Resolve ``reference`` against ``base`` following RFC 3986 semantics."""

    base_url = URL.parse(base)
    reference = (reference or "").strip()
    if not reference:
        return base_url
    if reference.startswith("//"):
        clone = base_url.copy()
        parsed = URL.parse(f"{base_url.scheme}:{reference}")
        clone.host = parsed.host
        clone.port = parsed.port
        clone.path = parsed.path
        clone.query = parsed.query
        return clone
    if "://" in reference:
        return URL.parse(reference)
    if reference.startswith("#"):
        return base_url.with_fragment(reference[1:])
    if reference.startswith("?"):
        return base_url.with_query(reference[1:])
    if reference.startswith("/"):
        clone = base_url.with_path(reference.split("?")[0])
        if "?" in reference:
            clone.query = QueryParams.parse(reference.split("?", 1)[1])
        else:
            clone.query = QueryParams()
        return clone
    base_dir = posixpath.dirname(base_url.path.rstrip("/")) or "/"
    joined = posixpath.normpath(posixpath.join(base_dir, reference.split("?")[0]))
    clone = base_url.with_path(joined if joined.startswith("/") else "/" + joined)
    if "?" in reference:
        clone.query = QueryParams.parse(reference.split("?", 1)[1])
    else:
        clone.query = QueryParams()
    return clone


def encode_component(value: str, *, safe: str = "") -> str:
    return quote(str(value), safe=safe)


def decode_component(value: str) -> str:
    return unquote(value.replace("+", " "))


def query_string(mapping: dict[str, Any]) -> str:
    return QueryParams.from_mapping(mapping).render()


def host_matches(host: str, pattern: str) -> bool:
    host = host.lower().strip(".")
    pattern = pattern.lower().strip(".")
    if pattern.startswith("*."):
        suffix = pattern[2:]
        return host == suffix or host.endswith("." + suffix)
    if pattern.startswith("."):
        suffix = pattern[1:]
        return host == suffix or host.endswith("." + suffix)
    return host == pattern


def is_loopback(host: str) -> bool:
    if host in {"localhost", "localhost.localdomain"}:
        return True
    try:
        return ipaddress.ip_address(host.split("%")[0]).is_loopback
    except ValueError:
        return False


def is_private(host: str) -> bool:
    try:
        address = ipaddress.ip_address(host.split("%")[0])
    except ValueError:
        return False
    return address.is_private or address.is_link_local or address.is_reserved


def strip_port(authority: str) -> str:
    match = _HOST_PORT_RE.match(authority)
    return match.group("host") if match else authority


def dedupe_urls(urls: Iterable[str | URL]) -> list[str]:
    seen: dict[str, None] = {}
    for raw in urls:
        try:
            key = URL.parse(raw).dedupe_key()
        except ValueError:
            continue
        seen.setdefault(key, None)
    return list(seen)


def sort_urls(urls: Iterable[str | URL]) -> list[str]:
    def key(raw: str | URL) -> tuple[str, int, str]:
        url = URL.parse(raw)
        return (url.host, url.effective_port or 0, url.path + "?" + url.query.render())

    return [URL.parse(raw).render() for raw in sorted(urls, key=key)]


def path_segments(url: str | URL) -> list[str]:
    parsed = URL.parse(url)
    return [segment for segment in parsed.path.split("/") if segment]


def is_static_asset(url: str) -> bool:
    path = URL.parse(url).path.lower()
    return any(
        path.endswith(extension)
        for extension in (
            ".css", ".js.map", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff",
            ".woff2", ".ttf", ".eot", ".mp4", ".webm", ".mp3", ".wav", ".pdf", ".zip",
        )
    )


__all__ = [
    "DEFAULT_PORTS",
    "URL",
    "QueryParams",
    "decode_component",
    "dedupe_urls",
    "encode_component",
    "host_matches",
    "is_loopback",
    "is_private",
    "is_static_asset",
    "join_url",
    "normalize_url",
    "path_segments",
    "query_string",
    "sort_urls",
    "strip_port",
]
