"""Cookie parsing and session handling.

The harness keeps a per-host cookie jar so that a crawl stays authenticated
after a login, and exposes cookie attribute analysis used by the cookie
hardening detector.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Iterable
from urllib.parse import urlsplit


@dataclass
class Cookie:
    name: str
    value: str
    domain: str = ""
    path: str = "/"
    secure: bool = False
    http_only: bool = False
    same_site: str = ""
    expires: float | None = None
    max_age: int | None = None
    host_only: bool = True
    raw: str = ""
    session: bool = True

    def is_expired(self, now: float | None = None) -> bool:
        if self.expires is None:
            return False
        return (now or time.time()) > self.expires

    def matches(self, host: str, path: str) -> bool:
        if self.domain:
            domain = self.domain.lstrip(".")
            if host != domain and not host.endswith("." + domain):
                return False
            if self.host_only and host != domain:
                return False
        return path.startswith(self.path or "/")

    def set_cookie(self) -> str:
        parts = [f"{self.name}={self.value}"]
        if self.domain:
            parts.append(f"Domain={self.domain}")
        if self.path:
            parts.append(f"Path={self.path}")
        if self.expires:
            parts.append(f"Expires={time.strftime('%a, %d %b %Y %H:%M:%S GMT', time.gmtime(self.expires))}")
        if self.max_age is not None:
            parts.append(f"Max-Age={self.max_age}")
        if self.secure:
            parts.append("Secure")
        if self.http_only:
            parts.append("HttpOnly")
        if self.same_site:
            parts.append(f"SameSite={self.same_site}")
        return "; ".join(parts)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "domain": self.domain,
            "path": self.path,
            "secure": self.secure,
            "http_only": self.http_only,
            "same_site": self.same_site,
            "session": self.session,
        }


def parse_set_cookie(header: str, host: str = "") -> Cookie | None:
    if not header or "=" not in header:
        return None
    segments = [segment.strip() for segment in header.split(";") if segment.strip()]
    name, _, value = segments[0].partition("=")
    name = name.strip()
    if not name or name.lower() in {"expires", "max-age", "path", "domain", "secure", "httponly", "samesite"}:
        return None
    cookie = Cookie(name=name, value=value.strip(), domain=host, raw=header)
    for segment in segments[1:]:
        key, _, raw = segment.partition("=")
        key_lower = key.strip().lower()
        raw = raw.strip()
        if key_lower == "domain":
            cookie.domain = raw.lstrip(".").lower()
            cookie.host_only = False
        elif key_lower == "path":
            cookie.path = raw or "/"
        elif key_lower == "secure":
            cookie.secure = True
        elif key_lower == "httponly":
            cookie.http_only = True
        elif key_lower == "samesite":
            cookie.same_site = raw
        elif key_lower == "max-age":
            try:
                cookie.max_age = int(raw)
                cookie.expires = time.time() + cookie.max_age
                cookie.session = False
            except ValueError:
                continue
        elif key_lower == "expires":
            cookie.expires = _parse_cookie_time(raw)
            cookie.session = False
    return cookie


def _parse_cookie_time(value: str) -> float | None:
    formats = (
        "%a, %d %b %Y %H:%M:%S GMT",
        "%a, %d-%b-%Y %H:%M:%S GMT",
        "%a, %d %b %Y %H:%M:%S",
        "%d-%b-%Y %H:%M:%S GMT",
    )
    for fmt in formats:
        try:
            import calendar

            return float(calendar.timegm(time.strptime(value, fmt)))
        except ValueError:
            continue
    return None


def parse_cookie_header(header: str, host: str = "") -> list[Cookie]:
    cookies: list[Cookie] = []
    for chunk in (header or "").split(";"):
        name, _, value = chunk.strip().partition("=")
        if name and value:
            cookies.append(Cookie(name=name.strip(), value=value.strip(), domain=host))
    return cookies


class CookieJar:
    """Minimal RFC 6265 cookie store."""

    def __init__(self) -> None:
        self._cookies: dict[tuple[str, str, str], Cookie] = {}
        self._lock = None

    def __len__(self) -> int:
        return len(self._cookies)

    def add(self, cookie: Cookie) -> None:
        if not cookie.name:
            return
        key = (cookie.domain or "*", cookie.path or "/", cookie.name)
        if cookie.is_expired() or cookie.max_age == 0:
            self._cookies.pop(key, None)
            return
        self._cookies[key] = cookie

    def add_from_headers(self, url: str, set_cookie_headers: Iterable[str]) -> list[Cookie]:
        parts = urlsplit(url)
        host = parts.hostname or ""
        added: list[Cookie] = []
        for header in set_cookie_headers:
            cookie = parse_set_cookie(header, host)
            if cookie is not None:
                self.add(cookie)
                added.append(cookie)
        return added

    def for_url(self, url: str) -> list[Cookie]:
        parts = urlsplit(url)
        host = parts.hostname or ""
        path = parts.path or "/"
        return [
            cookie
            for cookie in self._cookies.values()
            if cookie.matches(host, path) and not cookie.is_expired()
        ]

    def header(self, url: str) -> str:
        return "; ".join(f"{cookie.name}={cookie.value}" for cookie in self.for_url(url))

    def as_dict(self, url: str | None = None) -> dict[str, str]:
        if url is not None:
            return {cookie.name: cookie.value for cookie in self.for_url(url)}
        return {cookie.name: cookie.value for cookie in self._cookies.values()}

    def set(self, name: str, value: str, *, domain: str = "", path: str = "/", secure: bool = False) -> None:
        self.add(Cookie(name=name, value=value, domain=domain, path=path, secure=secure))

    def remove(self, name: str) -> None:
        for key in [key for key in self._cookies if key[2] == name]:
            self._cookies.pop(key, None)

    def clear(self) -> None:
        self._cookies.clear()

    def all(self) -> list[Cookie]:
        return list(self._cookies.values())

    def to_list(self) -> list[dict[str, Any]]:
        return [cookie.to_dict() for cookie in self._cookies.values()]

    def import_pairs(self, pairs: dict[str, str], host: str, *, path: str = "/") -> None:
        for name, value in pairs.items():
            self.set(name, value, domain=host, path=path)

    def clone(self) -> "CookieJar":
        jar = CookieJar()
        for cookie in self._cookies.values():
            jar.add(cookie)
        return jar


@dataclass
class CookieIssue:
    cookie: str
    problem: str
    severity: str
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "cookie": self.cookie,
            "problem": self.problem,
            "severity": self.severity,
            "detail": self.detail,
        }


def analyze_cookies(cookies: Iterable[Cookie], *, https: bool = True) -> list[CookieIssue]:
    """Flag missing hardening attributes and weak session identifiers."""

    issues: list[CookieIssue] = []
    for cookie in cookies:
        name_lower = cookie.name.lower()
        session_like = any(
            token in name_lower
            for token in ("sess", "sid", "auth", "token", "jwt", "login", "user", "remember", "csrf", "xsrf")
        )
        if not cookie.secure and https:
            issues.append(
                CookieIssue(
                    cookie=cookie.name,
                    problem="missing_secure",
                    severity="medium" if session_like else "low",
                    detail="cookie is sent over plaintext HTTP connections",
                )
            )
        if not cookie.http_only and session_like:
            issues.append(
                CookieIssue(
                    cookie=cookie.name,
                    problem="missing_httponly",
                    severity="medium",
                    detail="session cookie is readable from JavaScript, enabling token theft via XSS",
                )
            )
        if not cookie.same_site:
            issues.append(
                CookieIssue(
                    cookie=cookie.name,
                    problem="missing_samesite",
                    severity="medium" if session_like else "low",
                    detail="no SameSite attribute; browser defaults vary and CSRF risk increases",
                )
            )
        elif cookie.same_site.lower() == "none" and not cookie.secure:
            issues.append(
                CookieIssue(
                    cookie=cookie.name,
                    problem="samesite_none_insecure",
                    severity="medium",
                    detail="SameSite=None requires the Secure attribute and is rejected by modern browsers",
                )
            )
        if session_like and len(cookie.value) < 16 and cookie.value.isalnum():
            issues.append(
                CookieIssue(
                    cookie=cookie.name,
                    problem="weak_session_id",
                    severity="medium",
                    detail=f"session identifier is only {len(cookie.value)} characters",
                )
            )
    return issues
