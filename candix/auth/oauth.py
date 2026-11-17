"""OAuth 2.0 / OpenID Connect helpers for authorisation testing."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Iterable

COMMON_REDIRECT_PARAMS = ("redirect_uri", "redirect_url", "return_url", "callback", "next", "returnTo", "continue")
DANGEROUS_SCOPES = ("admin", "write", "offline_access", "openid", "profile", "email", "*.all")
PKCE_CHARSET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"


@dataclass
class OAuthRequest:
    authorization_endpoint: str
    client_id: str
    redirect_uri: str
    scope: str = "openid"
    state: str = ""
    response_type: str = "code"
    extra: dict[str, str] = field(default_factory=dict)

    def url(self) -> str:
        params = {
            "response_type": self.response_type,
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "scope": self.scope,
        }
        if self.state:
            params["state"] = self.state
        params.update(self.extra)
        return f"{self.authorization_endpoint}?{urllib.parse.urlencode(params)}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "authorization_endpoint": self.authorization_endpoint,
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "scope": self.scope,
            "state": self.state,
            "response_type": self.response_type,
            "url": self.url(),
        }


def random_state(length: int = 24) -> str:
    return base64.urlsafe_b64encode(os.urandom(length)).decode("ascii").rstrip("=")


def pkce_pair(length: int = 64) -> tuple[str, str]:
    verifier = "".join(PKCE_CHARSET[b % len(PKCE_CHARSET)] for b in os.urandom(length))
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return verifier, challenge


def parse_authorization_endpoint(url: str) -> OAuthRequest:
    parts = urllib.parse.urlsplit(url)
    params = dict(urllib.parse.parse_qsl(parts.query, keep_blank_values=True))
    base = urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))
    known = {"client_id", "redirect_uri", "scope", "state", "response_type"}
    extra = {key: value for key, value in params.items() if key not in known}
    return OAuthRequest(
        authorization_endpoint=base,
        client_id=params.get("client_id", ""),
        redirect_uri=params.get("redirect_uri", ""),
        scope=params.get("scope", ""),
        state=params.get("state", ""),
        response_type=params.get("response_type", "code"),
        extra=extra,
    )


def redirect_uri_variants(redirect_uri: str, attacker: str = "https://candix.example") -> list[tuple[str, str]]:
    """Generate candidate redirect_uri manipulations with a description."""

    parts = urllib.parse.urlsplit(redirect_uri)
    host = parts.netloc
    path = parts.path or "/"
    variants: list[tuple[str, str]] = [
        (f"{attacker}{path}", "absolute attacker host"),
        (f"{attacker}/{host}{path}", "attacker host with victim in path"),
        (f"{attacker}?{host}", "attacker host with victim in query"),
        (f"{attacker}#{host}", "attacker host with victim in fragment"),
        (f"{parts.scheme}://{host}@{urllib.parse.urlsplit(attacker).netloc}{path}", "userinfo confusion"),
        (f"{parts.scheme}://{host}.{urllib.parse.urlsplit(attacker).netloc}{path}", "suffix confusion"),
        (f"{parts.scheme}://{host}{path}/{urllib.parse.urlsplit(attacker).netloc}", "path suffix"),
        (f"{parts.scheme}://{host.upper()}{path}", "case variation"),
        (f"{parts.scheme}://{host}{path}/../{urllib.parse.urlsplit(attacker).netloc}", "traversal"),
        (f"{redirect_uri}?next={urllib.parse.quote(attacker)}", "open redirect chaining"),
        (redirect_uri.replace("https://", "http://"), "scheme downgrade"),
        (redirect_uri + "/", "trailing slash"),
        (redirect_uri + ".attacker.example", "dot suffix"),
        (redirect_uri.replace(host, "localhost"), "localhost swap"),
        (redirect_uri.replace(host, "127.0.0.1"), "loopback swap"),
    ]
    seen: set[str] = set()
    unique: list[tuple[str, str]] = []
    for value, description in variants:
        if value in seen or value == redirect_uri:
            continue
        seen.add(value)
        unique.append((value, description))
    return unique


@dataclass
class OidcMetadata:
    issuer: str = ""
    authorization_endpoint: str = ""
    token_endpoint: str = ""
    userinfo_endpoint: str = ""
    jwks_uri: str = ""
    scopes_supported: list[str] = field(default_factory=list)
    response_types_supported: list[str] = field(default_factory=list)
    grant_types_supported: list[str] = field(default_factory=list)
    pkce_methods: list[str] = field(default_factory=list)

    @classmethod
    def from_document(cls, document: dict[str, Any]) -> "OidcMetadata":
        return cls(
            issuer=str(document.get("issuer", "")),
            authorization_endpoint=str(document.get("authorization_endpoint", "")),
            token_endpoint=str(document.get("token_endpoint", "")),
            userinfo_endpoint=str(document.get("userinfo_endpoint", "")),
            jwks_uri=str(document.get("jwks_uri", "")),
            scopes_supported=[str(item) for item in document.get("scopes_supported", []) or []],
            response_types_supported=[str(item) for item in document.get("response_types_supported", []) or []],
            grant_types_supported=[str(item) for item in document.get("grant_types_supported", []) or []],
            pkce_methods=[str(item) for item in document.get("code_challenge_methods_supported", []) or []],
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "issuer": self.issuer,
            "authorization_endpoint": self.authorization_endpoint,
            "token_endpoint": self.token_endpoint,
            "userinfo_endpoint": self.userinfo_endpoint,
            "jwks_uri": self.jwks_uri,
            "scopes_supported": list(self.scopes_supported),
            "response_types_supported": list(self.response_types_supported),
            "grant_types_supported": list(self.grant_types_supported),
            "pkce_methods": list(self.pkce_methods),
        }

    def findings(self) -> list[str]:
        issues: list[str] = []
        if self.response_types_supported and "token" in self.response_types_supported:
            issues.append("implicit flow is advertised (response_type=token)")
        if not self.pkce_methods:
            issues.append("PKCE is not advertised for the authorisation code flow")
        if "password" in self.grant_types_supported:
            issues.append("resource owner password grant is enabled")
        if "client_credentials" in self.grant_types_supported:
            issues.append("client credentials grant is enabled; confirm client secrets are scoped")
        if self.issuer and not self.issuer.startswith("https://"):
            issues.append("issuer is not served over HTTPS")
        return issues


def discovery_urls(issuer: str) -> list[str]:
    base = issuer.rstrip("/")
    return [
        f"{base}/.well-known/openid-configuration",
        f"{base}/.well-known/oauth-authorization-server",
        f"{base}/oauth/.well-known/openid-configuration",
        f"{base}/auth/.well-known/openid-configuration",
    ]


def parse_authorization_response(location: str) -> dict[str, Any]:
    parts = urllib.parse.urlsplit(location)
    params = dict(urllib.parse.parse_qsl(parts.query, keep_blank_values=True))
    fragment = dict(urllib.parse.parse_qsl(parts.fragment, keep_blank_values=True))
    return {
        "location": location,
        "host": parts.netloc,
        "code": params.get("code", ""),
        "state": params.get("state", ""),
        "error": params.get("error", "") or fragment.get("error", ""),
        "access_token_in_fragment": "access_token" in fragment,
        "has_query": bool(parts.query),
        "has_fragment": bool(parts.fragment),
    }


def scope_analysis(scope: str) -> dict[str, Any]:
    granted = [item for item in re.split(r"[\s,]+", scope or "") if item]
    risky = [item for item in granted if item.lower() in DANGEROUS_SCOPES]
    return {
        "scopes": granted,
        "risky": risky,
        "count": len(granted),
        "wildcard": any(item == "*" or item.endswith(".*") for item in granted),
    }


def state_entropy(state: str) -> float:
    if not state:
        return 0.0
    counts = {char: state.count(char) for char in set(state)}
    entropy = 0.0
    for count in counts.values():
        p = count / len(state)
        entropy -= p * (p and __import__("math").log2(p))
    return entropy


def expires_soon(document: dict[str, Any], *, margin: int = 60) -> bool:
    expires = document.get("expires_at") or document.get("exp")
    if expires is None:
        return False
    try:
        value = float(expires)
    except (TypeError, ValueError):
        return False
    if value > 10_000_000_000:
        value /= 1000.0
    return value - time.time() < margin


def summarize_request(request: OAuthRequest) -> str:
    scopes = scope_analysis(request.scope)
    return (
        f"client {request.client_id or '(unknown)'} → {request.redirect_uri or '(no redirect)'} "
        f"· scopes {scopes['count']} · risky {', '.join(scopes['risky']) or 'none'}"
    )


def safe_scope_label(scope: str) -> str:
    return re.sub(r"[^a-z0-9:_-]+", "-", scope.lower())[:40]
