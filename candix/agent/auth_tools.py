"""Authentication, token and OAuth checks as agent tools.

Everything here is bounded on purpose: at most a handful of login attempts, a
short secret list, and no request ever leaves the engagement scope. The goal is
to prove a weakness, not to break into an account.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote, urlencode

from candix.agent.web import Fetch, fetch, form_fields, csrf_token, join
from candix.auth.jwt import crack_hs256, forge_none, inspect_token
from candix.auth.oauth import OidcMetadata, discovery_urls, pkce_pair, redirect_uri_variants, scope_analysis
from candix.auth.session import analyse_cookies, compare_sessions, parse_set_cookie
from candix.catalog.wordlists import PASSWORDS
from candix.core.log import get_logger

log = get_logger("candix.agent.auth")

LOGIN_PATHS = ("/login", "/signin", "/auth/login", "/session/new", "/account/login", "/users/sign_in")
_ANONYMOUS_MARKERS = ("sign in", "signin", "login", "log in")
_ERROR_MARKERS = ("invalid", "incorrect", "wrong", "failed", "not found", "unknown")


@dataclass
class LoginOutcome:
    url: str
    form_action: str = ""
    fields: list[str] = field(default_factory=list)
    status: int = 0
    redirected: bool = False
    authenticated: bool = False
    cookies_before: list[dict[str, Any]] = field(default_factory=list)
    cookies_after: list[dict[str, Any]] = field(default_factory=list)
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "form_action": self.form_action,
            "fields": self.fields,
            "status": self.status,
            "redirected": self.redirected,
            "authenticated": self.authenticated,
            "error": self.error,
            "cookies_before": self.cookies_before,
            "cookies_after": self.cookies_after,
        }

    def summary(self) -> str:
        state = "authenticated" if self.authenticated else "not authenticated"
        return f"{state} at {self.form_action or self.url} (status {self.status}, {len(self.cookies_after)} cookie(s))"


def _cookie_dict(record: Fetch, *, host: str = "") -> list[dict[str, Any]]:
    header = record.headers.get("set-cookie", "")
    if not header:
        return []
    return [parse_set_cookie(part, host=host).to_dict() for part in header.split(",") if "=" in part][:10]


def find_login(ctx: Any, base: str) -> Fetch | None:
    for path in ("",) + LOGIN_PATHS:
        record = fetch(ctx, base if not path else join(base, path))
        if record.error or record.status >= 400:
            continue
        if form_fields(record):
            return record
    return None


def login(
    ctx: Any,
    page: Fetch,
    *,
    username: str,
    password: str,
    headers: dict[str, str] | None = None,
) -> LoginOutcome:
    fields = {field["name"]: field["value"] for field in form_fields(page)}
    action = ""
    try:
        forms = list(page.doc().forms())
        action = join(page.url, getattr(forms[0], "action", "") or page.url)
    except Exception:
        action = page.url
    outcome = LoginOutcome(url=page.url, form_action=action, fields=sorted(fields))
    outcome.cookies_before = _cookie_dict(page)

    token_name, token_value = csrf_token(page)
    if token_name and token_name not in fields:
        fields[token_name] = token_value
    user_field = next((name for name in fields if any(marker in name.lower() for marker in ("user", "email", "login"))), "username")
    pass_field = next((name for name in fields if "pass" in name.lower()), "password")
    fields[user_field] = username
    fields[pass_field] = password
    payload = urlencode({name: value for name, value in fields.items() if name})

    merged = {
        "content-type": "application/x-www-form-urlencoded",
        "accept": "text/html,application/xhtml+xml",
    }
    merged.update(headers or {})
    response = fetch(ctx, action, method="POST", body=payload, headers=merged, follow=False)
    outcome.status = response.status
    outcome.redirected = response.status in (301, 302, 303, 307, 308) or bool(response.headers.get("location"))
    outcome.cookies_after = _cookie_dict(response)
    if response.error:
        outcome.error = response.error
        return outcome

    body = response.body.lower()
    if outcome.redirected:
        location = response.headers.get("location", "")
        outcome.authenticated = not any(marker in location.lower() for marker in ("login", "error", "denied"))
    else:
        outcome.authenticated = pass_field not in body and not any(marker in body[:4000] for marker in _ERROR_MARKERS)
    if not outcome.authenticated and any(marker in body[:4000] for marker in _ANONYMOUS_MARKERS):
        outcome.authenticated = False
    return outcome


def session_findings(outcome: LoginOutcome, page: Fetch | None = None) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    if outcome.cookies_before and outcome.cookies_after:
        before = [parse_set_cookie(name + "=" + str(item.get("value", "")), host="") for item in outcome.cookies_before for name in [str(item.get("name", "session"))]]
        after = [parse_set_cookie(name + "=" + str(item.get("value", "")), host="") for item in outcome.cookies_after for name in [str(item.get("name", "session"))]]
        report = compare_sessions(before, after)
        if getattr(report, "fixed", False):
            findings.append(
                {
                    "title": "Session identifier does not rotate after login",
                    "severity": "medium",
                    "category": "session",
                    "detector": "agent.auth_flow",
                    "url": outcome.form_action,
                    "description": "The session cookie sent before authentication is still accepted afterwards.",
                    "impact": "An attacker who fixes a victim's session id can ride the authenticated session.",
                    "remediation": "Issue a new session id on privilege change and invalidate the previous one.",
                    "confidence": "likely",
                    "verified": False,
                    "tags": ["session", "authentication"],
                }
            )
    cookies = [parse_set_cookie(str(item.get("name", "session")) + "=" + str(item.get("value", ""))) for item in outcome.cookies_after]
    if cookies:
        report = analyse_cookies(cookies)
        for issue in getattr(report, "issues", []) or []:
            findings.append(
                {
                    "title": f"Session cookie weakness: {issue}",
                    "severity": "low",
                    "category": "session",
                    "detector": "agent.auth_flow",
                    "url": outcome.form_action,
                    "description": str(issue),
                    "impact": "Weakened cookie attributes make session theft easier once another bug is found.",
                    "remediation": "Set HttpOnly, Secure and SameSite on session cookies.",
                    "confidence": "observed",
                    "verified": True,
                    "tags": ["session", "cookies"],
                }
            )
    return findings


def enumeration_check(ctx: Any, page: Fetch, action: str, *, field_name: str, headers: dict[str, str] | None = None) -> dict[str, Any]:
    """Compare the error text for a real and an imaginary account."""

    base_fields = {field["name"]: field["value"] for field in form_fields(page)}

    def attempt(user: str) -> str:
        payload_fields = dict(base_fields)
        payload_fields[field_name] = user
        for name in list(payload_fields):
            if "pass" in name.lower():
                payload_fields[name] = "definitely-not-the-password"
        body = urlencode(payload_fields)
        record = fetch(ctx, action, method="POST", body=body, headers={"content-type": "application/x-www-form-urlencoded"})
        text = (record.body or "").lower()
        for marker in _ERROR_MARKERS:
            position = text.find(marker)
            if position >= 0:
                return text[max(0, position - 20) : position + 80]
        return text[:120]

    known = attempt("admin")
    unknown = attempt("candix-user-that-does-not-exist-" + str(len(base_fields)))
    different = known != unknown and bool(known) and bool(unknown)
    return {"known": known[:120], "unknown": unknown[:120], "different": different}


def login_findings(outcome: LoginOutcome) -> list[dict[str, Any]]:
    if outcome.authenticated or not outcome.form_action:
        return []
    return []


def tool_auth_flow(ctx: Any, arguments: dict[str, Any]) -> dict[str, Any]:
    base = str(arguments.get("url", "")).rstrip("/")
    if not base:
        targets = list(ctx.state.get("targets") or [])
        base = targets[0] if targets else ""
    username = str(arguments.get("username", "candix-test"))
    password = str(arguments.get("password", "candix-test-password"))
    page = find_login(ctx, base)
    if page is None:
        return {"summary": f"no login form found under {base}", "findings": []}
    outcome = login(ctx, page, username=username, password=password)
    findings = session_findings(outcome)
    enabling = enumeration_check(
        ctx,
        page,
        outcome.form_action,
        field_name=next((name for name in outcome.fields if any(m in name.lower() for m in ("user", "email", "login"))), "username"),
        headers=None,
    )
    if enabling["different"]:
        findings.append(
            {
                "title": "Login response differs for unknown accounts",
                "severity": "low",
                "category": "authentication",
                "detector": "agent.auth_flow",
                "url": outcome.form_action,
                "description": "The error message for a real account differs from the one for an unknown account.",
                "impact": "An attacker can confirm which usernames exist before trying passwords.",
                "remediation": "Return one generic failure message and one timing profile for every login failure.",
                "confidence": "observed",
                "verified": False,
                "tags": ["authentication", "enumeration"],
            }
        )
    return {
        "summary": outcome.summary(),
        "login": outcome.to_dict(),
        "enumeration": enabling,
        "findings": findings,
    }


# ----------------------------------------------------------------- token
def tool_jwt_inspect(ctx: Any, arguments: dict[str, Any]) -> dict[str, Any]:
    token = str(arguments.get("token", "")).strip()
    if not token:
        observed = ctx.state.get("jwt") or ""
        token = str(observed)
    if not token:
        return {"summary": "no token supplied", "findings": []}
    issues = [issue.to_dict() if hasattr(issue, "to_dict") else {"detail": str(issue)} for issue in inspect_token(token)]
    findings: list[dict[str, Any]] = []
    url = str(arguments.get("url", ""))
    header_name = str(arguments.get("header", "Authorization"))
    secret = ""
    if arguments.get("crack", True):
        secret = crack_hs256(token, PASSWORDS[:200]) or ""
        if secret:
            findings.append(
                {
                    "title": "JWT signed with a guessable secret",
                    "severity": "critical",
                    "category": "authentication",
                    "detector": "agent.jwt",
                    "url": url,
                    "description": "The HS256 signature verifies with a secret from a short common-password list.",
                    "impact": "Anyone can mint a token with arbitrary claims, including administrative roles.",
                    "remediation": "Rotate the signing secret and use a 256-bit random value.",
                    "confidence": "confirmed",
                    "verified": True,
                    "tags": ["jwt", "authentication"],
                }
            )
    accepted_none = False
    if url:
        from candix.auth.jwt import decode_unverified

        _header, claims, _signature = decode_unverified(token)
        forged = forge_none(claims)
        baseline = fetch(ctx, url)
        attempt = fetch(ctx, url, headers={header_name: f"Bearer {forged}"})
        accepted_none = attempt.status == 200 and baseline.status in (401, 403)
        if accepted_none:
            findings.append(
                {
                    "title": "JWT accepts an unsigned token",
                    "severity": "critical",
                    "category": "authentication",
                    "detector": "agent.jwt",
                    "url": url,
                    "description": "A token with alg=none is accepted while the anonymous request is rejected.",
                    "impact": "Signature verification can be bypassed entirely.",
                    "remediation": "Reject tokens whose algorithm is not on an allow-list.",
                    "confidence": "confirmed",
                    "verified": True,
                    "tags": ["jwt", "authentication"],
                }
            )
    for issue in issues:
        severity = "low"
        detail = str(issue.get("detail") or issue.get("code") or issue)
        if "expired" in detail.lower():
            severity = "low"
        findings.append(
            {
                "title": f"JWT issue: {detail[:60]}",
                "severity": severity,
                "category": "authentication",
                "detector": "agent.jwt",
                "url": url,
                "description": detail[:300],
                "impact": "Token handling weakness that can widen the impact of a stolen token.",
                "remediation": "Validate algorithm, expiry, audience and issuer on every request.",
                "confidence": "observed",
                "verified": False,
                "tags": ["jwt"],
            }
        )
    summary = f"{len(issues)} token issue(s)"
    if secret:
        summary += ", signing secret guessed"
    if accepted_none:
        summary += ", alg=none accepted"
    return {
        "summary": summary,
        "issues": issues,
        "secret": secret,
        "accepted_none": accepted_none,
        "findings": findings,
    }


# ----------------------------------------------------------------- oauth
def tool_oauth_flow(ctx: Any, arguments: dict[str, Any]) -> dict[str, Any]:
    issuer = str(arguments.get("issuer") or arguments.get("url") or "").rstrip("/")
    if not issuer:
        targets = list(ctx.state.get("targets") or [])
        issuer = targets[0] if targets else ""
    metadata: OidcMetadata | None = None
    discovered = ""
    for candidate in discovery_urls(issuer):
        record = fetch(ctx, candidate)
        if record.status == 200 and record.body.strip().startswith("{"):
            payload = record.json() or {}
            if "issuer" in payload or "authorization_endpoint" in payload:
                metadata = OidcMetadata.from_document(payload)
                discovered = candidate
                break
    if metadata is None:
        return {"summary": f"no OIDC metadata found for {issuer}", "findings": []}

    findings: list[dict[str, Any]] = []
    if not metadata.pkce_methods:
        findings.append(
            {
                "title": "Authorization server does not advertise PKCE",
                "severity": "low",
                "category": "oauth",
                "detector": "agent.oauth",
                "url": discovered,
                "description": "The metadata lists no code_challenge_methods_supported entry.",
                "impact": "Public clients cannot protect the authorization code flow against interception.",
                "remediation": "Support S256 PKCE and require it for public clients.",
                "confidence": "likely",
                "verified": False,
                "tags": ["oauth", "pkce"],
            }
        )
    if "token" in metadata.response_types_supported:
        findings.append(
            {
                "title": "Implicit flow is advertised",
                "severity": "low",
                "category": "oauth",
                "detector": "agent.oauth",
                "url": discovered,
                "description": "response_types_supported includes token, exposing access tokens in the URL fragment.",
                "impact": "Tokens leak through history, referrers and logs.",
                "remediation": "Remove the implicit flow and use authorization code with PKCE.",
                "confidence": "observed",
                "verified": False,
                "tags": ["oauth"],
            }
        )

    redirect_test: dict[str, Any] = {}
    client_id = str(arguments.get("client_id", ""))
    redirect_uri = str(arguments.get("redirect_uri", ""))
    if metadata.authorization_endpoint and client_id and redirect_uri:
        _verifier, _challenge = pkce_pair()
        variants = redirect_uri_variants(redirect_uri)[:3]
        accepted: list[str] = []
        for label, candidate in variants:
            query = urlencode(
                {
                    "response_type": "code",
                    "client_id": client_id,
                    "redirect_uri": candidate,
                    "scope": str(arguments.get("scope", "openid")),
                    "state": "candix",
                }
            )
            record = fetch(ctx, metadata.authorization_endpoint + "?" + query)
            location = record.headers.get("location", "")
            if record.status in (301, 302, 303) and location.startswith(candidate.rstrip("/")):
                accepted.append(label)
        redirect_test = {"variants": [label for label, _ in variants], "accepted": accepted}
        if accepted:
            findings.append(
                {
                    "title": "Redirect URI matching is lax",
                    "severity": "high",
                    "category": "oauth",
                    "detector": "agent.oauth",
                    "url": metadata.authorization_endpoint,
                    "description": f"The authorization endpoint redirected to these manipulated URIs: {', '.join(accepted)}.",
                    "impact": "An attacker can receive authorization codes meant for the client.",
                    "remediation": "Compare redirect_uri against an exact allow-list.",
                    "confidence": "confirmed",
                    "verified": True,
                    "tags": ["oauth", "redirect"],
                }
            )

    return {
        "summary": (
            f"OIDC metadata at {discovered}: {len(metadata.scopes_supported)} scope(s), "
            f"pkce={'yes' if metadata.pkce_methods else 'no'}"
        ),
        "metadata": {
            "issuer": metadata.issuer,
            "authorization_endpoint": metadata.authorization_endpoint,
            "token_endpoint": metadata.token_endpoint,
            "scopes": metadata.scopes_supported,
            "response_types": metadata.response_types_supported,
            "pkce": metadata.pkce_methods,
        },
        "scopes": scope_analysis(" ".join(metadata.scopes_supported)) if metadata.scopes_supported else {},
        "redirect_test": redirect_test,
        "findings": findings,
    }
