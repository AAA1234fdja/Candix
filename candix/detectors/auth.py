"""Authentication controls: default credentials, enumeration and throttling."""

from __future__ import annotations

import statistics
import time
from typing import Iterable

from candix.catalog.wordlists import credential_pairs
from candix.core.endpoint import Endpoint
from candix.core.finding import Finding
from candix.core.severity import Confidence, Severity
from candix.detectors.base import BaseDetector, DetectorMeta, register_detector
from candix.net.http import Response

_SUCCESS_MARKERS = ("welcome", "dashboard", "logout", "sign out", "my account", "profile", "admin")
_FAILURE_MARKERS = ("invalid", "incorrect", "failed", "try again", "denied", "wrong", "not found", "unknown user")
_PROTECTIVE_MARKERS = ("captcha", "too many", "locked", "rate limit", "retry later", "slow down")


@register_detector
class AuthDetector(BaseDetector):
    meta = DetectorMeta(
        id="auth",
        name="Authentication weaknesses",
        category="auth",
        description="Tests default credentials, username enumeration, missing lockout and weak login responses on discovered forms.",
        severity=Severity.HIGH,
        cwe=("CWE-287", "CWE-307", "CWE-204"),
        owasp=("A07:2021 Identification and Authentication Failures",),
        intrusive=True,
        tags=("authentication", "brute-force"),
        order=105,
        remediation_key="auth",
    )

    def run(self) -> Iterable[Finding]:
        seen: set[str] = set()
        for endpoint in self._login_endpoints():
            key = endpoint.identity()
            if key in seen:
                continue
            seen.add(key)
            try:
                yield from self._analyze_login(endpoint)
            except Exception as exc:
                self.logger.debug("auth probe failed", url=endpoint.url, error=str(exc))

    # ------------------------------------------------------------------
    def _login_endpoints(self) -> list[Endpoint]:
        candidates: list[Endpoint] = []
        for endpoint in self.ctx.endpoints:
            hints = endpoint.url.lower() + " " + " ".join(sorted(endpoint.tags))
            has_password = any(param.name.lower() in {"password", "passwd", "pwd", "pass"} for param in endpoint.params)
            has_identity = any(
                param.name.lower() in {"username", "user", "email", "login", "account", "identifier"}
                for param in endpoint.params
            )
            if (has_password and has_identity) or any(token in hints for token in ("/login", "/signin", "/auth")):
                if endpoint.params:
                    candidates.append(endpoint)
        return candidates[:5]

    def _credentials(self, endpoint: Endpoint) -> tuple[str, str]:
        username_field = "username"
        password_field = "password"
        for param in endpoint.params:
            name = param.name.lower()
            if name in {"username", "user", "email", "login", "account", "identifier"}:
                username_field = param.name
            if name in {"password", "passwd", "pwd", "pass"}:
                password_field = param.name
        return username_field, password_field

    def _attempt(self, endpoint: Endpoint, username: str, password: str) -> Response | None:
        username_field, password_field = self._credentials(endpoint)
        try:
            return self.send(
                endpoint,
                {username_field: username, password_field: password},
                tag="auth-login",
            )
        except Exception:
            return None

    # ------------------------------------------------------------------
    def _analyze_login(self, endpoint: Endpoint) -> Iterable[Finding]:
        username_field, password_field = self._credentials(endpoint)
        baseline = self._attempt(endpoint, "candix-nonexistent-user", "candix-invalid-password")
        if baseline is None or self.missing(baseline):
            return
        yield from self._default_credentials(endpoint, baseline)
        yield from self._enumeration(endpoint, baseline)
        yield from self._lockout(endpoint)

    def _default_credentials(self, endpoint: Endpoint, baseline: Response) -> Iterable[Finding]:
        pairs = credential_pairs()[:12]
        for username, password in pairs:
            response = self._attempt(endpoint, username, password)
            if response is None:
                continue
            verdict = _login_verdict(baseline, response)
            if verdict != "success":
                continue
            yield self.emit(
                self.build_finding(
                    title="Default or weak administrative credentials accepted",
                    severity=Severity.CRITICAL,
                    url=endpoint.url,
                    method=endpoint.method,
                    location="body",
                    description=(
                        f"The login form accepted the well-known credential pair {username!r}/"
                        f"{'*' * len(password)} (masked in this report)."
                    ),
                    impact=(
                        "An attacker gains an authenticated session immediately. If the account is "
                        "administrative, the application is fully compromised."
                    ),
                    payload=f"{username}:{password}",
                    confidence=Confidence.CONFIRMED,
                    cwe=("CWE-1392", "CWE-521"),
                    tags=("authentication", "default-credentials"),
                    evidence=[self.capture(response, summary="Login succeeded with default credentials", control=baseline)],
                    vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    metadata={"username": username, "password_length": len(password)},
                )
            )
            return

    def _enumeration(self, endpoint: Endpoint, baseline: Response) -> Iterable[Finding]:
        known_user = self._known_username(endpoint)
        valid = self._attempt(endpoint, known_user, "candix-wrong-password-1")
        if valid is None:
            return
        invalid = self._attempt(endpoint, "candix-definitely-not-a-user-9f2", "candix-wrong-password-1")
        if invalid is None:
            return
        if _login_verdict(valid, invalid) == "success":
            return
        status_differs = valid.status != invalid.status
        message_differs = _messages_differ(valid, invalid)
        length_differs = abs(valid.size - invalid.size) > max(32, int(max(valid.size, 1) * 0.1))
        if not (status_differs or message_differs or length_differs):
            return
        yield self.emit(
            self.build_finding(
                title="Username enumeration on the authentication endpoint",
                severity=Severity.MEDIUM,
                url=endpoint.url,
                method=endpoint.method,
                location="body",
                description=(
                    f"Responses for an existing account ({valid.status}, {valid.size} bytes) and a non-existent "
                    f"account ({invalid.status}, {invalid.size} bytes) differ, allowing account discovery."
                ),
                impact="Attackers can build a list of valid accounts before launching password spraying or phishing.",
                confidence=Confidence.CONFIRMED,
                cwe=("CWE-204",),
                tags=("authentication", "enumeration"),
                evidence=[
                    self.capture(valid, summary="Response for an existing username", control=invalid),
                    self.capture(invalid, summary="Response for a non-existent username"),
                ],
                metadata={"known_user": known_user},
            )
        )

    def _known_username(self, endpoint: Endpoint) -> str:
        for param in endpoint.params:
            value = (param.value or "").strip()
            if "@" in value and param.name.lower() in {"email", "username", "user", "login"}:
                return value
            if value and param.name.lower() in {"username", "user", "login"}:
                return value
        return "admin"

    def _lockout(self, endpoint: Endpoint) -> Iterable[Finding]:
        attempts = 8
        responses: list[Response] = []
        for index in range(attempts):
            response = self._attempt(endpoint, "candix-lockout-probe", f"wrong-password-{index}")
            if response is None:
                return
            responses.append(response)
            if self.rate_limited(response) or any(marker in response.text.lower() for marker in _PROTECTIVE_MARKERS):
                return
        if len(responses) < attempts:
            return
        yield self.emit(
            self.build_finding(
                title="No lockout or throttling after repeated failed logins",
                severity=Severity.MEDIUM,
                url=endpoint.url,
                method=endpoint.method,
                location="body",
                description=(
                    f"{attempts} consecutive failed authentication attempts were processed without a lockout, "
                    "CAPTCHA or rate-limit response."
                ),
                impact="Attackers can perform unlimited online password guessing against user accounts.",
                confidence=Confidence.CONFIRMED,
                cwe=("CWE-307",),
                tags=("authentication", "rate-limit"),
                evidence=[self.capture(responses[-1], summary="Final failed attempt was not throttled", control=responses[0])],
                metadata={"attempts": attempts},
            )
        )


def _login_verdict(baseline: Response, response: Response) -> str:
    if response.status in {429, 403} and baseline.status not in {429, 403}:
        return "blocked"
    body = response.text.lower()
    if any(marker in body for marker in _FAILURE_MARKERS):
        return "failure"
    if response.status == 200 and baseline.status != 200:
        return "success"
    if response.header("Set-Cookie") and not baseline.header("Set-Cookie"):
        return "success"
    if response.status in {301, 302} and response.header("Location") and "login" not in response.header("Location").lower():
        return "success"
    if any(marker in body for marker in _SUCCESS_MARKERS) and not any(marker in baseline.text.lower() for marker in _SUCCESS_MARKERS):
        return "success"
    return "unknown"


def _messages_differ(first: Response, second: Response) -> bool:
    first_markers = {marker for marker in _FAILURE_MARKERS if marker in first.text.lower()}
    second_markers = {marker for marker in _FAILURE_MARKERS if marker in second.text.lower()}
    return first_markers != second_markers


def _median(values: list[float]) -> float:
    return statistics.median(values) if values else 0.0
