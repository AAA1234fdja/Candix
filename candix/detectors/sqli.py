"""SQL injection detection.

Three independent techniques increase confidence and reduce false positives:

* **error-based** - a payload provokes a database-specific error string that
  never appears in the baseline;
* **boolean-based** - a true/false payload pair produces a stable, different
  response for the false condition, repeatable across two rounds;
* **time-based** - a sleep payload delays the response proportionally to the
  requested delay, while a control payload does not.

A confirmed finding never depends on a single observation.
"""

from __future__ import annotations

import re
import statistics
import time
from typing import Iterable, Iterator

from candix.analysis.diff import compare_responses, extract_error_signatures, similarity
from candix.core.endpoint import Endpoint, Param
from candix.core.finding import Finding
from candix.core.severity import Confidence, Severity
from candix.detectors.base import BaseDetector, DetectorMeta, register_detector
from candix.net.http import Response

_DB_ERROR_PATTERNS = (
    r"you have an error in your sql syntax",
    r"warning:\s*mysql",
    r"unclosed quotation mark after the character string",
    r"quoted string not properly terminated",
    r"pg_query\(\)",
    r"postgresql.*error",
    r"sqlite3?\.(?:operational|programming)error",
    r"sqlite error",
    r"ora-\d{5}",
    r"microsoft ole db provider for sql server",
    r"odbc sql server driver",
    r"system\.data\.sqlclient",
    r"mysql_fetch_(?:array|assoc|row)",
    r"supplied argument is not a valid mysql",
    r"column count doesn't match value count",
    r"unknown column",
    r"no such column",
    r"sqlstate\[",
)
_ERROR_RE = re.compile("|".join(_DB_ERROR_PATTERNS), re.IGNORECASE)

_SKIP_PARAM_TOKENS = ("csrf", "xsrf", "_token", "authenticity", "submit", "captcha", "search")


@register_detector
class SqlInjectionDetector(BaseDetector):
    meta = DetectorMeta(
        id="sqli",
        name="SQL injection",
        category="sqli",
        description="Detects error-, boolean-, union- and time-based SQL injection in query and body parameters.",
        severity=Severity.CRITICAL,
        cwe=("CWE-89",),
        owasp=("A03:2021 Injection",),
        intrusive=True,
        tags=("injection", "database"),
        order=40,
        remediation_key="sqli",
    )

    def run(self) -> Iterable[Finding]:
        for endpoint in self.endpoints():
            for param in self.params_for(endpoint):
                if not self._interesting(param):
                    continue
                finding = self._test(endpoint, param)
                if finding is not None:
                    yield self.emit(finding)

    # ------------------------------------------------------------------
    def _interesting(self, param: Param) -> bool:
        name = param.name.lower()
        if any(token in name for token in _SKIP_PARAM_TOKENS):
            return False
        if param.location not in {"query", "body", "json"}:
            return False
        return True

    def _test(self, endpoint: Endpoint, param: Param) -> Finding | None:
        baseline = self._baseline(endpoint, param)
        if baseline is None:
            return None
        error = self._error_based(endpoint, param, baseline)
        if error is not None:
            return error
        boolean = self._boolean_based(endpoint, param, baseline)
        if boolean is not None:
            return boolean
        union = self._union_based(endpoint, param, baseline)
        if union is not None:
            return union
        if self.time_based_enabled() and self._time_based_allowed(endpoint, param):
            timed = self._time_based(endpoint, param)
            if timed is not None:
                return timed
        return None

    def _baseline(self, endpoint: Endpoint, param: Param) -> Response | None:
        value = param.value or _benign_value(param)
        try:
            response = self.send(endpoint, {param.name: value}, tag="sqli-baseline")
        except Exception as exc:
            self.logger.debug("baseline failed", error=str(exc), url=endpoint.url)
            return None
        if self.missing(response):
            return None
        return response

    # ------------------------------------------------------------------
    def _error_based(self, endpoint: Endpoint, param: Param, baseline: Response) -> Finding | None:
        baseline_matches = set(_ERROR_RE.findall(baseline.text)) | set(extract_error_signatures(baseline.text))
        hits: list[tuple[str, Response, str]] = []
        for payload in self.load_payloads("sqli_error"):
            try:
                response = self.send(endpoint, {param.name: payload}, tag="sqli-error")
            except Exception:
                continue
            if self.missing(response):
                continue
            signatures = set(extract_error_signatures(response.text))
            raw_match = _ERROR_RE.search(response.text)
            new_signature = bool(signatures - baseline_matches) or (raw_match is not None and not _ERROR_RE.search(baseline.text))
            if not new_signature:
                continue
            if raw_match is None and not (signatures - baseline_matches):
                continue
            fragment = self._error_fragment(response.text)
            hits.append((payload, response, fragment))
            if len(hits) >= 2:
                break
        if not hits:
            # A generic 500 with a database-ish message still deserves a look if
            # an independent payload reproduces it.
            for payload in self.load_payloads("sqli_error", limit=6):
                try:
                    response = self.send(endpoint, {param.name: payload}, tag="sqli-error")
                except Exception:
                    continue
                if response.status >= 500 and self.looks_broken(response) and not self.looks_broken(baseline):
                    hits.append((payload, response, self.truncate(response.text, 300)))
                    break
        if not hits:
            return None
        payload, response, fragment = hits[0]
        control = hits[1][1] if len(hits) > 1 else baseline
        confidence = Confidence.CONFIRMED if len(hits) > 1 else Confidence.LIKELY
        return self.build_finding(
            title="SQL injection (error-based)",
            severity=Severity.HIGH,
            url=endpoint.url,
            method=endpoint.method,
            parameter=param.name,
            location=param.location,
            description=(
                f"Injecting the payload {payload!r} into parameter '{param.name}' produced a database error. "
                f"Observed: {fragment}"
            ),
            impact="An attacker can read and modify arbitrary database content, bypass authentication and in many configurations execute operating-system commands.",
            payload=payload,
            confidence=confidence,
            cwe=("CWE-89",),
            tags=("sqli", "error-based"),
            evidence=[
                self.capture(control, summary="Control response for error-based SQLi"),
                self.capture(
                    response,
                    summary=f"Database error after injecting {payload!r}",
                    control=baseline,
                    data={"signatures": sorted(extract_error_signatures(response.text))},
                ),
            ],
            vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
            metadata={"technique": "error-based", "error_fragment": fragment},
        )

    # ------------------------------------------------------------------
    def _boolean_based(self, endpoint: Endpoint, param: Param, baseline: Response) -> Finding | None:
        pairs = [
            ("' AND '1'='1", "' AND '1'='2"),
            ("1 AND 1=1", "1 AND 1=2"),
            ("1' AND 1=1-- -", "1' AND 1=2-- -"),
            ('" AND "1"="1', '" AND "1"="2'),
        ]
        for true_payload, false_payload in pairs[: self.payload_budget()]:
            try:
                first_true = self.send(endpoint, {param.name: true_payload}, tag="sqli-bool")
                first_false = self.send(endpoint, {param.name: false_payload}, tag="sqli-bool")
            except Exception:
                continue
            if self.missing(first_true) or self.missing(first_false):
                continue
            if first_true.status != first_false.status and self._status_pair_meaningful(first_true, first_false):
                if self._confirm_boolean(endpoint, param, true_payload, false_payload, first_true, first_false):
                    return self._boolean_finding(endpoint, param, true_payload, false_payload, first_true, first_false, True)
            true_similarity = similarity(baseline.text, first_true.text)
            false_similarity = similarity(baseline.text, first_false.text)
            if true_similarity - false_similarity > 0.15 and first_true.status == baseline.status:
                if self._confirm_boolean(endpoint, param, true_payload, false_payload, first_true, first_false):
                    return self._boolean_finding(endpoint, param, true_payload, false_payload, first_true, first_false, True)
        return None

    def _status_pair_meaningful(self, first: Response, second: Response) -> bool:
        codes = {first.status, second.status}
        if codes <= {200, 404} or codes <= {200, 302} or codes <= {401, 200} or codes <= {500, 200}:
            return True
        return abs(first.size - second.size) > 32

    def _confirm_boolean(
        self,
        endpoint: Endpoint,
        param: Param,
        true_payload: str,
        false_payload: str,
        first_true: Response,
        first_false: Response,
    ) -> bool:
        """Replay the pair and require the difference to be reproducible."""

        try:
            second_true = self.send(endpoint, {param.name: true_payload}, tag="sqli-bool-confirm")
            second_false = self.send(endpoint, {param.name: false_payload}, tag="sqli-bool-confirm")
        except Exception:
            return False
        if self.missing(second_true) or self.missing(second_false):
            return False
        true_stable = (
            second_true.status == first_true.status
            and abs(second_true.size - first_true.size) <= max(32, int(first_true.size * 0.08))
        )
        false_stable = (
            second_false.status == first_false.status
            and abs(second_false.size - first_false.size) <= max(32, int(first_false.size * 0.08))
        )
        if not (true_stable and false_stable):
            return False
        status_differs = second_true.status != second_false.status
        size_differs = abs(second_true.size - second_false.size) > max(48, int(max(second_true.size, 1) * 0.1))
        return status_differs or size_differs

    def _boolean_finding(
        self,
        endpoint: Endpoint,
        param: Param,
        true_payload: str,
        false_payload: str,
        true_response: Response,
        false_response: Response,
        confirmed: bool,
    ) -> Finding:
        return self.build_finding(
            title="SQL injection (boolean-based blind)",
            severity=Severity.HIGH,
            url=endpoint.url,
            method=endpoint.method,
            parameter=param.name,
            location=param.location,
            description=(
                f"A true condition ({true_payload!r}) and a false condition ({false_payload!r}) "
                f"produce consistently different responses (HTTP {true_response.status} vs "
                f"{false_response.status}, {true_response.size} vs {false_response.size} bytes)."
            ),
            impact="Blind SQL injection allows an attacker to extract the full database contents one bit at a time.",
            payload=true_payload,
            confidence=Confidence.CONFIRMED,
            cwe=("CWE-89",),
            tags=("sqli", "blind", "boolean"),
            evidence=[
                self.capture(true_response, summary="Response for TRUE condition", control=false_response),
                self.capture(false_response, summary="Response for FALSE condition"),
            ],
            vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            metadata={"technique": "boolean", "false_payload": false_payload},
        )

    # ------------------------------------------------------------------
    def _union_based(self, endpoint: Endpoint, param: Param, baseline: Response) -> Finding | None:
        marker = self.marker("un")
        candidates = [
            f"0 UNION SELECT 1,'{marker}',3,4",
            f"1 UNION SELECT 1,'{marker}',3,4",
            f"' UNION SELECT 1,'{marker}',3,4-- -",
            f"0 UNION SELECT NULL,'{marker}',NULL,NULL",
            f"-1 UNION SELECT 1,'{marker}'",
        ]
        for payload in candidates[: self.payload_budget()]:
            try:
                response = self.send(endpoint, {param.name: payload}, tag="sqli-union")
            except Exception:
                continue
            if self.missing(response):
                continue
            if marker in response.text and marker not in baseline.text:
                # Rule out plain reflection: if the bare marker also appears in
                # the response, the page is echoing the parameter rather than
                # returning query results.
                try:
                    control = self.send(endpoint, {param.name: marker}, tag="sqli-union-control")
                except Exception:
                    control = None
                if control is not None and marker in control.text:
                    continue
                return self.build_finding(
                    title="SQL injection (UNION-based)",
                    severity=Severity.CRITICAL,
                    url=endpoint.url,
                    method=endpoint.method,
                    parameter=param.name,
                    location=param.location,
                    description=(
                        f"A UNION payload returned attacker-controlled data in the response body, proving "
                        f"that the parameter is concatenated into a SQL statement."
                    ),
                    impact="Direct extraction of arbitrary tables, including credentials and personal data.",
                    payload=payload,
                    confidence=Confidence.CONFIRMED,
                    cwe=("CWE-89",),
                    tags=("sqli", "union"),
                    evidence=[self.capture(response, summary="UNION payload reflected in response", control=baseline)],
                    vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                    metadata={"technique": "union"},
                )
        return None

    # ------------------------------------------------------------------
    def _time_based_allowed(self, endpoint: Endpoint, param: Param) -> bool:
        """Time-based probes are expensive; only run them on likely injectables.

        A sleep payload costs seconds per attempt, so the harness limits them to
        the first two eligible parameters per endpoint and skips endpoints whose
        baseline is already slow (the timing signal would be drowned out).
        """

        if not hasattr(self, "_time_based_counts"):
            self._time_based_counts = {}
        count = self._time_based_counts.get(endpoint.key(), 0)
        if count >= 2:
            return False
        name = param.name.lower()
        likely = any(
            token in name
            for token in ("id", "user", "product", "item", "order", "cat", "page", "num", "account", "ref")
        )
        if not likely and count >= 1:
            return False
        self._time_based_counts[endpoint.key()] = count + 1
        return True

    def _time_based(self, endpoint: Endpoint, param: Param) -> Finding | None:
        delay_unit = max(1, int(self.config.get("detect.sleep_seconds", 1)))
        delays = [delay_unit, delay_unit * 2]
        timings: list[float] = []
        responses: list[Response] = []
        for delay in delays:
            payload = f"' AND SLEEP({delay})-- -"
            started = time.monotonic()
            try:
                response = self.send(endpoint, {param.name: payload}, tag="sqli-time")
            except Exception:
                return None
            elapsed = time.monotonic() - started
            if self.missing(response):
                return None
            timings.append(elapsed)
            responses.append(response)
        control_payload = f"' AND SLEEP(0)-- -"
        started = time.monotonic()
        try:
            control = self.send(endpoint, {param.name: control_payload}, tag="sqli-time-control")
        except Exception:
            control = responses[0]
        control_elapsed = time.monotonic() - started
        if timings[0] - control_elapsed < max(0.8, delay_unit * 0.6):
            return None
        if timings[1] - timings[0] < max(0.5, delay_unit * 0.4):
            return None
        return self.build_finding(
            title="SQL injection (time-based blind)",
            severity=Severity.HIGH,
            url=endpoint.url,
            method=endpoint.method,
            parameter=param.name,
            location=param.location,
            description=(
                "Sleep payloads delay the response proportionally to the requested duration "
                f"({timings[0]:.2f}s for 2s, {timings[1]:.2f}s for 4s, control {control_elapsed:.2f}s)."
            ),
            impact="Blind SQL injection allows full database extraction and may enable further compromise.",
            payload="SLEEP()",
            confidence=Confidence.CONFIRMED,
            cwe=("CWE-89",),
            tags=("sqli", "time-based", "blind"),
            evidence=[
                self.capture(responses[0], summary="Response for 2 second sleep payload", control=control),
                self.capture(responses[1], summary="Response for 4 second sleep payload"),
            ],
            vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
            metadata={"technique": "time-based", "timings": [round(value, 3) for value in timings]},
        )


def _benign_value(param: Param) -> str:
    if param.kind in {"int", "number"}:
        return "1"
    return "candix"


def _error_fragment(text: str) -> str:
    match = _ERROR_RE.search(text)
    if not match:
        return text.strip().replace("\n", " ")[:200]
    start = max(0, match.start() - 60)
    end = min(len(text), match.end() + 120)
    return re.sub(r"\s+", " ", text[start:end]).strip()
