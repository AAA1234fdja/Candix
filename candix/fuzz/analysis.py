"""Response analysis: decide whether a mutated response is worth reporting."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterable

from candix.core.finding import Finding, Remediation
from candix.core.severity import Confidence, Severity

STACK_TRACE = re.compile(
    r"(traceback \(most recent call last\)|java\.lang\.[a-z.]*exception|system\.nullreferenceexception"
    r"|at [a-z0-9_.]+\([a-z0-9_.]+\.java:\d+\)|werkzeug debugger|whoops|django technical 500)",
    re.IGNORECASE,
)
SQL_ERROR = re.compile(
    r"(sql syntax|unclosed quotation mark|quoted string not properly terminated|pg_query\(\)"
    r"|mysql_fetch|ora-\d{5}|sqlite3\.operationalerror|syntax error at or near)",
    re.IGNORECASE,
)
TEMPLATE_EVAL = re.compile(r"(?<!\d)(49|343|2401|7777777|1728)(?!\d)")
COMMAND_OUTPUT = re.compile(r"(uid=\d+\([^)]+\)|gid=\d+\([^)]+\)|root:x:0:0:|/bin/(?:ba)?sh)", re.IGNORECASE)
PATH_LEAK = re.compile(r"(/var/www/[\w./-]+|/etc/passwd|/home/[\w.-]+/|[a-z]:\\inetpub\\[\w./-]+)", re.IGNORECASE)
SECRET_LEAK = re.compile(r"(?i)(api[_-]?key|secret|password|token)\s*[:=]\s*[\"']?[a-z0-9_\-]{8,}")
HEADER_INJECTION = re.compile(r"(?im)^(set-cookie|x-injected|candix-probe)\s*:")
JSON_ERROR = re.compile(r"(unexpected token|json\.parse|invalid json|malformed json)", re.IGNORECASE)

ERROR_PATTERNS: list[tuple[str, re.Pattern[str], Severity, float]] = [
    ("stack-trace", STACK_TRACE, Severity.MEDIUM, 0.8),
    ("sql-error", SQL_ERROR, Severity.HIGH, 0.85),
    ("template-evaluation", TEMPLATE_EVAL, Severity.CRITICAL, 0.9),
    ("command-output", COMMAND_OUTPUT, Severity.CRITICAL, 0.95),
    ("path-disclosure", PATH_LEAK, Severity.MEDIUM, 0.7),
    ("secret-disclosure", SECRET_LEAK, Severity.HIGH, 0.8),
    ("header-injection", HEADER_INJECTION, Severity.MEDIUM, 0.75),
    ("json-error", JSON_ERROR, Severity.LOW, 0.5),
]

INTERESTING_STATUS = {500, 502, 503, 504}
REFLECT_MARKERS = ("<script", "onerror=", "onload=", "javascript:", "\"><", "'><")


@dataclass
class Bucket:
    """Coarse response class used for novelty detection."""

    status: int
    length_band: int
    content_type: str

    @classmethod
    def of(cls, response: Any) -> "Bucket":
        length = len(response.content or b"")
        band = 0 if length < 512 else 1 if length < 4096 else 2 if length < 32768 else 3
        content_type = (response.headers.get("Content-Type", "") or "").split(";")[0].strip().lower()
        return cls(status=response.status, length_band=band, content_type=content_type)

    def to_dict(self) -> dict[str, Any]:
        return {"status": self.status, "length_band": self.length_band, "content_type": self.content_type}


@dataclass
class Signal:
    family: str
    kind: str
    score: float
    severity: Severity
    reasons: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "family": self.family,
            "kind": self.kind,
            "score": round(self.score, 3),
            "severity": self.severity.value,
            "reasons": list(self.reasons),
            "evidence": dict(self.evidence),
        }


def body_delta_ratio(baseline: str, body: str) -> float:
    if not baseline and not body:
        return 0.0
    if not baseline:
        return 1.0
    common = sum(1 for left, right in zip(baseline[:8192], body[:8192]) if left == right)
    return 1.0 - (common / max(len(baseline[:8192]), len(body[:8192])))


def classify(
    *,
    family: str,
    payload: str,
    baseline_status: int,
    baseline_body: str,
    response: Any,
    control: Any | None = None,
) -> Signal | None:
    """Score one fuzzed response; ``None`` means nothing notable happened."""

    body = response.text or ""
    baseline = baseline_body or ""
    reasons: list[str] = []
    score = 0.0
    kind = "anomaly"
    severity = Severity.LOW
    evidence: dict[str, Any] = {"payload": payload[:400], "status": response.status}

    for name, pattern, severity_hint, weight in ERROR_PATTERNS:
        match = pattern.search(body)
        if match and match.group(0) and match.group(0).lower() in payload.lower():
            match = None
        if match and not pattern.search(baseline):
            score = max(score, weight)
            kind = name
            severity = severity_hint
            reasons.append(f"{name} appeared in the response: {match.group(0)[:120]!r}")
            evidence["match"] = match.group(0)[:200]

    if response.status in INTERESTING_STATUS and baseline_status not in INTERESTING_STATUS:
        score = max(score, 0.55)
        kind = "server-error" if kind == "anomaly" else kind
        severity = Severity.MEDIUM if severity.rank >= Severity.MEDIUM.rank else severity
        reasons.append(f"status changed from {baseline_status} to {response.status}")

    delta = body_delta_ratio(baseline, body)
    if delta > 0.6 and len(body) > 64 and not reasons:
        score = max(score, 0.45)
        kind = "body-divergence"
        severity = Severity.LOW
        reasons.append(f"response body diverged by {delta:.0%} from the baseline")

    marker = payload.strip()
    if marker and len(marker) >= 4 and marker in body and marker not in baseline:
        if any(token in marker.lower() for token in REFLECT_MARKERS):
            score = max(score, 0.7)
            kind = "reflection"
            severity = Severity.HIGH
            reasons.append("payload reflected verbatim inside markup")

    if control is not None and getattr(control, "status", 0) == response.status:
        control_delta = body_delta_ratio(control.text or "", body)
        if control_delta < 0.15 and reasons:
            score = max(0.0, score - 0.25)
            reasons.append("a benign control value produced a nearly identical response")

    if response.elapsed > 4.0 and getattr(response, "elapsed", 0.0) > 0:
        score = max(score, 0.5)
        kind = "timing-anomaly" if kind == "anomaly" else kind
        severity = Severity.MEDIUM if severity.rank >= Severity.MEDIUM.rank else severity
        reasons.append(f"response took {response.elapsed:.1f}s")

    if not reasons:
        return None
    return Signal(
        family=family,
        kind=kind,
        score=min(1.0, score),
        severity=severity,
        reasons=reasons,
        evidence=evidence,
    )


def _remediation_for(kind: str) -> Remediation:
    table = {
        "sql-error": (
            "Parameterise every database query",
            [
                "Replace string concatenation with prepared statements or a query builder.",
                "Restrict the database account to the minimum privileges the feature needs.",
                "Reject input whose type does not match the expected shape before it reaches storage.",
            ],
            "low",
        ),
        "command-output": (
            "Never build shell commands from request data",
            [
                "Call the target binary with an argument vector and no shell.",
                "Allow-list the accepted values (for example hostnames or interface names).",
                "Run the service as an unprivileged user in a sandbox with no outbound access.",
            ],
            "medium",
        ),
        "template-evaluation": (
            "Do not evaluate template syntax from user input",
            [
                "Pass user data as template variables, never as the template source.",
                "Use a sandboxed environment without object introspection helpers.",
                "Reject delimiters that the engine would treat as code.",
            ],
            "medium",
        ),
        "stack-trace": (
            "Disable verbose error output in production",
            [
                "Return a generic error page with a correlation id.",
                "Log the technical detail server-side only.",
                "Run with debug mode disabled and framework debugging packages removed.",
            ],
            "low",
        ),
        "path-disclosure": (
            "Stop returning filesystem paths in responses",
            [
                "Map internal errors to stable public messages.",
                "Move uploaded content outside the web root.",
                "Remove absolute paths from build artefacts and source maps.",
            ],
            "low",
        ),
        "secret-disclosure": (
            "Rotate the leaked secret and remove it from responses",
            [
                "Treat the value as compromised and rotate it immediately.",
                "Keep secrets in a managed store, injected at runtime.",
                "Add a regression test that fails if the value appears in a response.",
            ],
            "medium",
        ),
        "header-injection": (
            "Strip control characters from values written to headers",
            [
                "Reject CR/LF in any input that reaches a response header.",
                "Use framework APIs that encode header values.",
                "Set cookies with HttpOnly, Secure and an explicit SameSite policy.",
            ],
            "low",
        ),
        "reflection": (
            "Encode output for the context where it lands",
            [
                "Apply contextual HTML/attribute/JavaScript encoding on output.",
                "Deploy a restrictive Content-Security-Policy as defence in depth.",
                "Validate the accepted character set for each parameter.",
            ],
            "low",
        ),
        "timing-anomaly": (
            "Make response time independent of secret values",
            [
                "Use constant-time comparisons for tokens and credentials.",
                "Bound and normalise the work performed per request.",
                "Add a timeout and a uniform error path for slow operations.",
            ],
            "medium",
        ),
        "server-error": (
            "Handle malformed input without failing",
            [
                "Validate the request schema and return a 4xx before business logic runs.",
                "Add regression tests for the crashing input.",
                "Alert on 5xx rates so regressions are noticed.",
            ],
            "low",
        ),
        "body-divergence": (
            "Investigate unexpected response changes",
            [
                "Confirm the input is validated and the behaviour is intentional.",
                "Add the case to the regression corpus with an expected result.",
                "Review whether the divergence leaks data or state.",
            ],
            "low",
        ),
    }
    summary, steps, effort = table.get(kind, table["body-divergence"])
    return Remediation(summary=summary, steps=list(steps), effort=effort)


def signal_to_finding(
    signal: Signal,
    *,
    title_prefix: str,
    url: str,
    method: str,
    parameter: str,
    location: str,
    payload: str,
    evidence: list[Any] | None = None,
) -> Finding:
    return Finding(
        title=f"{title_prefix} ({signal.kind})",
        severity=signal.severity,
        detector="fuzz",
        category="fuzz",
        url=url,
        method=method.upper(),
        parameter=parameter,
        location=location,
        description="; ".join(signal.reasons)[:900] or "Response diverged from the baseline.",
        impact="Input reaching this parameter changes server behaviour in a way that suggests missing validation.",
        payload=payload[:800],
        confidence=Confidence.LIKELY if signal.score < 0.85 else Confidence.CONFIRMED,
        verified=signal.score >= 0.75,
        remediation=_remediation_for(signal.kind),
        cwe=("CWE-20",),
        tags=("fuzz", signal.family, signal.kind),
        evidence=list(evidence or []),
        metadata={"fuzz_signal": signal.to_dict(), "family": signal.family},
    )


def summarise_signals(signals: Iterable[Signal]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for signal in signals:
        counts[signal.kind] = counts.get(signal.kind, 0) + 1
    return dict(sorted(counts.items(), key=lambda pair: -pair[1]))
