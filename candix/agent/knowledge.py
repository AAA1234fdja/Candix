"""What the agent knows about each vulnerability class, in one place."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable


@dataclass(frozen=True)
class VulnClass:
    key: str
    name: str
    cwe: str
    owasp: str
    asvs: tuple[str, ...] = ()
    impact: str = ""
    verify: tuple[str, ...] = ()
    exploit: tuple[str, ...] = ()
    remediation: tuple[str, ...] = ()
    false_positive_checks: tuple[str, ...] = ()
    payloads: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "name": self.name,
            "cwe": self.cwe,
            "owasp": self.owasp,
            "asvs": list(self.asvs),
            "impact": self.impact,
            "remediation": list(self.remediation),
        }


VULN_CLASSES: dict[str, VulnClass] = {
    item.key: item
    for item in (
        VulnClass(
            key="xss",
            name="Cross-site scripting",
            cwe="CWE-79",
            owasp="A03:2021",
            asvs=("5.3.3", "5.3.4"),
            impact="Script execution in another user's session: token theft, action forgery, phishing overlays.",
            verify=(
                "send the marker payload and confirm it appears unencoded in the response body",
                "check the content type: JSON APIs that reflect into HTML consumers still matter",
                "compare against a control request with a harmless value to rule out generic reflection",
            ),
            exploit=(
                "use a benign alert payload first, never a cookie stealer on a client system",
                "capture the rendered response as evidence, not just the request",
            ),
            remediation=(
                "encode output for the exact context (HTML, attribute, JS, URL, CSS)",
                "prefer framework auto-escaping and forbid raw HTML sinks",
                "add a restrictive Content-Security-Policy as defence in depth",
                "mark session cookies HttpOnly so script cannot read them",
            ),
            false_positive_checks=(
                "the reflection may be encoded but decode in the browser: check the raw bytes",
                "a 200 response may be a generic error page echoing the parameter name only",
            ),
            payloads=('<script>alert(1)</script>', '"><svg onload=alert(1)>', "'-alert(1)-'"),
            tags=("client", "injection"),
        ),
        VulnClass(
            key="sqli",
            name="SQL injection",
            cwe="CWE-89",
            owasp="A03:2021",
            asvs=("5.3.4",),
            impact="Read or modify database contents, bypass authentication, sometimes execute commands.",
            verify=(
                "compare a true condition against a false one and look for a response delta",
                "use time-based confirmation only when the response is identical",
                "never use destructive statements; SELECT-based probes only",
            ),
            exploit=(
                "extract a single boolean from a known table to prove access",
                "keep the extracted data minimal and redact it in the report",
            ),
            remediation=(
                "use parameterised queries everywhere, including ORDER BY and LIKE",
                "apply least privilege to the database account",
                "log and alert on database errors reaching the client",
            ),
            false_positive_checks=(
                "a syntax error may come from the driver, not the query",
                "a timing difference may be network jitter: repeat three times",
            ),
            payloads=("' AND 1=1--", "' AND 1=2--", "'||(SELECT 1)--"),
            tags=("server", "injection"),
        ),
        VulnClass(
            key="ssrf",
            name="Server-side request forgery",
            cwe="CWE-918",
            owasp="A10:2021",
            asvs=("12.6.1",),
            impact="Reach internal services, cloud metadata endpoints, or bypass network segmentation.",
            verify=(
                "point the parameter at a host you control and confirm the callback",
                "confirm the request came from the server, not the browser",
                "check whether the response body reflects the fetched content",
            ),
            exploit=(
                "fetch a harmless internal endpoint that only the server can reach",
                "do not touch cloud metadata credentials; report the reachability instead",
            ),
            remediation=(
                "allowlist destination hosts and schemes",
                "resolve DNS once and pin the IP for the outbound request",
                "block link-local and private ranges at the egress layer",
            ),
            false_positive_checks=(
                "the client may be following the redirect, not the server",
                "a callback from the scanner's own IP is not proof",
            ),
            payloads=("http://127.0.0.1:80/", "http://169.254.169.254/latest/meta-data/", "file:///etc/hostname"),
            tags=("server", "network"),
        ),
        VulnClass(
            key="idor",
            name="Broken object level authorization",
            cwe="CWE-639",
            owasp="A01:2021",
            asvs=("4.1.1", "4.2.1"),
            impact="Read or change another tenant's records by changing an identifier.",
            verify=(
                "request an object you own, then the neighbouring identifier",
                "compare status and body shape, not just the code",
                "check both read and write paths; write paths are usually worse",
            ),
            exploit=(
                "prove access with a single field from the other object",
                "stop at the first confirmed record; do not enumerate",
            ),
            remediation=(
                "authorise every object access against the session subject",
                "prefer unpredictable identifiers as defence in depth, not as the control",
                "return 404 for unauthorised objects to avoid enumeration",
            ),
            false_positive_checks=(
                "the object may be intentionally public",
                "a 200 with an empty body means the lookup failed",
            ),
            tags=("authz", "api"),
        ),
        VulnClass(
            key="lfi",
            name="Path traversal / local file inclusion",
            cwe="CWE-22",
            owasp="A01:2021",
            asvs=("12.3.1",),
            impact="Read arbitrary files, sometimes execute code through included content.",
            verify=(
                "traverse to a file that always exists and is not secret, like /etc/hostname",
                "compare the response length against a missing file",
                "check whether absolute paths work as well as relative ones",
            ),
            exploit=("read one harmless system file and stop there",),
            remediation=(
                "map user values to a fixed allowlist of files",
                "normalise and verify the final path stays under the base directory",
            ),
            false_positive_checks=("the file may be served by a static handler", "check for a WAF block page"),
            payloads=("../../../../etc/hostname", "....//....//etc/hostname", "/etc/hostname%00.png"),
            tags=("server", "files"),
        ),
        VulnClass(
            key="rce",
            name="Remote command or code execution",
            cwe="CWE-94",
            owasp="A03:2021",
            asvs=("5.3.4",),
            impact="Full control of the application host.",
            verify=(
                "use a command whose output is unmistakable and harmless, like id or uname -a",
                "confirm the output is fresh, not cached",
            ),
            exploit=("run one read-only command; never touch files or persistence",),
            remediation=(
                "never build shell strings from input",
                "use exec with argument arrays and a fixed binary",
                "sandbox the process and drop privileges",
            ),
            false_positive_checks=("output may come from a previous request", "check for template evaluation errors"),
            tags=("server", "critical"),
        ),
        VulnClass(
            key="open_redirect",
            name="Open redirect",
            cwe="CWE-601",
            owasp="A01:2021",
            asvs=("5.1.5",),
            impact="Phishing and OAuth token theft when combined with an allowlisted redirect URI.",
            verify=("follow a redirect to an external host you control", "check both Location headers and meta refresh"),
            exploit=("show the Location header pointing outside the target",),
            remediation=("allowlist redirect targets by origin", "warn the user before leaving the origin"),
            false_positive_checks=("the redirect may be relative and resolved by the browser",),
            payloads=("//example.org", "https:example.org", "/\\example.org"),
            tags=("client",),
        ),
        VulnClass(
            key="xxe",
            name="XML external entity",
            cwe="CWE-611",
            owasp="A05:2021",
            asvs=("5.5.2",),
            impact="Read local files or reach internal services through XML parsing.",
            verify=("submit a document with an external entity and watch for expansion",),
            exploit=("read one harmless file through the entity",),
            remediation=("disable DTDs and external entities in the parser",),
            false_positive_checks=("the parser may reject the document before entity resolution",),
            tags=("server", "injection"),
        ),
        VulnClass(
            key="csrf",
            name="Cross-site request forgery",
            cwe="CWE-352",
            owasp="A01:2021",
            asvs=("4.2.2",),
            impact="State changes performed as the victim.",
            verify=(
                "look for a token bound to the session on state-changing forms",
                "check SameSite and the request content type",
            ),
            exploit=("demonstrate the missing token on a non-destructive action",),
            remediation=("use per-session anti-CSRF tokens", "set SameSite=Lax or Strict on session cookies"),
            false_positive_checks=("a JSON-only endpoint with a strict content type may already be safe",),
            tags=("client",),
        ),
        VulnClass(
            key="exposed_secret",
            name="Exposed credential or configuration",
            cwe="CWE-538",
            owasp="A05:2021",
            asvs=("2.10.3",),
            impact="Direct access with the leaked credential: repositories, databases, cloud accounts.",
            verify=(
                "fetch the file and confirm it is real content, not a soft 404",
                "check whether the credential is live only against the owning service, with permission",
            ),
            exploit=("show the first lines with the secret redacted",),
            remediation=(
                "remove the file from the document root",
                "rotate every credential it contained",
                "add a deploy-time check that fails on dotfiles in the artefact",
            ),
            false_positive_checks=("a catch-all route may return 200 for every path",),
            tags=("exposure",),
        ),
        VulnClass(
            key="cors",
            name="Permissive CORS",
            cwe="CWE-942",
            owasp="A05:2021",
            asvs=("14.4.6",),
            impact="Any site can read authenticated responses when credentials are allowed.",
            verify=(
                "send an Origin you control and check the echoed value with credentials",
                "check preflight handling as well as the simple request",
            ),
            exploit=("show the echoed origin plus Access-Control-Allow-Credentials",),
            remediation=("allowlist origins", "never combine a wildcard with credentials"),
            false_positive_checks=("an echo without credentials is low impact",),
            tags=("client", "config"),
        ),
        VulnClass(
            key="jwt",
            name="JWT validation weakness",
            cwe="CWE-347",
            owasp="A02:2021",
            asvs=("3.5.3",),
            impact="Forge tokens and impersonate any user.",
            verify=("test alg=none and a weak secret offline", "check whether the header is trusted over the key"),
            exploit=("forge a token for the same user with a different claim and confirm acceptance",),
            remediation=("pin the algorithm", "use a strong key", "verify issuer and audience"),
            false_positive_checks=("a token accepted may still be rejected on privileged routes",),
            tags=("auth",),
        ),
        VulnClass(
            key="graphql_introspection",
            name="GraphQL introspection exposed",
            cwe="CWE-200",
            owasp="A01:2021",
            asvs=("14.1.1",),
            impact="Full schema disclosure, which speeds up every other attack.",
            verify=("run the introspection query and count the types returned",),
            exploit=("attach the type list to the report instead of a screenshot",),
            remediation=("disable introspection in production", "apply field-level authorization"),
            false_positive_checks=("a partial schema may be intentional for a public API",),
            tags=("api", "exposure"),
        ),
    )
}

ALIASES: dict[str, str] = {
    "cross_site_scripting": "xss",
    "cross-site-scripting": "xss",
    "sql_injection": "sqli",
    "sql-injection": "sqli",
    "server_side_request_forgery": "ssrf",
    "path_traversal": "lfi",
    "directory_traversal": "lfi",
    "file_inclusion": "lfi",
    "bola": "idor",
    "object_reference": "idor",
    "command_injection": "rce",
    "code_execution": "rce",
    "redirect": "open_redirect",
    "xml_external_entity": "xxe",
    "csrf_token": "csrf",
    "secret_exposure": "exposed_secret",
    "dotfile": "exposed_secret",
    "cors_misconfiguration": "cors",
    "jwt_weakness": "jwt",
    "introspection": "graphql_introspection",
}


def normalise(key: str) -> str:
    cleaned = (key or "").strip().lower().replace(" ", "_")
    if cleaned in VULN_CLASSES:
        return cleaned
    if cleaned in ALIASES:
        return ALIASES[cleaned]
    for candidate in VULN_CLASSES:
        if candidate in cleaned:
            return candidate
    return ""


def lookup(category: str) -> VulnClass | None:
    return VULN_CLASSES.get(normalise(category))


def guidance_for(finding: dict[str, Any]) -> VulnClass | None:
    for key in ("category", "title", "description"):
        value = str(finding.get(key, ""))
        if not value:
            continue
        found = lookup(value)
        if found:
            return found
    return None


def by_cwe(cwe: str) -> list[VulnClass]:
    return [item for item in VULN_CLASSES.values() if item.cwe == cwe]


def by_owasp(code: str) -> list[VulnClass]:
    return [item for item in VULN_CLASSES.values() if item.owasp == code]


def by_tag(tag: str) -> list[VulnClass]:
    return [item for item in VULN_CLASSES.values() if tag in item.tags]


def remediation_markdown(categories: Iterable[str], *, max_items: int = 20) -> str:
    seen: set[str] = set()
    lines = ["## Remediation", ""]
    for category in categories:
        item = lookup(category)
        if not item or item.key in seen:
            continue
        seen.add(item.key)
        lines.append(f"### {item.name} ({item.cwe}, {item.owasp})")
        for step in item.remediation:
            lines.append(f"- {step}")
        lines.append("")
        if len(seen) >= max_items:
            break
    return "\n".join(lines).rstrip() + "\n"


def checklist(category: str) -> list[str]:
    item = lookup(category)
    if not item:
        return []
    return [*item.verify, *item.false_positive_checks]


def verify_plan(finding: dict[str, Any]) -> list[str]:
    item = guidance_for(finding)
    if not item:
        return ["re-request the endpoint and compare against a control response"]
    steps = list(item.verify)
    if not str(finding.get("parameter", "")).strip():
        steps.append("identify the exact parameter or path segment that changed the behaviour")
    return steps


def exploit_hint(finding: dict[str, Any]) -> str:
    item = guidance_for(finding)
    if not item or not item.exploit:
        return "keep the proof limited to the smallest observable effect"
    return item.exploit[0]


def payloads_for(category: str) -> tuple[str, ...]:
    item = lookup(category)
    return item.payloads if item else ()


def cwe_of(category: str) -> str:
    item = lookup(category)
    return item.cwe if item else "CWE-693"


def asvs_controls(categories: Iterable[str]) -> list[str]:
    controls: set[str] = set()
    for category in categories:
        item = lookup(category)
        if item:
            controls.update(item.asvs)
    return sorted(controls)


def severity_hint(category: str) -> str:
    item = lookup(category)
    if not item:
        return "medium"
    if "critical" in item.tags:
        return "critical"
    if item.key in {"sqli", "idor", "ssrf", "rce", "xxe"}:
        return "high"
    if item.key in {"xss", "lfi", "exposed_secret", "jwt"}:
        return "high"
    if item.key in {"cors", "csrf", "open_redirect", "graphql_introspection"}:
        return "medium"
    return "low"


def confidence_delta(finding: dict[str, Any], *, response: str = "") -> float:
    """How much a confirmation should move the confidence of a finding."""

    delta = 0.15
    body = (response or "").lower()
    if any(marker in body for marker in ("<script", "onerror", "sql syntax", "root:x:", "exception")):
        delta += 0.2
    item = guidance_for(finding)
    if item and item.key in {"xss", "sqli"}:
        delta += 0.05
    if finding.get("verified"):
        delta += 0.1
    return min(0.5, delta)


def is_likely_false_positive(finding: dict[str, Any]) -> tuple[bool, str]:
    severity = str(finding.get("severity", "")).lower()
    title = str(finding.get("title", "")).lower()
    body = str(finding.get("evidence", "") or finding.get("response", "")).lower()
    if severity in {"critical", "high"} and not finding.get("verified"):
        return True, "high severity without a verification request"
    if "not found" in body or "404" in body:
        return True, "response looks like a not-found page"
    if "soft 404" in body:
        return True, "soft-404 marker in the response"
    if "could not resolve" in title:
        return True, "the target did not resolve"
    item = guidance_for(finding)
    if item and item.key == "exposed_secret" and len(body) < 20:
        return True, "empty body for an exposure finding"
    return False, ""


def summarize(finding: dict[str, Any]) -> str:
    item = guidance_for(finding)
    if not item:
        return f"{finding.get('title', 'finding')}: no knowledge entry"
    return f"{item.name} ({item.cwe}): {item.impact}"


def coverage_gaps(categories: Iterable[str]) -> list[VulnClass]:
    seen = {normalise(item) for item in categories}
    return [item for key, item in VULN_CLASSES.items() if key not in seen]


def all_classes() -> list[VulnClass]:
    return sorted(VULN_CLASSES.values(), key=lambda item: item.name)


def export_markdown() -> str:
    lines = ["# Vulnerability knowledge", ""]
    for item in all_classes():
        lines.append(f"## {item.name}")
        lines.append(f"- {item.cwe} · {item.owasp} · ASVS {', '.join(item.asvs) or 'n/a'}")
        lines.append(f"- impact: {item.impact}")
        if item.payloads:
            lines.append(f"- payloads: {', '.join(item.payloads)}")
        lines.append("")
    return "\n".join(lines)


SEARCH_TERMS: dict[str, tuple[str, ...]] = {
    "jwt": ("token", "bearer", "signature", "alg", "claim"),
    "csrf": ("token", "form", "same-site", "state change"),
    "exposed_secret": ("secret", "credential", "dotfile", "key", "env"),
    "xss": ("script", "reflection", "dom", "csp"),
    "sqli": ("database", "query", "sql", "blind"),
    "ssrf": ("internal", "metadata", "callback", "egress"),
    "idor": ("object", "tenant", "ownership", "identifier"),
    "auth": ("login", "session", "cookie"),
    "graphql_introspection": ("graphql", "schema", "introspection"),
    "cors": ("origin", "header", "browser"),
    "lfi": ("file", "path", "traversal"),
    "rce": ("command", "shell", "code"),
    "open_redirect": ("redirect", "location", "phishing"),
    "xxe": ("xml", "entity", "parser"),
}


@dataclass
class KnowledgeIndex:
    items: dict[str, VulnClass] = field(default_factory=lambda: dict(VULN_CLASSES))

    def search(self, query: str, *, limit: int = 5) -> list[VulnClass]:
        needle = (query or "").lower()
        scored: list[tuple[int, VulnClass]] = []
        for item in self.items.values():
            head = " ".join([item.key, item.name, item.cwe, item.owasp, *item.tags]).lower()
            body = " ".join([item.impact, *item.remediation, *item.verify]).lower()
            score = 0
            for word in needle.split():
                if not word:
                    continue
                if word in head:
                    score += 6
                elif word in body:
                    score += 1
                if any(word in term for term in SEARCH_TERMS.get(item.key, ())):
                    score += 4
            if score:
                scored.append((score, item))
        scored.sort(key=lambda pair: (-pair[0], pair[1].name))
        return [item for _, item in scored[:limit]]

    def for_findings(self, findings: Iterable[dict[str, Any]]) -> dict[str, str]:
        mapping: dict[str, str] = {}
        for finding in findings:
            item = guidance_for(finding)
            if item:
                mapping[str(finding.get("id") or finding.get("title", ""))] = item.cwe
        return mapping
