"""Playbook definitions grouped by weakness class."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Playbook:
    id: str
    title: str
    category: str
    objective: str
    prerequisites: tuple[str, ...]
    steps: tuple[str, ...]
    confirm: tuple[str, ...]
    impact: str
    detections: tuple[str, ...] = ()
    references: tuple[str, ...] = ()
    techniques: tuple[str, ...] = ()
    severity_hint: str = "medium"

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "category": self.category,
            "objective": self.objective,
            "prerequisites": list(self.prerequisites),
            "steps": list(self.steps),
            "confirm": list(self.confirm),
            "impact": self.impact,
            "detections": list(self.detections),
            "references": list(self.references),
            "techniques": list(self.techniques),
            "severity_hint": self.severity_hint,
        }


PLAYBOOKS: dict[str, Playbook] = {
    "rce": Playbook(
        id="rce",
        title="Command execution to host control",
        category="rce",
        objective="Turn a command injection primitive into a stable view of the host and its data.",
        prerequisites=("A parameter reaches a shell or interpreter", "The response returns stdout or a side channel"),
        steps=(
            "Confirm execution with an idempotent command (id, hostname, whoami) and record the exact payload.",
            "Identify the runtime user, groups, kernel and container markers (/proc/1/cgroup, /.dockerenv).",
            "Check egress: resolve a documentation domain and note whether outbound DNS works.",
            "Look for readable configuration files that hold credentials (app config, .env, cloud metadata).",
            "Stop once the impact is demonstrated; collect only the evidence the rules of engagement allow.",
        ),
        confirm=("The command output is unique to the target host", "A second, different command confirms the same context"),
        impact="An unauthenticated attacker can run arbitrary code as the web user and pivot to internal services.",
        detections=(
            "Process trees where the web server spawns sh, bash or cmd.exe",
            "Requests containing shell metacharacters or command substitutions",
            "Unexpected outbound connections from the application host",
        ),
        references=("https://cwe.mitre.org/data/definitions/78.html",),
        techniques=("rce",),
        severity_hint="critical",
    ),
    "sqli": Playbook(
        id="sqli",
        title="SQL injection to data exposure",
        category="sqli",
        objective="Establish whether the injection reads or modifies data beyond the current user's authorisation.",
        prerequisites=("A parameter changes query semantics", "The response or timing reflects the query result"),
        steps=(
            "Confirm with a boolean pair that changes the result set, then with a time-based probe where needed.",
            "Enumerate the database engine and version through the error channel or metadata functions.",
            "Retrieve one row of non-sensitive metadata (current database, current user) as proof.",
            "Assess write capability only if the engagement permits it and the impact requires it.",
            "Document the vulnerable query shape and the parameter that reaches it.",
        ),
        confirm=("Truth and false conditions produce consistently different responses", "Metadata matches the observed engine"),
        impact="Attackers can read credentials, session tokens and customer data, and may be able to modify records.",
        detections=("SQL keywords in request parameters", "Database errors surfacing to clients"),
        references=("https://cwe.mitre.org/data/definitions/89.html",),
        techniques=("sqli",),
        severity_hint="high",
    ),
    "xss": Playbook(
        id="xss",
        title="Cross-site scripting to session abuse",
        category="xss",
        objective="Show that attacker-controlled script executes in the application origin and can act as the victim.",
        prerequisites=("Input is reflected or stored", "The output context does not encode the payload"),
        steps=(
            "Build the smallest payload that survives the context (HTML text, attribute, script, URL).",
            "Verify execution in a browser with the same headers and cookies a victim would send.",
            "Demonstrate a single benign effect (cookie visibility or a DOM change), never data exfiltration.",
            "Record the exact URL, browser and timestamp used for the proof.",
        ),
        confirm=("The payload executes without user interaction beyond visiting the URL", "The payload survives a second replay"),
        impact="Account takeover through session theft, request forgery in the victim's context, or credential phishing.",
        detections=("Reflected payload fragments in responses", "Requests with encoded script tags in parameters"),
        references=("https://cwe.mitre.org/data/definitions/79.html",),
        techniques=("xss",),
        severity_hint="high",
    ),
    "ssti": Playbook(
        id="ssti",
        title="Template injection to server-side execution",
        category="ssti",
        objective="Prove that user input is evaluated by the template engine and can reach dangerous objects.",
        prerequisites=("The parameter is rendered by a template engine", "Arithmetic or object access appears in the output"),
        steps=(
            "Send an arithmetic expression unique to the engine and compare it with the expected value.",
            "Identify the engine from the delimiters and the error text.",
            "If the engagement allows it, demonstrate a single sandbox-escape primitive and stop.",
            "Capture the exact request and the evaluated output as evidence.",
        ),
        confirm=("The evaluated value appears where the input was placed", "A different expression yields the matching value"),
        impact="Server-side code execution and access to application secrets, often equivalent to full compromise.",
        detections=("Template delimiters in request parameters", "Unexpected evaluation errors in application logs"),
        references=("https://cwe.mitre.org/data/definitions/1336.html",),
        techniques=("ssti",),
        severity_hint="critical",
    ),
    "lfi": Playbook(
        id="lfi",
        title="File read to credential harvesting",
        category="lfi",
        objective="Determine which files an unauthenticated user can read and what secrets they expose.",
        prerequisites=("A path or filename parameter reaches the filesystem", "The response returns file content"),
        steps=(
            "Read a harmless system file to confirm the primitive, then the application configuration.",
            "Search readable files for credentials, tokens and connection strings.",
            "Never download customer data; record hashes and byte counts as proof instead.",
            "Map the traversal depth and any prefix or suffix the application adds.",
        ),
        confirm=("The returned bytes match the expected file content", "A second, different file can also be read"),
        impact="Secrets in configuration files allow authentication to databases, cloud accounts and internal APIs.",
        detections=("Traversal sequences in parameters", "Reads of files outside the web root"),
        references=("https://cwe.mitre.org/data/definitions/22.html",),
        techniques=("lfi",),
        severity_hint="high",
    ),
    "ssrf": Playbook(
        id="ssrf",
        title="Server-side request forgery to internal services",
        category="ssrf",
        objective="Establish whether the server can be made to reach internal or metadata endpoints.",
        prerequisites=("The application fetches a user-supplied URL", "Responses or timing leak the fetch result"),
        steps=(
            "Fetch a documentation domain first to confirm the server performs the request.",
            "Probe loopback and link-local addresses with harmless paths and record status and timing.",
            "Attempt the cloud metadata endpoint only if the engagement explicitly allows it.",
            "Stop before any state-changing internal request.",
        ),
        confirm=("Body or timing differs between reachable and unreachable hosts", "A second internal target behaves consistently"),
        impact="Access to internal admin interfaces, cloud credentials and network reconnaissance from inside the perimeter.",
        detections=("Application servers fetching arbitrary hosts", "Requests to link-local or metadata addresses"),
        references=("https://cwe.mitre.org/data/definitions/918.html",),
        techniques=("ssrf",),
        severity_hint="high",
    ),
    "auth": Playbook(
        id="auth",
        title="Authentication bypass to account access",
        category="auth",
        objective="Confirm that authentication or session controls can be avoided and what an attacker gains.",
        prerequisites=("A protected endpoint exists", "A token, cookie or credential is handled predictably"),
        steps=(
            "Capture a baseline as an anonymous user and as a legitimate low-privilege user.",
            "Test token handling: signature verification, algorithm confusion, expiry and revocation.",
            "Test authorisation separately from authentication on every object reference.",
            "Demonstrate access to one object belonging to another user, then stop.",
        ),
        confirm=("The bypassed request returns data the anonymous baseline could not", "The result reproduces on a clean session"),
        impact="Account takeover and unauthorised access to customer or administrative functionality.",
        detections=("Requests without tokens that return protected data", "Tokens with altered headers or claims"),
        references=("https://cwe.mitre.org/data/definitions/287.html",),
        techniques=("jwt", "auth", "idor"),
        severity_hint="high",
    ),
    "exposed": Playbook(
        id="exposed",
        title="Exposed artifacts to full compromise",
        category="exposed",
        objective="Assess what a leaked file, repository or backup reveals and how it can be used.",
        prerequisites=("A path returns content that should not be public",),
        steps=(
            "Verify the artifact is served with real content, not a soft 404.",
            "Extract only metadata, hashes and structure needed to prove the exposure.",
            "Check whether the artifact contains credentials and whether they are still valid (without using them destructively).",
            "Recommend removal, rotation and a review of what else was exposed alongside it.",
        ),
        confirm=("The artifact differs from the application's 404 page", "A second related artifact is also reachable"),
        impact="Repository history and environment files typically contain credentials that unlock production systems.",
        detections=("Requests for .git, .env, backups and editor artifacts", "Unusual 200 responses on dotfiles"),
        references=("https://cwe.mitre.org/data/definitions/538.html",),
        techniques=("exposed_file",),
        severity_hint="high",
    ),
    "deserialization": Playbook(
        id="deserialization",
        title="Unsafe deserialization to code execution",
        category="deserialization",
        objective="Determine whether untrusted data is deserialised with dangerous semantics.",
        prerequisites=("The application accepts serialised objects or signed blobs",),
        steps=(
            "Identify the format (Java serialisation, PHP, Python pickle, .NET, YAML).",
            "Confirm with a benign class that only changes timing or output.",
            "Escalate to a single gadget only when the engagement explicitly permits code execution.",
            "Record the exact blob and the library versions involved.",
        ),
        confirm=("A benign gadget changes behaviour without payload side effects",),
        impact="Remote code execution with the privileges of the application server.",
        detections=("Base64 blobs with serialisation magic bytes", "Deserialisation errors in logs"),
        references=("https://cwe.mitre.org/data/definitions/502.html",),
        techniques=("deserialization",),
        severity_hint="critical",
    ),
    "smuggling": Playbook(
        id="smuggling",
        title="Request smuggling to cache poisoning",
        category="smuggling",
        objective="Establish whether front-end and back-end disagree about request boundaries.",
        prerequisites=("A proxy or CDN sits in front of the application",),
        steps=(
            "Send paired requests with conflicting Content-Length and Transfer-Encoding headers.",
            "Measure response timing and queue effects rather than changing shared state.",
            "Do not poison a cache shared with real users.",
            "Capture both requests and the observed timing difference.",
        ),
        confirm=("The second request is affected by the first in a repeatable way",),
        impact="Bypass of access controls, cache poisoning and credential capture from other users' requests.",
        detections=("Conflicting framing headers", "Unexpected request counts on the back end"),
        references=("https://cwe.mitre.org/data/definitions/444.html",),
        techniques=("smuggling",),
        severity_hint="high",
    ),
    "config": Playbook(
        id="config",
        title="Security configuration gaps",
        category="config",
        objective="Prioritise configuration weaknesses that make other attacks easier.",
        prerequisites=("Headers, cookies or TLS settings were collected",),
        steps=(
            "Capture the current headers and cookie attributes for each host in scope.",
            "Map missing controls to the concrete attack they enable.",
            "Propose the exact header or attribute values expected by the platform.",
            "Re-test after deployment with the same collector.",
        ),
        confirm=("The missing control is observable in every response",),
        impact="Reduced defence in depth: easier exploitation of injection and session attacks.",
        detections=("Automated header audits", "Browser console warnings"),
        references=("https://owasp.org/www-project-secure-headers/",),
        severity_hint="low",
    ),
    "disclosure": Playbook(
        id="disclosure",
        title="Information disclosure to targeted attack",
        category="info",
        objective="Turn leaked metadata into a concrete attack path.",
        prerequisites=("Errors, headers or files expose internal detail",),
        steps=(
            "Collect the leaked versions, paths and identifiers with evidence.",
            "Correlate versions with public advisories to find exploitable components.",
            "Check whether the leak reveals credentials or internal hostnames.",
            "Recommend removal of the leak and upgrade of the identified components.",
        ),
        confirm=("The leaked version matches the running component",),
        impact="Attackers skip reconnaissance and target the exact vulnerable component.",
        detections=("Server banners", "Error pages", "Publicly served dotfiles"),
        references=("https://cwe.mitre.org/data/definitions/200.html",),
        severity_hint="medium",
    ),
}


CATEGORY_ALIASES = {
    "rce": "rce",
    "command": "rce",
    "cmdi": "rce",
    "sqli": "sqli",
    "sql": "sqli",
    "nosqli": "sqli",
    "xss": "xss",
    "ssti": "ssti",
    "template": "ssti",
    "lfi": "lfi",
    "traversal": "lfi",
    "ssrf": "ssrf",
    "auth": "auth",
    "jwt": "auth",
    "idor": "auth",
    "csrf": "auth",
    "exposed": "exposed",
    "disclosure": "disclosure",
    "info": "disclosure",
    "deserialization": "deserialization",
    "smuggling": "smuggling",
    "headers": "config",
    "cookies": "config",
    "tls": "config",
    "cors": "config",
}


def playbook(identifier: str) -> Playbook | None:
    key = identifier.strip().lower()
    if key in PLAYBOOKS:
        return PLAYBOOKS[key]
    alias = CATEGORY_ALIASES.get(key)
    return PLAYBOOKS.get(alias) if alias else None


def playbook_ids() -> list[str]:
    return sorted(PLAYBOOKS)


def playbooks_by_category() -> dict[str, list[str]]:
    grouped: dict[str, list[str]] = {}
    for item in PLAYBOOKS.values():
        grouped.setdefault(item.category, []).append(item.id)
    return {category: sorted(ids) for category, ids in grouped.items()}
