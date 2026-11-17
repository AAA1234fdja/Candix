"""Turn a finding into a request someone else can run."""

from __future__ import annotations

import json
import re
import shlex
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from candix.agent.knowledge import payloads_for

SECRET_HEADERS = {"authorization", "cookie", "x-api-key", "proxy-authorization", "x-auth-token"}
MARKER = "candix_probe_7f3a"


@dataclass
class Request:
    method: str = "GET"
    url: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    note: str = ""

    def header(self, name: str, default: str = "") -> str:
        for key, value in self.headers.items():
            if key.lower() == name.lower():
                return value
        return default

    def with_param(self, name: str, value: str) -> "Request":
        parsed = urllib.parse.urlsplit(self.url)
        pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        replaced = False
        rebuilt: list[tuple[str, str]] = []
        for key, existing in pairs:
            if key == name:
                rebuilt.append((key, value))
                replaced = True
            else:
                rebuilt.append((key, existing))
        if not replaced:
            rebuilt.append((name, value))
        query = urllib.parse.urlencode(rebuilt)
        return Request(self.method, urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, parsed.fragment)), dict(self.headers), self.body, self.note)

    def with_header(self, name: str, value: str) -> "Request":
        headers = {key: existing for key, existing in self.headers.items() if key.lower() != name.lower()}
        headers[name] = value
        return Request(self.method, self.url, headers, self.body, self.note)

    def params(self) -> dict[str, str]:
        return dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(self.url).query, keep_blank_values=True))

    def to_dict(self) -> dict[str, Any]:
        return {"method": self.method, "url": self.url, "headers": self.headers, "body": self.body, "note": self.note}


@dataclass
class PoC:
    finding: dict[str, Any]
    request: Request
    expect: str = ""
    steps: list[str] = field(default_factory=list)

    def files(self) -> dict[str, str]:
        return {
            "poc.sh": to_curl(self.request),
            "poc.py": to_python(self.request),
            "poc.mjs": to_js(self.request),
            "poc.http": to_raw(self.request),
            "README.md": self.readme(),
        }

    def readme(self) -> str:
        lines = [
            f"# Proof of concept: {self.finding.get('title', 'finding')}",
            "",
            f"- severity: {self.finding.get('severity', 'unknown')}",
            f"- endpoint: `{self.request.method} {self.request.url}`",
            f"- parameter: `{self.finding.get('parameter', 'n/a')}`",
            "",
            "## Steps",
            "",
        ]
        for index, step in enumerate(self.steps or ["run `bash poc.sh`"], start=1):
            lines.append(f"{index}. {step}")
        lines += ["", "## Expected", "", self.expect or "the response differs from the control request", ""]
        lines += ["## Files", "", "- `poc.sh` — curl, no dependencies", "- `poc.py` — standard library only", "- `poc.mjs` — Node 18+ fetch", "- `poc.http` — raw request for Burp/IntelliJ", ""]
        lines += ["## Handling", "", "Credentials are placeholders. Export them before running:", ""]
        for name in sorted(_placeholders(self.request)):
            lines.append(f"    export {name}='<value>'")
        lines += ["", "Run this only against the engagement's in-scope hosts.", ""]
        return "\n".join(lines)

    def write(self, directory: str | Path) -> list[str]:
        base = Path(directory)
        base.mkdir(parents=True, exist_ok=True)
        written = []
        for name, body in self.files().items():
            path = base / name
            path.write_text(body, encoding="utf-8")
            if name.endswith(".sh"):
                path.chmod(0o755)
            written.append(str(path))
        return written


def _placeholders(request: Request) -> set[str]:
    names: set[str] = set()
    for key in request.headers:
        lowered = key.lower()
        if lowered in SECRET_HEADERS:
            names.add("CANDIX_AUTH" if lowered == "authorization" else f"CANDIX_{lowered.replace('-', '_').upper()}")
    return names


def _header_value(key: str, value: str, *, shell: bool) -> str:
    lowered = key.lower()
    if lowered not in SECRET_HEADERS:
        return value
    name = "CANDIX_AUTH" if lowered == "authorization" else f"CANDIX_{lowered.replace('-', '_').upper()}"
    return f"${name}" if shell else f"{{{{env:{name}}}}}"


def to_curl(request: Request) -> str:
    parts = ["curl", "-sS", "-i", "-X", request.method, shlex.quote(request.url)]
    for key, value in request.headers.items():
        rendered = _header_value(key, value, shell=True)
        if rendered.startswith("$"):
            parts += ["-H", shlex.quote(f'{key}: ') + '"' + rendered + '"']
        else:
            parts += ["-H", shlex.quote(f"{key}: {value}")]
    if request.body:
        parts += ["--data-raw", shlex.quote(request.body)]
    return "#!/usr/bin/env bash\nset -euo pipefail\n" + " ".join(parts) + "\n"


def to_python(request: Request) -> str:
    headers = json.dumps({key: _header_value(key, value, shell=False) for key, value in request.headers.items()}, indent=4)
    body = repr(request.body) if request.body else "None"
    return "\n".join(
        [
            "import json",
            "import urllib.request",
            "",
            f"URL = {request.url!r}",
            f"HEADERS = json.loads(r'''{headers}''')",
            f"BODY = {body}",
            "",
            "def main() -> None:",
            "    for key in list(HEADERS):",
            "        if HEADERS[key].startswith('{' + '{env:'):",
            "            import os",
            "",
            "            name = HEADERS[key][6:-2]",
            "            HEADERS[key] = os.environ.get(name, '')",
            "    data = BODY.encode('utf-8') if BODY else None",
            f"    request = urllib.request.Request(URL, data=data, headers=HEADERS, method={request.method!r})",
            "    with urllib.request.urlopen(request, timeout=15) as response:",
            "        payload = response.read().decode('utf-8', 'replace')",
            "        print(response.status)",
            "        print(payload[:4000])",
            "",
            "",
            "if __name__ == '__main__':",
            "    main()",
            "",
        ]
    )


def to_js(request: Request) -> str:
    headers = json.dumps({key: _header_value(key, value, shell=False) for key, value in request.headers.items()}, indent=2)
    return "\n".join(
        [
            "const headers = " + headers + ";",
            "const env = (value) => value.replace(/\\{\\{env:([A-Z0-9_]+)\\}\\}/g, (_, name) => process.env[name] ?? '');",
            "const clean = Object.fromEntries(Object.entries(headers).map(([k, v]) => [k, env(v)]));",
            "",
            f"const response = await fetch({request.url!r}, {{",
            f"  method: {request.method!r},",
            "  headers: clean,",
            f"  body: {json.dumps(request.body) if request.body else 'undefined'},",
            "});",
            "console.log(response.status);",
            "console.log((await response.text()).slice(0, 4000));",
            "",
        ]
    )


def to_httpie(request: Request) -> str:
    parts = ["http", request.method, shlex.quote(request.url)]
    for key, value in request.headers.items():
        parts.append(shlex.quote(f"{key}:{value}"))
    if request.body:
        parts += ["--raw", shlex.quote(request.body)]
    return " ".join(parts) + "\n"


def to_raw(request: Request) -> str:
    parsed = urllib.parse.urlsplit(request.url)
    target = parsed.path or "/"
    if parsed.query:
        target += "?" + parsed.query
    lines = [f"{request.method} {target} HTTP/1.1", f"Host: {parsed.netloc}"]
    for key, value in request.headers.items():
        if key.lower() == "host":
            continue
        lines.append(f"{key}: {value}")
    lines.append("")
    if request.body:
        lines.append(request.body)
    return "\r\n".join(lines) + "\r\n"


def parse_request(raw: str) -> Request:
    lines = raw.replace("\r\n", "\n").split("\n")
    if not lines or not lines[0].strip():
        raise ValueError("empty request")
    method, target, *_ = lines[0].split(" ")
    headers: dict[str, str] = {}
    body_lines: list[str] = []
    in_body = False
    host = ""
    for line in lines[1:]:
        if in_body:
            body_lines.append(line)
            continue
        if not line.strip():
            in_body = True
            continue
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip()
        value = value.strip()
        if key.lower() == "host":
            host = value
        else:
            headers[key] = value
    url = target if target.startswith("http") else f"http://{host}{target}"
    return Request(method=method.upper(), url=url, headers=headers, body="\n".join(body_lines).strip())


def from_finding(finding: dict[str, Any], *, evidence: dict[str, Any] | None = None) -> PoC:
    request = request_from_evidence(evidence or {}) or request_from_finding(finding)
    return PoC(finding=finding, request=request, expect=expected_observation(finding), steps=steps_for(finding))


def request_from_evidence(evidence: dict[str, Any]) -> Request | None:
    for key in ("request", "exchange", "attempt"):
        block = evidence.get(key)
        if isinstance(block, dict) and block.get("url"):
            return Request(
                method=str(block.get("method", "GET")).upper(),
                url=str(block["url"]),
                headers={str(k): str(v) for k, v in (block.get("headers") or {}).items()},
                body=str(block.get("body", "") or ""),
            )
    if isinstance(evidence.get("request_raw"), str):
        try:
            return parse_request(evidence["request_raw"])
        except ValueError:
            return None
    return None


def request_from_finding(finding: dict[str, Any]) -> Request:
    url = str(finding.get("url", ""))
    method = str(finding.get("method", "GET") or "GET").upper()
    parameter = str(finding.get("parameter", "") or "")
    headers = {str(key): str(value) for key, value in (finding.get("headers") or {}).items()}
    payload = str(finding.get("payload", "") or "")
    request = Request(method=method, url=url, headers=headers)
    if parameter and payload:
        request = request.with_param(parameter, payload)
    elif parameter:
        request = request.with_param(parameter, MARKER)
    return request


def expected_observation(finding: dict[str, Any]) -> str:
    category = str(finding.get("category", "")).lower()
    if category == "xss":
        return f"the response body contains the unencoded marker `{MARKER}`"
    if category == "sqli":
        return "the true/false pair produces different responses"
    if category == "ssrf":
        return "the callback host receives a request from the target's address"
    if category == "idor":
        return "the response returns another subject's object"
    if category == "exposed_secret":
        return "the response contains real file content, not a soft 404 page"
    if category == "lfi":
        return "the response contains the contents of the requested file"
    return "the response differs from the control request in a way that matches the finding"


def steps_for(finding: dict[str, Any]) -> list[str]:
    request = request_from_finding(finding)
    parameter = str(finding.get("parameter", "") or "")
    steps = [f"send the control request to `{request.url}` and keep the response"]
    if parameter:
        steps.append(f"repeat with `{parameter}` replaced by the payload in `poc.http`")
    steps.append(f"confirm: {expected_observation(finding)}")
    steps.append("attach both responses to the finding as evidence")
    return steps


def payload_for(finding: dict[str, Any]) -> str:
    existing = str(finding.get("payload", "") or "")
    if existing:
        return existing
    category = str(finding.get("category", ""))
    options = payloads_for(category)
    return options[0] if options else MARKER


def variants(finding: dict[str, Any]) -> list[Request]:
    request = request_from_finding(finding)
    parameter = str(finding.get("parameter", "") or "")
    if not parameter:
        return [request]
    category = str(finding.get("category", ""))
    payloads = list(payloads_for(category)) or [MARKER]
    return [request.with_param(parameter, item) for item in payloads[:4]]


def control(finding: dict[str, Any]) -> Request:
    request = request_from_finding(finding)
    parameter = str(finding.get("parameter", "") or "")
    if not parameter:
        return request
    return request.with_param(parameter, "candix_control_1")


def bundle_for(findings: Iterable[dict[str, Any]], directory: str | Path) -> list[str]:
    base = Path(directory)
    written: list[str] = []
    for index, finding in enumerate(findings, start=1):
        slug = re.sub(r"[^a-z0-9]+", "-", str(finding.get("title", "finding")).lower()).strip("-")[:40]
        written += from_finding(finding).write(base / f"{index:02d}-{slug or 'finding'}")
    return written


def as_curl(finding: dict[str, Any]) -> str:
    return to_curl(request_from_finding(finding))
