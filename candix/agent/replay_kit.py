"""Turn captured exchanges into something a client can run themselves.

The proof is only useful if it reproduces. Each package contains a shell script,
a Python snippet and a REST-client file, all built from the stored request, with
secrets replaced by environment variables instead of pasted in.
"""

from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

_SKIP_HEADERS = {"content-length", "host", "connection", "accept-encoding"}
_SECRET_HEADERS = {"authorization", "cookie", "set-cookie", "x-api-key", "proxy-authorization"}


def _request_of(payload: dict[str, Any]) -> dict[str, Any]:
    request = payload.get("request")
    if isinstance(request, dict):
        return request
    exchange = payload.get("exchange")
    if isinstance(exchange, dict) and isinstance(exchange.get("request"), dict):
        return exchange["request"]
    return {"url": payload.get("url", ""), "method": payload.get("method", "GET")}


@dataclass
class ReplayPackage:
    title: str
    request: dict[str, Any]
    directory: str = ""
    files: list[str] = field(default_factory=list)

    @property
    def url(self) -> str:
        return str(self.request.get("url", ""))

    @property
    def method(self) -> str:
        return str(self.request.get("method", "GET")).upper()

    def headers(self, *, keep_secrets: bool = True) -> dict[str, str]:
        raw = self.request.get("headers") or {}
        output: dict[str, str] = {}
        for name, value in (raw.items() if isinstance(raw, dict) else []):
            lowered = str(name).lower()
            if lowered in _SKIP_HEADERS:
                continue
            if not keep_secrets and lowered in _SECRET_HEADERS:
                continue
            output[str(name)] = str(value)
        return output

    def body(self) -> str:
        return str(self.request.get("body") or self.request.get("data") or "")

    # ------------------------------------------------------------------
    def curl(self, *, keep_secrets: bool = False) -> str:
        parts = [f"curl -sS -i -X {self.method} '{self.url}'"]
        for name, value in self.headers(keep_secrets=keep_secrets).items():
            parts.append(f"  -H '{name}: {value}'")
        if self.body():
            parts.append(f"  --data-raw '{self.body()[:2000]}'")
        return " \\\n".join(parts)

    def bash(self) -> str:
        return "\n".join(
            [
                "#!/usr/bin/env bash",
                "set -euo pipefail",
                f"# {self.title}",
                "# export TOKEN and COOKIE before running; they are not stored in this file.",
                "",
                self.curl(),
                "",
            ]
        )

    def httpie(self) -> str:
        parts = [f"http {self.method} '{self.url}'"]
        for name, value in self.headers().items():
            parts.append(f"  '{name}:{value}'")
        if self.body():
            parts.append(f"  <<< '{self.body()[:2000]}'")
        return " \\\n".join(parts)

    def python(self) -> str:
        return "\n".join(
            [
                "import json",
                "import os",
                "",
                "import urllib.request",
                "",
                f"request = urllib.request.Request({self.url!r}, method={self.method!r})",
                "for name, value in {",
                *[f"    {name!r}: os.environ.get({name.upper().replace('-', '_')!r}, {value!r})," for name, value in self.headers().items()],
                "}.items():",
                "    request.add_header(name, value)",
                f"data = {self.body()!r}.encode() if {bool(self.body())!r} else None",
                "with urllib.request.urlopen(request, data=data) as response:",
                "    print(response.status)",
                "    print(response.read().decode('utf-8', 'replace')[:4000])",
                "",
            ]
        )

    def rest(self) -> str:
        lines = [f"### {self.title}", f"{self.method} {self.url}"]
        for name, value in self.headers().items():
            lines.append(f"{name}: {value}")
        if self.body():
            lines.extend(["", self.body()[:2000]])
        return "\n".join(lines) + "\n"

    def powershell(self) -> str:
        return "\n".join(
            [
                f"$headers = @{{",
                *[f"  '{name}' = '{value}'" for name, value in self.headers().items()],
                "}",
                f"Invoke-WebRequest -Method {self.method.title()} -Uri '{self.url}' -Headers $headers"
                + (" -Body '" + self.body()[:1000] + "'" if self.body() else ""),
                "",
            ]
        )

    def to_dict(self) -> dict[str, Any]:
        return {"title": self.title, "url": self.url, "method": self.method, "files": list(self.files)}


def package(payload: dict[str, Any], *, title: str = "") -> ReplayPackage:
    return ReplayPackage(title=title or str(payload.get("title") or payload.get("claim") or "proof"), request=_request_of(payload))


def write(packages: Iterable[ReplayPackage], directory: str | Path, *, shell_only: bool = False) -> list[str]:
    root = Path(directory)
    root.mkdir(parents=True, exist_ok=True)
    written: list[str] = []
    for index, bundle in enumerate(packages, start=1):
        base = f"proof-{index:02d}"
        targets = [("sh", bundle.bash(), 0o755)]
        if not shell_only:
            targets.extend(
                [
                    ("py", bundle.python(), 0o644),
                    ("http", bundle.rest(), 0o644),
                    ("ps1", bundle.powershell(), 0o644),
                ]
            )
        for extension, content, mode in targets:
            path = root / f"{base}.{extension}"
            path.write_text(content, encoding="utf-8")
            path.chmod(mode | stat.S_IRUSR)
            written.append(str(path))
    return written


def index(packages: Iterable[ReplayPackage]) -> str:
    lines = ["# Replay kit", "", "Run each script after exporting the credentials it references.", ""]
    for index_number, bundle in enumerate(packages, start=1):
        lines.append(f"## {index_number}. {bundle.title}")
        lines.append("")
        lines.append(f"`{bundle.method} {bundle.url}`")
        lines.append("")
        lines.append("```bash")
        lines.append(bundle.curl())
        lines.append("```")
        lines.append("")
    return "\n".join(lines)


def from_result(result: Any) -> list[ReplayPackage]:
    bundles = []
    for proof in getattr(result, "proofs", []):
        bundles.append(package(proof))
    for finding in getattr(result, "findings", []):
        if not (finding.get("verified") or finding.get("exploited")):
            continue
        request = finding.get("request") or {"url": finding.get("url", ""), "method": finding.get("method", "GET")}
        bundles.append(package({"title": finding.get("title", "finding"), "request": request}))
    return bundles


def manifest(bundles: Iterable[ReplayPackage]) -> str:
    return json.dumps(
        {
            "package": "candix-replay",
            "count": len(list(bundles)),
            "files": ["proof-NN.sh", "proof-NN.py", "proof-NN.http", "proof-NN.ps1"],
            "notes": "Credentials are read from environment variables; nothing secret is stored here.",
        },
        indent=2,
    )


def checkout_script(bundles: Iterable[ReplayPackage], directory: str = ".") -> str:
    lines = ["#!/usr/bin/env bash", "set -euo pipefail", f"cd {directory!r}"]
    for index, _bundle in enumerate(bundles, start=1):
        lines.append(f"bash proof-{index:02d}.sh | tee proof-{index:02d}.log")
    lines.append("echo 'done'")
    return "\n".join(lines) + "\n"


def ensure_directory(path: str | Path) -> str:
    root = Path(path)
    root.mkdir(parents=True, exist_ok=True)
    return str(root)


def env_template(bundles: Iterable[ReplayPackage]) -> str:
    names: set[str] = set()
    for bundle in bundles:
        for header in bundle.headers(keep_secrets=True):
            if header.lower() in _SECRET_HEADERS:
                names.add(header.upper().replace("-", "_"))
    lines = ["# Fill these in before running the proofs", "set -a"]
    for name in sorted(names):
        lines.append(f"{name}=changeme")
    lines.append(os.linesep + "set +a")
    return "\n".join(lines) + "\n"
