"""Static analysis of JavaScript for DOM sinks and hidden endpoints.

This is deliberately heuristic: it looks for classic source-to-sink flows that
are cheap to spot and frequently exploitable. A match is reported as "possible"
until a detector confirms it by observing the reflection in a live page.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterable

SOURCES = {
    "location.hash": "URL fragment, fully attacker controlled",
    "location.search": "query string, attacker controlled via a crafted link",
    "location.href": "full URL, attacker controlled via a crafted link",
    "document.URL": "document URL, attacker controlled",
    "document.documentURI": "document URI, attacker controlled",
    "document.referrer": "referrer header, attacker influenced",
    "window.name": "persisted across navigations, attacker controlled",
    "document.cookie": "cookie content, may contain attacker data",
    "postMessage": "cross-window messaging, origin checks frequently missing",
    "localStorage": "persistent storage, may contain attacker data",
    "sessionStorage": "session storage, may contain attacker data",
    "innerText": "text extraction from the DOM",
}

SINKS = {
    "innerHTML": "HTML injection",
    "outerHTML": "HTML injection",
    "insertAdjacentHTML": "HTML injection",
    "document.write": "HTML injection",
    "document.writeln": "HTML injection",
    "eval": "arbitrary JavaScript execution",
    "Function": "arbitrary JavaScript execution",
    "setTimeout": "code execution when the first argument is a string",
    "setInterval": "code execution when the first argument is a string",
    "new Function": "arbitrary JavaScript execution",
    "jQuery.html": "HTML injection",
    "jQuery.append": "HTML injection",
    "jQuery.prepend": "HTML injection",
    "jQuery.after": "HTML injection",
    "jQuery.before": "HTML injection",
    "$.globalEval": "arbitrary JavaScript execution",
    "v-html": "Vue HTML injection",
    "dangerouslySetInnerHTML": "React HTML injection",
    "srcdoc": "iframe HTML injection",
    "javascript:": "javascript URI execution",
}

_ENDPOINT_RE = re.compile(
    r"""["'`]((?:https?://[^"'`\s]+)|(?:/[A-Za-z0-9_\-./{}?=&%:]+))["'`]"""
)
_FETCH_RE = re.compile(r"""(?:fetch|axios\.(?:get|post|put|delete)|\.open)\s*\(\s*["'`]([^"'`]+)["'`]""")
_ASSIGN_RE = re.compile(r"""(?:var|let|const)?\s*([A-Za-z_$][\w$]*)\s*=\s*([^;\n]+)""")


@dataclass
class SinkMatch:
    sink: str
    source: str
    line: int
    snippet: str
    kind: str = "dom-xss"

    def to_dict(self) -> dict[str, Any]:
        return {
            "sink": self.sink,
            "source": self.source,
            "line": self.line,
            "snippet": self.snippet,
            "kind": self.kind,
        }


@dataclass
class ScriptAnalysis:
    sources: list[str] = field(default_factory=list)
    sinks: list[str] = field(default_factory=list)
    matches: list[SinkMatch] = field(default_factory=list)
    endpoints: list[str] = field(default_factory=list)
    secrets: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "sources": sorted(set(self.sources)),
            "sinks": sorted(set(self.sinks)),
            "matches": [match.to_dict() for match in self.matches],
            "endpoints": sorted(set(self.endpoints)),
        }


def analyze_script(script: str, *, line_limit: int = 5000) -> ScriptAnalysis:
    analysis = ScriptAnalysis()
    if not script:
        return analysis
    lines = script.splitlines()[:line_limit]
    for number, line in enumerate(lines, start=1):
        for source in SOURCES:
            if source in line:
                analysis.sources.append(source)
        for sink in SINKS:
            if sink in line:
                analysis.sinks.append(sink)
        if any(source in line for source in SOURCES) and any(sink in line for sink in SINKS):
            analysis.matches.append(
                SinkMatch(
                    sink=_first_present(line, SINKS),
                    source=_first_present(line, SOURCES),
                    line=number,
                    snippet=line.strip()[:240],
                )
            )
    # taint-lite: variable assigned from a source and later used in a sink
    assigned: dict[str, str] = {}
    for number, line in enumerate(lines, start=1):
        match = _ASSIGN_RE.search(line)
        if match:
            name, expression = match.group(1), match.group(2)
            for source in SOURCES:
                if source in expression:
                    assigned[name] = source
                    break
        for name, source in list(assigned.items()):
            if re.search(rf"\b{re.escape(name)}\b", line) and not _ASSIGN_RE.search(line):
                for sink in SINKS:
                    if sink in line:
                        analysis.matches.append(
                            SinkMatch(
                                sink=sink,
                                source=source,
                                line=number,
                                snippet=line.strip()[:240],
                                kind="dom-xss-tainted",
                            )
                        )
    for match in _FETCH_RE.finditer(script):
        analysis.endpoints.append(match.group(1))
    for match in _ENDPOINT_RE.finditer(script):
        candidate = match.group(1)
        if candidate.startswith(("/", "http://", "https://")) and not candidate.endswith((".png", ".jpg", ".css", ".woff", ".svg", ".ico")):
            analysis.endpoints.append(candidate)
    analysis.endpoints = list(dict.fromkeys(analysis.endpoints))[:200]
    return analysis


def _first_present(line: str, mapping: dict[str, str]) -> str:
    for key in mapping:
        if key in line:
            return key
    return ""


def iter_script_blocks(html: str, *, limit: int = 200) -> Iterable[str]:
    pattern = re.compile(r"<script[^>]*>(.*?)</script>", re.IGNORECASE | re.DOTALL)
    for index, match in enumerate(pattern.finditer(html or "")):
        if index >= limit:
            break
        body = match.group(1).strip()
        if body:
            yield body


def has_unsafe_dynamic_handler(html: str) -> list[str]:
    patterns = {
        "inline-event-handler": re.compile(r"""\son[a-z]+\s*=\s*["'][^"']*["']""", re.IGNORECASE),
        "javascript-uri": re.compile(r"""href\s*=\s*["']javascript:""", re.IGNORECASE),
        "eval-call": re.compile(r"\beval\s*\(", re.IGNORECASE),
    }
    return [name for name, pattern in patterns.items() if pattern.search(html or "")]


def analyze_document(html: str, scripts: Iterable[str] = ()) -> dict[str, Any]:
    combined = "\n".join([*iter_script_blocks(html), *scripts])
    analysis = analyze_script(combined)
    result = analysis.to_dict()
    result["inline_handlers"] = has_unsafe_dynamic_handler(html)
    return result
