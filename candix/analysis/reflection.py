"""Reflection analysis for XSS and header injection detection.

A parameter is only interesting for cross-site scripting if its value survives
into a response in an executable context. This module locates the reflection,
classifies the surrounding context and checks whether the dangerous characters
were encoded.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

CONTEXT_HTML = "html"
CONTEXT_ATTRIBUTE_DOUBLE = "attribute-double"
CONTEXT_ATTRIBUTE_SINGLE = "attribute-single"
CONTEXT_ATTRIBUTE_UNQUOTED = "attribute-unquoted"
CONTEXT_SCRIPT = "script"
CONTEXT_STYLE = "style"
CONTEXT_COMMENT = "comment"
CONTEXT_URL = "url"
CONTEXT_JSON = "json"
CONTEXT_TEXT = "text"

_SCRIPT_RE = re.compile(r"<script[^>]*>(.*?)</script>", re.IGNORECASE | re.DOTALL)
_STYLE_RE = re.compile(r"<style[^>]*>(.*?)</style>", re.IGNORECASE | re.DOTALL)
_COMMENT_RE = re.compile(r"<!--(.*?)-->", re.DOTALL)
_ATTR_RE = re.compile(r"""[a-zA-Z0-9_:-]+\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+)""", re.DOTALL)


@dataclass
class Reflection:
    marker: str
    found: bool
    count: int = 0
    offset: int = -1
    context: str = CONTEXT_TEXT
    snippet: str = ""
    raw_specials: bool = False
    encoded_specials: bool = False
    executable: bool = False
    attribute_name: str = ""
    tag: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "found": self.found,
            "count": self.count,
            "offset": self.offset,
            "context": self.context,
            "snippet": self.snippet,
            "raw_specials": self.raw_specials,
            "encoded_specials": self.encoded_specials,
            "executable": self.executable,
            "attribute_name": self.attribute_name,
            "tag": self.tag,
        }


def find_reflection(
    text: str,
    marker: str,
    *,
    payload: str | None = None,
    window: int = 120,
) -> Reflection:
    if not text or not marker:
        return Reflection(marker=marker, found=False)
    offset = text.find(marker)
    if offset < 0:
        return Reflection(marker=marker, found=False, snippet="")
    count = text.count(marker)
    start = max(0, offset - window)
    end = min(len(text), offset + len(marker) + window)
    snippet = text[start:end]
    context, tag, attribute = classify_context(text, offset)
    if payload:
        verbatim = payload in text
        raw_specials = verbatim and any(char in payload for char in "<>\"'")
    else:
        raw_specials = any(char in marker for char in "<>\"'")
    encoded_specials = any(
        entity in snippet.lower()
        for entity in ("&lt;", "&gt;", "&quot;", "&#x27;", "&#39;", "%3c", "%3e", "\\u003c")
    )
    executable = context in {
        CONTEXT_HTML,
        CONTEXT_SCRIPT,
        CONTEXT_ATTRIBUTE_DOUBLE,
        CONTEXT_ATTRIBUTE_SINGLE,
        CONTEXT_ATTRIBUTE_UNQUOTED,
        CONTEXT_COMMENT,
    } and raw_specials
    return Reflection(
        marker=marker,
        found=True,
        count=count,
        offset=offset,
        context=context,
        snippet=snippet,
        raw_specials=raw_specials,
        encoded_specials=encoded_specials,
        executable=executable,
        attribute_name=attribute,
        tag=tag,
    )


def classify_context(full_text: str, offset: int) -> tuple[str, str, str]:
    prefix = full_text[:offset]
    for match in _SCRIPT_RE.finditer(full_text):
        if match.start() < offset < match.end():
            return CONTEXT_SCRIPT, "script", ""
    for match in _STYLE_RE.finditer(full_text):
        if match.start() < offset < match.end():
            return CONTEXT_STYLE, "style", ""
    for match in _COMMENT_RE.finditer(full_text):
        if match.start() < offset < match.end():
            return CONTEXT_COMMENT, "comment", ""
    tag_start = prefix.rfind("<")
    tag_end = prefix.rfind(">")
    if tag_start > tag_end:
        fragment = prefix[tag_start:]
        tag_match = re.match(r"<\s*([a-zA-Z0-9]+)", fragment)
        tag = tag_match.group(1).lower() if tag_match else ""
        for match in _ATTR_RE.finditer(fragment):
            attr_text = match.group(0)
            name, _, value = attr_text.partition("=")
            value = value.strip()
            if len(name) and name.strip().lower() in {"href", "src", "action", "formaction", "data", "poster"}:
                return CONTEXT_URL, tag, name.strip().lower()
            if value.startswith('"'):
                return CONTEXT_ATTRIBUTE_DOUBLE, tag, name.strip().lower()
            if value.startswith("'"):
                return CONTEXT_ATTRIBUTE_SINGLE, tag, name.strip().lower()
            return CONTEXT_ATTRIBUTE_UNQUOTED, tag, name.strip().lower()
        return CONTEXT_HTML, tag, ""
    trimmed = prefix.rstrip()
    if trimmed.endswith(("{", "[", ":")) and '"' in prefix[-200:]:
        return CONTEXT_JSON, "", ""
    return CONTEXT_HTML, "", ""


def is_escaping_effective(text: str) -> bool:
    lowered = text.lower()
    return any(entity in lowered for entity in ("&lt;", "&gt;", "&quot;", "&#x27;", "&#39;"))


def score_reflection(reflection: Reflection, *, payload_has_script: bool = False) -> float:
    if not reflection.found:
        return 0.0
    score = 0.0
    if reflection.context == CONTEXT_HTML:
        score += 0.45
    elif reflection.context in {CONTEXT_ATTRIBUTE_DOUBLE, CONTEXT_ATTRIBUTE_SINGLE}:
        score += 0.35
    elif reflection.context == CONTEXT_ATTRIBUTE_UNQUOTED:
        score += 0.4
    elif reflection.context == CONTEXT_SCRIPT:
        score += 0.55
    elif reflection.context == CONTEXT_URL:
        score += 0.4 if payload_has_script else 0.2
    elif reflection.context == CONTEXT_COMMENT:
        score += 0.3
    else:
        score += 0.05
    if reflection.raw_specials:
        score += 0.35
    if reflection.encoded_specials and not reflection.raw_specials:
        score -= 0.2
    if payload_has_script and reflection.raw_specials:
        score += 0.1
    return max(0.0, min(1.0, score))


def reflection_variants(marker: str) -> list[str]:
    """Encodings a framework might apply; used to detect weak filters."""

    return [
        marker,
        marker.replace("<", "&lt;"),
        marker.replace(">", "&gt;"),
        marker.replace('"', "&quot;"),
        marker.replace("'", "&#39;"),
        marker.replace("<", "\\u003c"),
        marker.replace("<", "%3c"),
    ]


def find_all_reflections(text: str, marker: str) -> list[int]:
    offsets: list[int] = []
    start = 0
    while True:
        index = text.find(marker, start)
        if index < 0:
            break
        offsets.append(index)
        start = index + len(marker)
    return offsets


def contains_unescaped_tag(text: str, tag: str = "script") -> bool:
    pattern = re.compile(rf"<\s*{re.escape(tag)}[\s>]", re.IGNORECASE)
    return bool(pattern.search(text))


def detect_csp_bypass_hint(text: str) -> list[str]:
    """Look for JSONP endpoints and unsafe sinks advertised in the page."""

    hints: list[str] = []
    if re.search(r"callback\s*=", text or "", re.IGNORECASE):
        hints.append("jsonp-callback-parameter")
    if re.search(r"angular\.module|ng-app", text or "", re.IGNORECASE):
        hints.append("angularjs-template-injection-candidate")
    if re.search(r"requirejs|webpackJsonp", text or "", re.IGNORECASE):
        hints.append("client-side-module-loader")
    return hints
