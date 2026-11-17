"""Content analysis: HTML/JS parsing, response diffing and statistics."""

from __future__ import annotations

from candix.analysis.diff import ResponseDiff, compare_responses
from candix.analysis.html import HTMLDocument, extract_links, parse_forms
from candix.analysis.reflection import Reflection, find_reflection

__all__ = [
    "HTMLDocument",
    "Reflection",
    "ResponseDiff",
    "compare_responses",
    "extract_links",
    "find_reflection",
    "parse_forms",
]
