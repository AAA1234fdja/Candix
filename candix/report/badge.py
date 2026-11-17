"""SVG badge generation for CI pages and pull requests."""

from __future__ import annotations

import re
from typing import Any
from xml.sax.saxutils import escape

from candix.report.model import ReportModel

_COLOURS = {
    "critical": "#b91c1c",
    "high": "#dc2626",
    "medium": "#d97706",
    "low": "#0284c7",
    "info": "#475569",
    "clean": "#16a34a",
}


def _text_width(text: str, size: int = 11) -> int:
    return int(len(text) * size * 0.62) + 10


def badge(
    label: str,
    value: str,
    *,
    colour: str = "#475569",
) -> str:
    label_width = _text_width(label)
    value_width = _text_width(value)
    total = label_width + value_width
    colour = _COLOURS.get(str(colour), str(colour)) if str(colour) in _COLOURS else str(colour)
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{total}" height="20" role="img" '
        f'aria-label="{escape(label)}: {escape(value)}">'
        f"<title>{escape(label)}: {escape(value)}</title>"
        f'<linearGradient id="s" x2="0" y2="100%">'
        f'<stop offset="0" stop-color="#bbb" stop-opacity=".1"/><stop offset="1" stop-opacity=".1"/>'
        f"</linearGradient>"
        f'<clipPath id="r"><rect width="{total}" height="20" rx="3" fill="#fff"/></clipPath>'
        f'<g clip-path="url(#r)">'
        f'<rect width="{label_width}" height="20" fill="#555"/>'
        f'<rect x="{label_width}" width="{value_width}" height="20" fill="{escape(colour)}"/>'
        f'<rect width="{total}" height="20" fill="url(#s)"/>'
        f"</g>"
        f'<g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" '
        f'font-size="11">'
        f'<text x="{label_width / 2:.0f}" y="14">{escape(label)}</text>'
        f'<text x="{label_width + value_width / 2:.0f}" y="14">{escape(value)}</text>'
        f"</g></svg>"
    )


def severity_badge(model: ReportModel) -> str:
    counts = model.counts
    worst = next((severity for severity in ("critical", "high", "medium", "low") if counts.get(severity)), "clean")
    total = counts.get("total", 0)
    value = f"{worst} {counts.get(worst, 0)}" if worst != "clean" else "clean"
    return badge("candix", f"{value} · {total} total", colour=_COLOURS.get(worst, "#475569"))


def score_badge(model: ReportModel) -> str:
    score = model.risk_score
    colour = "#16a34a" if score < 10 else "#d97706" if score < 40 else "#dc2626"
    return badge("risk", f"{score:.1f}", colour=colour)


def coverage_badge(model: ReportModel) -> str:
    verified = len(model.verified_findings)
    total = max(1, model.counts.get("total", 0))
    ratio = int(round(verified / total * 100))
    colour = "#16a34a" if ratio >= 60 else "#d97706" if ratio >= 30 else "#dc2626"
    return badge("verified", f"{ratio}%", colour=colour)


def proofs_badge(model: ReportModel) -> str:
    count = len(model.exploited_findings)
    colour = "#dc2626" if count else "#16a34a"
    return badge("proofs", str(count), colour=colour)


def badges(model: ReportModel) -> list[dict[str, str]]:
    return [
        {"name": "severity", "svg": severity_badge(model)},
        {"name": "risk", "svg": score_badge(model)},
        {"name": "verified", "svg": coverage_badge(model)},
        {"name": "proofs", "svg": proofs_badge(model)},
    ]


def render(model: ReportModel, *, name: str = "severity") -> str:
    mapping = {item["name"]: item["svg"] for item in badges(model)}
    if name not in mapping:
        raise ValueError(f"unknown badge: {name}")
    return mapping[name]


def sanitize(text: str) -> str:
    return re.sub(r"[\x00-\x1f<>&\"']", "", text or "")


def summary(model: ReportModel) -> dict[str, Any]:
    return {
        "badges": [item["name"] for item in badges(model)],
        "worst": next((s for s in ("critical", "high", "medium", "low") if model.counts.get(s)), "clean"),
        "risk": model.risk_score,
        "total": model.counts.get("total", 0),
    }
