"""Jupyter notebook export for analysts who want to continue the work."""

from __future__ import annotations

import json
from typing import Any, Iterable

from candix.report.model import ReportModel


def _code(source: str) -> dict[str, Any]:
    return {
        "cell_type": "code",
        "execution_count": None,
        "metadata": {},
        "outputs": [],
        "source": [line + "\n" for line in source.strip().splitlines()],
    }


def _markdown(source: str) -> dict[str, Any]:
    return {
        "cell_type": "markdown",
        "metadata": {},
        "source": [line + "\n" for line in source.strip().splitlines()],
    }


def _notebook(cells: list[dict[str, Any]], *, title: str) -> dict[str, Any]:
    return {
        "cells": cells,
        "metadata": {
            "kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"},
            "language_info": {"name": "python", "version": "3.11"},
            "title": title,
        },
        "nbformat": 4,
        "nbformat_minor": 5,
    }


def render_notebook(model: ReportModel, *, include_findings: int = 50) -> str:
    counts = model.counts
    cells: list[dict[str, Any]] = [
        _markdown(
            f"# {model.title}\n\n"
            f"Scan `{model.scan_id}` · {model.profile} profile · generated {model.generated_at}\n\n"
            f"- Findings: **{counts.get('total', 0)}** "
            f"({counts.get('critical', 0)} critical, {counts.get('high', 0)} high)\n"
            f"- Verified: {len(model.verified_findings)} · exploited: {len(model.exploited_findings)}\n"
            f"- Risk score: {model.risk_score}\n"
        ),
        _code(
            "from candix.report.model import ReportModel\n"
            "from candix.report.builder import ReportBuilder\n"
            "import json\n"
            "report = json.load(open('report.json'))\n"
            "model = ReportModel.from_snapshot(report)\n"
            "model.counts"
        ),
        _markdown("## Severity distribution"),
        _code(
            "from collections import Counter\n"
            "counts = Counter(f.severity.value for f in model.findings)\n"
            "counts.most_common()"
        ),
        _markdown("## Findings by endpoint"),
        _code(
            "by_url = {}\n"
            "for finding in model.findings:\n"
            "    by_url.setdefault(finding.url, []).append(finding.title)\n"
            "sorted(by_url.items(), key=lambda item: -len(item[1]))[:10]"
        ),
    ]
    if model.chains:
        cells.append(_markdown("## Attack paths"))
        cells.append(_code("for chain in model.chains:\n    print(chain.get('name'), '→', chain.get('impact', ''))"))
    if model.findings:
        cells.append(_markdown("## Finding detail"))
        for finding in model.findings[:include_findings]:
            cells.append(_markdown(_finding_markdown(finding)))
    cells.append(_markdown("## Remediation plan"))
    cells.append(_code("model.remediation_plan()[:10]"))
    cells.append(
        _code(
            "builder = ReportBuilder(model)\n"
            "builder.write('out', formats='html,json,markdown,sarif')\n"
            "print('reports written to ./out')"
        )
    )
    return json.dumps(_notebook(cells, title=model.title), indent=1)


def _finding_markdown(finding: Any) -> str:
    lines = [f"### {finding.severity.value.upper()} — {finding.title}"]
    lines.append("")
    lines.append(f"`{finding.method} {finding.url}`")
    if finding.parameter:
        lines.append(f"parameter `{finding.parameter}` ({finding.location})")
    lines.append("")
    lines.append(finding.description)
    if finding.impact:
        lines.append("")
        lines.append(f"**Impact.** {finding.impact}")
    if finding.payload:
        lines.append("")
        lines.append("```")
        lines.append(finding.payload[:800])
        lines.append("```")
    if finding.remediation.summary:
        lines.append("")
        lines.append(f"**Fix.** {finding.remediation.summary}")
    return "\n".join(lines)


def notebook_summary(model: ReportModel) -> dict[str, Any]:
    return {
        "title": model.title,
        "scan_id": model.scan_id,
        "findings": model.counts.get("total", 0),
        "cells": 4 + min(len(model.findings), 50) + (1 if model.chains else 0) + 3,
        "format": "nbformat 4.5",
    }


def validate_notebook(payload: str | dict[str, Any]) -> list[str]:
    problems: list[str] = []
    if isinstance(payload, dict):
        document = payload
    else:
        try:
            document = json.loads(payload)
        except json.JSONDecodeError as exc:
            return [f"invalid JSON: {exc}"]
    if document.get("nbformat") != 4:
        problems.append("nbformat must be 4")
    if not isinstance(document.get("cells"), list) or not document.get("cells"):
        problems.append("notebook has no cells")
    for index, cell in enumerate(document.get("cells", [])):
        if cell.get("cell_type") not in {"markdown", "code"}:
            problems.append(f"cell {index} has an unsupported type")
        if not isinstance(cell.get("source"), list):
            problems.append(f"cell {index} source must be a list of lines")
    return problems


def merge_notebooks(notebooks: Iterable[str], *, title: str = "Combined Candix report") -> str:
    cells: list[dict[str, Any]] = [_markdown(f"# {title}")]
    for payload in notebooks:
        document = json.loads(payload)
        cells.extend(document.get("cells", []))
    return json.dumps(_notebook(cells, title=title), indent=1)
