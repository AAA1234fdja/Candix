"""JSON renderer."""

from __future__ import annotations

import json
from typing import Any

from candix.report.model import ReportModel


def render_json(model: ReportModel, *, include_evidence: bool = True, indent: int = 2) -> str:
    payload = model.to_dict(include_evidence=include_evidence)
    payload["schema"] = "https://candix.local/schema/report-v1.json"
    payload["findings_by_category"] = {
        category: [finding.id for finding in findings] for category, findings in model.by_category().items()
    }
    return json.dumps(payload, indent=indent, ensure_ascii=False, default=str)


def render_jsonl_findings(model: ReportModel) -> str:
    lines = [json.dumps(finding.to_dict(include_evidence=False), ensure_ascii=False) for finding in model.findings]
    return "\n".join(lines)


def summary_json(model: ReportModel) -> str:
    return json.dumps(model.summary(), indent=2, ensure_ascii=False)


def load_report(payload: str | dict[str, Any]) -> dict[str, Any]:
    if isinstance(payload, str):
        return json.loads(payload)
    return dict(payload)
