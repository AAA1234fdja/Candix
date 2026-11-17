import json

import pytest

from candix.report.builder import DEFAULT_FORMATS, parse_formats
from candix.report.junit import junit_summary, parse_junit, render_junit
from candix.report.markdown import render_markdown
from candix.report.model import ReportModel
from candix.report.notebook import render_notebook, validate_notebook
from candix.report.slides import render_slides, slide_count


def snapshot():
    return {
        "summary": {"title": "unit", "scan_id": "unit-1", "duration_seconds": 1.0, "profile": "safe", "targets": ["http://a"]},
        "findings": [
            {
                "id": "CDX-1",
                "title": "OS command injection",
                "severity": "critical",
                "score": 9.8,
                "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "detector": "rce",
                "category": "rce",
                "url": "http://a/ping",
                "method": "GET",
                "description": "marker echoed",
                "impact": "code execution",
                "verified": True,
            },
            {
                "id": "CDX-2",
                "title": "Missing headers",
                "severity": "low",
                "detector": "headers",
                "category": "headers",
                "url": "http://a/",
                "method": "GET",
                "description": "no CSP",
                "impact": "defence in depth",
            },
        ],
    }


def model():
    return ReportModel.from_snapshot(snapshot())


def test_formats_parse():
    assert parse_formats("json,html") == ["json", "html"]
    assert set(parse_formats("junit")) <= set(DEFAULT_FORMATS) | {"junit"}


def test_junit_roundtrip():
    xml = render_junit(model(), fail_on="high")
    summary = junit_summary(model(), fail_on="high")
    assert summary["failures"] == 1
    assert summary["exit_code"] == 1
    parsed = parse_junit(xml)
    assert parsed["tests"] == 2


def test_notebook_and_slides():
    notebook = json.loads(render_notebook(model()))
    assert validate_notebook(notebook) == []
    assert slide_count(render_slides(model())) >= 3


def test_markdown_is_complete():
    text = render_markdown(model())
    assert text.startswith("# unit")
    assert "Findings overview" in text
    assert text.count("## ") >= 4
