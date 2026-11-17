"""Report generation: JSON, SARIF, Markdown, CSV and a self-contained HTML deliverable."""

from __future__ import annotations

from candix.report.builder import ReportBuilder, build_report
from candix.report.model import ReportModel

__all__ = ["ReportBuilder", "ReportModel", "build_report"]
