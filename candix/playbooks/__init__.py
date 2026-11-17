"""Curated playbooks that turn a finding into a sequence of next steps."""

from __future__ import annotations

from candix.playbooks.catalog import PLAYBOOKS, playbook, playbook_ids, playbooks_by_category
from candix.playbooks.engine import (
    PlaybookMatch,
    for_finding,
    for_report,
    render_playbook_markdown,
    render_report_playbooks,
    summarize_matches,
)

__all__ = [
    "PLAYBOOKS",
    "PlaybookMatch",
    "playbook",
    "playbook_ids",
    "playbooks_by_category",
    "for_finding",
    "for_report",
    "render_playbook_markdown",
    "render_report_playbooks",
    "summarize_matches",
]
