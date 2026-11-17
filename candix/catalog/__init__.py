"""Static knowledge used by detectors, exploitation and reporting.

The catalogues are plain Python data so the harness stays importable on an
air-gapped host: no YAML parsing, no network lookups, no version skew.
"""

from __future__ import annotations

from candix.catalog.payloads import PAYLOADS, get_payloads, render_payload
from candix.catalog.remediation import REMEDIATION, remediation_for

__all__ = ["PAYLOADS", "REMEDIATION", "get_payloads", "remediation_for", "render_payload"]
