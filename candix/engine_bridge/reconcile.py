"""Reconciliation for the dual-engine (Python + Go) running in parallel."""

from __future__ import annotations

from typing import Any

from candix.engine_bridge.client import BridgeResult


def level_of(score: int) -> str:
    if score >= 70:
        return "high"
    if score >= 30:
        return "medium"
    return "low"


def merge_risk(
    python_report: Any,
    go_result: BridgeResult | None,
) -> BridgeResult:
    """Merge Python RiskReport and Go BridgeResult in parallel.

    Rules:
    - score = max(python, go) — the most conservative wins (fail-safe)
    - level derived from merged score
    - reasons = union (preserving order, deduped)
    - discrepancies flagged when scores differ >10 or levels differ
    """
    py_score = int(getattr(python_report, "score", 0) or 0)
    py_level = getattr(python_report, "level", level_of(py_score)) or level_of(py_score)
    py_reasons: list[str] = list(getattr(python_report, "reasons", []) or [])

    if go_result is None or not go_result.ok:
        # Python-only path but report both sides for audit
        data: dict[str, Any] = {
            "score": py_score,
            "level": py_level,
            "reasons": py_reasons,
            "python": {"score": py_score, "level": py_level, "reasons": py_reasons},
            "go": None,
            "go_error": go_result.error if go_result else "unavailable",
            "discrepancy": None,
            "consensus": "python-only",
        }
        return BridgeResult(ok=True, data=data, source="parallel-python-only")

    go_score = int(go_result.data.get("score", py_score) or py_score)
    go_level = go_result.data.get("level", level_of(go_score)) or level_of(go_score)
    go_reasons: list[str] = list(go_result.data.get("reasons", []) or [])

    merged_score = max(py_score, go_score)
    merged_level = level_of(merged_score)

    # union reasons preserving Python first, then Go extras
    seen: set[str] = set()
    merged_reasons: list[str] = []
    for r in py_reasons + go_reasons:
        if r not in seen:
            seen.add(r)
            merged_reasons.append(r)

    # discrepancy detection
    discrepancy: dict[str, Any] | None = None
    score_diff = abs(py_score - go_score)
    if score_diff > 10 or py_level != go_level:
        discrepancy = {
            "python_score": py_score,
            "go_score": go_score,
            "python_level": py_level,
            "go_level": go_level,
            "score_diff": score_diff,
            "note": "engines disagree — merged takes max (fail-safe)",
        }

    consensus = "agree" if discrepancy is None else "disagree-merged-max"

    data2: dict[str, Any] = {
        "score": merged_score,
        "level": merged_level,
        "reasons": merged_reasons,
        "python": {"score": py_score, "level": py_level, "reasons": py_reasons},
        "go": {"score": go_score, "level": go_level, "reasons": go_reasons},
        "go_error": "",
        "discrepancy": discrepancy,
        "consensus": consensus,
    }
    return BridgeResult(ok=True, data=data2, source="parallel")


def merge_targets(
    python_target: Any | None,
    go_result: BridgeResult | None,
) -> BridgeResult:
    """Merge target normalisation results (Python Target + Go)."""
    py_dict: dict[str, Any] | None = None
    if python_target is not None:
        try:
            py_dict = python_target.to_dict()  # type: ignore
        except Exception:
            py_dict = {"kind": getattr(python_target, "kind", "?"), "host": getattr(python_target, "host", ""), "port": getattr(python_target, "port", 0)}

    if go_result is None or not go_result.ok:
        # keep top-level host/port for callers that expect merged keys
        base: dict[str, Any] = dict(py_dict) if isinstance(py_dict, dict) else {}
        base.update({"python": py_dict, "go": None, "consensus": "python-only"})
        return BridgeResult(ok=py_dict is not None, data=base, source="parallel-python-only")

    go_data = go_result.data
    # Go bridge returns {ok, target} or direct target
    go_target = go_data.get("target", go_data) if isinstance(go_data, dict) else go_data

    # simple consensus: hosts must match (case-insensitive)
    py_host = (py_dict or {}).get("host", "") if isinstance(py_dict, dict) else ""
    go_host = go_target.get("host", "") if isinstance(go_target, dict) else ""
    agree = bool(py_host and go_host and py_host.lower() == go_host.lower())

    merged = dict(py_dict) if isinstance(py_dict, dict) else (dict(go_target) if isinstance(go_target, dict) else {})
    merged.update({"python": py_dict, "go": go_target, "consensus": "agree" if agree else "disagree", "merged": py_dict or go_target})
    return BridgeResult(ok=True, data=merged, source="parallel")
