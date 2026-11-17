from __future__ import annotations

import ipaddress
from typing import Any

from candix.engine_bridge.client import BridgeResult


def level_of(score: int) -> str:
    if score >= 70:
        return "high"
    if score >= 30:
        return "medium"
    return "low"


def merge_risk(python_report: Any, go_result: BridgeResult | None) -> BridgeResult:
    py_score = int(getattr(python_report, "score", 0) or 0)
    py_level = getattr(python_report, "level", level_of(py_score)) or level_of(py_score)
    py_reasons: list[str] = list(getattr(python_report, "reasons", []) or [])
    if go_result is None or not go_result.ok:
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
    seen: set[str] = set()
    merged_reasons: list[str] = []
    for r in py_reasons + go_reasons:
        if r not in seen:
            seen.add(r)
            merged_reasons.append(r)
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


def _is_sensitive_target(d: dict[str, Any] | None) -> bool:
    if not d:
        return False
    host = str(d.get("host", "")).lower()
    kind = d.get("kind", "")
    if host in {"metadata.google.internal", "metadata", "instance-data"}:
        return True
    if kind == "ip":
        try:
            ip = ipaddress.ip_address(host)
            if ip == ipaddress.ip_address("169.254.169.254") or ip == ipaddress.ip_address("fd00:ec2::254"):
                return True
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
                return True
        except ValueError:
            pass
    return False


def merge_targets(python_target: Any | None, go_result: BridgeResult | None) -> BridgeResult:
    py_dict: dict[str, Any] | None = None
    if python_target is not None:
        try:
            py_dict = python_target.to_dict()  # type: ignore
        except Exception:
            py_dict = {"kind": getattr(python_target, "kind", "?"), "host": getattr(python_target, "host", ""), "port": getattr(python_target, "port", 0)}
    if go_result is None or not go_result.ok:
        base: dict[str, Any] = dict(py_dict) if isinstance(py_dict, dict) else {}
        base.update({"python": py_dict, "go": None, "consensus": "python-only", "fail_safe": _is_sensitive_target(py_dict)})
        return BridgeResult(ok=py_dict is not None, data=base, source="parallel-python-only")
    go_data = go_result.data
    go_target = go_data.get("target", go_data) if isinstance(go_data, dict) else go_data
    py_host = (py_dict or {}).get("host", "") if isinstance(py_dict, dict) else ""
    go_host = go_target.get("host", "") if isinstance(go_target, dict) else ""
    agree = bool(py_host and go_host and py_host.lower() == go_host.lower())
    py_sensitive = _is_sensitive_target(py_dict)
    go_sensitive = _is_sensitive_target(go_target if isinstance(go_target, dict) else None)
    fail_safe_host = py_dict if py_sensitive else (go_target if go_sensitive else py_dict or go_target)
    if isinstance(fail_safe_host, dict):
        merged = dict(fail_safe_host)
    else:
        merged = {}
        if isinstance(py_dict, dict):
            merged = dict(py_dict)
        elif isinstance(go_target, dict):
            merged = dict(go_target)
    discrepancy = None
    if not agree and py_host and go_host:
        discrepancy = {"python_host": py_host, "go_host": go_host, "fail_safe": "most_restrictive"}
    consensus = "agree" if agree else "disagree"
    if py_sensitive or go_sensitive:
        consensus = "fail_safe_sensitive"
    merged.update(
        {
            "python": py_dict,
            "go": go_target,
            "consensus": consensus,
            "discrepancy": discrepancy,
            "fail_safe": py_sensitive or go_sensitive,
            "merged": fail_safe_host,
        }
    )
    return BridgeResult(ok=True, data=merged, source="parallel")
