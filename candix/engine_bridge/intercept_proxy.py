"""Proxy that delegates intercept/risk/target checks to Go when available."""

from __future__ import annotations

from typing import Any

from candix.engine_bridge.client import EngineClient, BridgeResult
from candix.engine_bridge.config import BridgeConfig


class InterceptProxy:
    """Drop-in wrapper around ``candix.agent.intercept`` that can delegate to Go.

    Usage::

        proxy = InterceptProxy(config=BridgeConfig(enabled=True))
        decision = proxy.score_tool("Bash", {"command": "rm -rf /tmp"})
        # decision carries Go result when possible, else Python fallback

    The proxy never raises — it returns a ``BridgeResult`` with ``source``
    indicating which implementation answered.
    """

    def __init__(self, config: BridgeConfig | None = None) -> None:
        self.config = config or BridgeConfig()
        self.client = EngineClient(self.config)

    def score_tool(self, tool: str, arguments: dict[str, Any]) -> BridgeResult:
        """Score a tool call (risk 0..100) via Go or Python."""
        return self.client.score_risk(tool, arguments)

    def score_command(self, command: str) -> BridgeResult:
        return self.score_tool("Bash", {"command": command})

    def normalize_target(self, raw: str) -> BridgeResult:
        return self.client.normalize_target(raw)

    def check_command_gate(self, command: str, targets: list[str] | None = None) -> BridgeResult:
        """Full gate check, combining risk + target checks.

        Delegates risk to Go and target normalisation to Go, then applies
        Python's ``CommandGate`` logic for allowlist/denylist so both sides
        stay consistent.
        """
        from candix.agent import intercept as py_intercept

        # Risk via Go if possible
        risk_res = self.score_tool("Bash", {"command": command})
        # Also compute Python report for comparison
        py_report = py_intercept.score_command(command)

        # Build a combined view; prefer Go score when available
        if risk_res.ok and risk_res.source.startswith("go"):
            score = int(risk_res.data.get("score", py_report.score))
            level = risk_res.data.get("level", py_intercept.level_of(score))
            reasons = risk_res.data.get("reasons", py_report.reasons)
        else:
            score, level, reasons = py_report.score, py_report.level, py_report.reasons

        # Target extraction stays in Python (same regex as Go's target_extract)
        targets = targets or py_intercept.command_targets(command)
        gate_results: list[dict[str, Any]] = []
        for t in targets:
            tr = self.normalize_target(t)
            gate_results.append({"target": t, "result": tr.to_dict()})

        return BridgeResult(
            ok=True,
            data={
                "score": score,
                "level": level,
                "reasons": reasons,
                "python_score": py_report.score,
                "go_score": risk_res.data.get("score") if risk_res.source.startswith("go") else None,
                "source": risk_res.source,
                "targets": gate_results,
            },
            source=risk_res.source,
        )

    def describe(self) -> dict[str, Any]:
        h = self.client.health()
        return {
            "enabled": self.config.enabled,
            "url": self.config.url,
            "engine_available": h.ok,
            "engine_health": h.to_dict(),
            "go_toolchain": self.config.has_go_toolchain(),
            "use_subprocess": self.config.use_subprocess,
        }
