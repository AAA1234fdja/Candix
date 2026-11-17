from __future__ import annotations

import concurrent.futures
from typing import Any, Iterable

from candix.engine_bridge.client import EngineClient, BridgeResult
from candix.engine_bridge.config import BridgeConfig


class InterceptProxy:
    def __init__(self, config: BridgeConfig | None = None) -> None:
        self.config = config or BridgeConfig()
        self.client = EngineClient(self.config)

    def score_tool(self, tool: str, arguments: dict[str, Any]) -> BridgeResult:
        return self.client.score_risk(tool, arguments)

    def score_command(self, command: str) -> BridgeResult:
        return self.score_tool("Bash", {"command": command})

    def normalize_target(self, raw: str) -> BridgeResult:
        return self.client.normalize_target(raw)

    def check_command_gate(
        self,
        command: str,
        *,
        targets: Iterable[str] | None = None,
        allowed_prefixes: Iterable[str] = (),
        max_risk: int = 70,
    ) -> Any:
        from candix.agent import intercept as py_intercept

        gate = py_intercept.CommandGate(
            allowed_prefixes=tuple(allowed_prefixes),
            max_risk=max_risk,
            targets=tuple(targets) if targets else (),
        )
        risk_res = self.score_tool("Bash", {"command": command})
        risk_data = risk_res.data if risk_res.ok else {}
        merged_score = int(risk_data.get("score", 0) or 0)
        merged_level = risk_data.get("level", py_intercept.level_of(merged_score))
        merged_reasons = risk_data.get("reasons", [])
        target_list = list(targets) if targets is not None else py_intercept.command_targets(command)
        gate_results: list[dict[str, Any]] = []
        if target_list:
            with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, len(target_list))) as pool:
                futs = {pool.submit(self.normalize_target, t): t for t in target_list}
                for fut, t in futs.items():
                    try:
                        tr = fut.result(timeout=self.config.timeout + 2.0)
                    except Exception as exc:
                        tr = BridgeResult(ok=False, data={}, source="error", error=str(exc))
                    gate_results.append({"target": t, "result": tr.to_dict()})
        python_decision = gate.check(command, targets=targets or ())
        risk_obj = py_intercept.RiskReport(merged_score, level=merged_level, reasons=list(merged_reasons))
        py_sensitive = any(r.get("result", {}).get("data", {}).get("fail_safe") for r in gate_results)
        if python_decision.allowed:
            if merged_score >= max_risk:
                blocked = py_intercept.Decision(False, f"risk {merged_score} at or above {max_risk} (dual)", "risk", risk_obj)
                blocked_data: dict[str, Any] = {
                    "score": merged_score,
                    "level": merged_level,
                    "reasons": merged_reasons,
                    "python": risk_data.get("python"),
                    "go": risk_data.get("go"),
                    "go_error": risk_data.get("go_error", ""),
                    "discrepancy": risk_data.get("discrepancy"),
                    "consensus": risk_data.get("consensus"),
                    "source": risk_res.source,
                    "targets": gate_results,
                    "fail_safe_sensitive": py_sensitive,
                }
                blocked.risk = risk_obj  # type: ignore
                return _attach(blocked, blocked_data, risk_res)
            for td in target_list:
                norm = next((g for g in gate_results if g["target"] == td), None)
                if norm and norm.get("result", {}).get("data", {}).get("fail_safe"):
                    blocked = py_intercept.Decision(False, f"{td} is sensitive (dual)", "target", risk_obj)
                    blocked_data = {
                        "score": merged_score,
                        "level": merged_level,
                        "reasons": merged_reasons,
                        "python": risk_data.get("python"),
                        "go": risk_data.get("go"),
                        "go_error": risk_data.get("go_error", ""),
                        "discrepancy": risk_data.get("discrepancy"),
                        "consensus": risk_data.get("consensus"),
                        "source": risk_res.source,
                        "targets": gate_results,
                        "fail_safe_sensitive": True,
                    }
                    return _attach(blocked, blocked_data, risk_res)
        data: dict[str, Any] = {
            "score": merged_score,
            "level": merged_level,
            "reasons": merged_reasons,
            "python": risk_data.get("python"),
            "go": risk_data.get("go"),
            "go_error": risk_data.get("go_error", ""),
            "discrepancy": risk_data.get("discrepancy"),
            "consensus": risk_data.get("consensus"),
            "source": risk_res.source,
            "targets": gate_results,
            "fail_safe_sensitive": py_sensitive,
        }
        if not python_decision.allowed:
            python_decision.risk = risk_obj  # type: ignore
            return _attach(python_decision, data, risk_res)
        allowed = py_intercept.Decision(True, python_decision.reason, python_decision.rule, risk_obj, python_decision.prefix)
        return _attach(allowed, data, risk_res)

    def describe(self) -> dict[str, Any]:
        h = self.client.health()
        return {
            "enabled": self.config.enabled,
            "parallel": self.config.parallel,
            "url": self.config.url,
            "engine_available": h.ok,
            "engine_health": h.to_dict(),
            "go_toolchain": self.config.has_go_toolchain(),
            "use_subprocess": self.config.use_subprocess,
            "mode": "parallel" if (self.config.enabled and self.config.parallel) else ("go-preferente" if self.config.enabled else "python-only"),
        }


def _attach(decision: Any, data: dict[str, Any], res: BridgeResult) -> Any:
    decision.dual = data  # type: ignore
    decision.bridge_result = res  # type: ignore
    return decision
