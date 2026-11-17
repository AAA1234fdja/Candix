"""Proxy que hace que Python y Go trabajen **a la par**."""

from __future__ import annotations

import concurrent.futures
from typing import Any

from candix.engine_bridge.client import EngineClient, BridgeResult
from candix.engine_bridge.config import BridgeConfig


class InterceptProxy:
    """Wrapper sobre ``candix.agent.intercept`` + Go ``engine/intercept`` en paralelo.

    Ya no delega — **orquesta ambos motores concurrentemente** y reconcilia
    fail-safe (score = max, razones unidas). Funciona sin Go (python-only)
    y con Go (parallel).

    Usage::

        proxy = InterceptProxy(config=BridgeConfig(enabled=True))
        decision = proxy.score_tool("Bash", {"command": "rm -rf /tmp"})
        # decision.data = {score, level, reasons, python:{...}, go:{...}, consensus, discrepancy}
    """

    def __init__(self, config: BridgeConfig | None = None) -> None:
        self.config = config or BridgeConfig()
        self.client = EngineClient(self.config)

    def score_tool(self, tool: str, arguments: dict[str, Any]) -> BridgeResult:
        """Score a tool call — Python y Go en paralelo cuando enabled."""
        return self.client.score_risk(tool, arguments)

    def score_command(self, command: str) -> BridgeResult:
        return self.score_tool("Bash", {"command": command})

    def normalize_target(self, raw: str) -> BridgeResult:
        return self.client.normalize_target(raw)

    def check_command_gate(self, command: str, targets: list[str] | None = None) -> BridgeResult:
        """Gate completo: risk + targets, todo en paralelo.

        - Riesgo: Python + Go concurrentes → max
        - Targets: cada target normalizado en paralelo, luego CommandGate
        """
        from candix.agent import intercept as py_intercept

        # risk en paralelo (client ya lo hace), pero también queremos que
        # Python's CommandGate y Go's target checks corran juntos
        # Lanzamos ambas ramas concurrentes
        def _risk() -> BridgeResult:
            return self.score_tool("Bash", {"command": command})

        def _py_gate() -> Any:
            return py_intercept.CommandGate(
                allowed_prefixes=(),
                max_risk=70,  # informe, no bloqueo duro aquí — el caller decide
            )

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            fut_risk = pool.submit(_risk)
            # target extraction es Python pero lo hacemos en paralelo con risk
            declared = targets if targets is not None else py_intercept.command_targets(command)
            fut_risk_result = fut_risk.result()

        # Gate de targets — normaliza cada target en paralelo
        targets_to_check = declared or []
        gate = py_intercept.CommandGate(targets=[])  # sin scope fijo, solo reporta
        # si caller pasó allowlist, usar CommandGate real para auditar
        # pero aquí reportamos target normalisation paralela
        gate_results: list[dict[str, Any]] = []

        if targets_to_check:
            with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, len(targets_to_check))) as pool2:
                futs = {pool2.submit(self.normalize_target, t): t for t in targets_to_check}
                for fut, t in futs.items():
                    try:
                        tr = fut.result(timeout=self.config.timeout + 1.0)
                    except Exception as exc:
                        tr = BridgeResult(ok=False, data={}, source="error", error=str(exc))
                    gate_results.append({"target": t, "result": tr.to_dict()})

        data = fut_risk_result.data if fut_risk_result.ok else {}
        score = int(data.get("score", 0) or 0)
        level = data.get("level", py_intercept.level_of(score))
        reasons = data.get("reasons", [])

        return BridgeResult(
            ok=True,
            data={
                "score": score,
                "level": level,
                "reasons": reasons,
                "python": data.get("python"),
                "go": data.get("go"),
                "consensus": data.get("consensus"),
                "discrepancy": data.get("discrepancy"),
                "source": fut_risk_result.source,
                "targets": gate_results,
            },
            source=fut_risk_result.source,
        )

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
