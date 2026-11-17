"""HTTP + subprocess client for the Go engine — now **parallel**."""

from __future__ import annotations

import concurrent.futures
import json
import subprocess
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from candix.engine_bridge.config import BridgeConfig


@dataclass
class BridgeResult:
    ok: bool
    data: dict[str, Any]
    source: str  # "go-http" | "go-subprocess" | "python-fallback" | "parallel" | "parallel-python-only" | "error"
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"ok": self.ok, "data": self.data, "source": self.source, "error": self.error}


class EngineClient:
    """Talk to the Go engine via HTTP or via the ``bridge`` CLI — **a la par** con Python."""

    def __init__(self, config: BridgeConfig | None = None) -> None:
        self.config = config or BridgeConfig()

    # ------------------------------------------------------------------ HTTP
    def health(self) -> BridgeResult:
        """GET /api/health — true if the Go server is up."""
        url = self.config.url.rstrip("/") + "/api/health"
        try:
            with urllib.request.urlopen(url, timeout=self.config.timeout) as resp:
                body = resp.read().decode("utf-8", errors="replace")
                try:
                    data = json.loads(body) if body else {}
                except json.JSONDecodeError:
                    data = {"raw": body}
                return BridgeResult(ok=True, data=data, source="go-http")
        except Exception as exc:
            return BridgeResult(ok=False, data={}, source="error", error=str(exc))

    def is_available(self) -> bool:
        return self.health().ok

    # ---------------------------------------------------------------- subprocess bridge
    def score_risk_go(self, tool: str, tool_input: dict[str, Any]) -> BridgeResult:
        """Call Go's intercept.ScoreRisk via subprocess.

        Uses ``engine/cmd/bridge`` CLI so no HTTP/DB is required.
        """
        payload = json.dumps({"tool": tool, "input": tool_input}, ensure_ascii=False)
        return self._run_bridge("score-risk", payload)

    def normalize_target_go(self, raw: str) -> BridgeResult:
        payload = json.dumps({"raw": raw}, ensure_ascii=False)
        return self._run_bridge("normalize-target", payload)

    def _run_bridge(self, command: str, payload: str) -> BridgeResult:
        if not self.config.use_subprocess:
            return BridgeResult(ok=False, data={}, source="error", error="subprocess disabled")
        engine_root = self.config.engine_root()
        bridge_bin = Path(self.config.bridge_bin) if self.config.bridge_bin else None
        # Prefer explicit binary, then go run source
        cmd: list[str]
        cwd = str(engine_root.parent)
        if bridge_bin and bridge_bin.exists():
            cmd = [str(bridge_bin), command, payload]
        else:
            # go run ./engine/cmd/bridge -- requires Go toolchain
            if not self.config.has_go_toolchain():
                return BridgeResult(ok=False, data={}, source="error", error="go toolchain not found")
            bridge_pkg = "./engine/cmd/bridge"
            # ensure source exists
            if not (engine_root / "cmd" / "bridge" / "main.go").exists():
                return BridgeResult(ok=False, data={}, source="error", error="bridge source not found")
            cmd = ["go", "run", bridge_pkg, command, payload]
        try:
            proc = subprocess.run(
                cmd,
                cwd=cwd,
                capture_output=True,
                text=True,
                timeout=self.config.timeout + 1.0,
            )
            if proc.returncode != 0:
                return BridgeResult(ok=False, data={}, source="error", error=proc.stderr.strip() or f"exit {proc.returncode}")
            try:
                data = json.loads(proc.stdout) if proc.stdout.strip() else {}
            except json.JSONDecodeError as exc:
                return BridgeResult(ok=False, data={"raw": proc.stdout}, source="error", error=f"bad json: {exc}")
            return BridgeResult(ok=True, data=data, source="go-subprocess")
        except subprocess.TimeoutExpired as exc:
            return BridgeResult(ok=False, data={}, source="error", error=f"timeout: {exc}")
        except Exception as exc:
            return BridgeResult(ok=False, data={}, source="error", error=str(exc))

    # ---------------------------------------------------------------- high-level — PARALLEL
    def _python_score(self, tool: str, tool_input: dict[str, Any]) -> Any:
        from candix.agent import intercept as py_intercept

        return py_intercept.score_tool(tool, tool_input)

    def _python_normalize(self, raw: str) -> Any | None:
        from candix.agent import intercept as py_intercept

        return py_intercept.normalise_target(raw)  # type: ignore

    def score_risk(self, tool: str, tool_input: dict[str, Any]) -> BridgeResult:
        """Score risk **en paralelo** Python + Go, reconciliado fail-safe.

        - Si ``enabled=False``: solo Python (CI/air-gapped)
        - Si ``enabled=True`` y ``parallel=True``: ambos motores corren concurrentes,
          ``score=max(py, go)``, razones unidas, discrepancias reportadas
        - Si ``enabled=True`` y ``parallel=False``: legado Go-preferente con fallback
        """
        # Python report always available synchronously (fast)
        try:
            py_report = self._python_score(tool, tool_input)
        except Exception as exc:
            return BridgeResult(ok=False, data={}, source="error", error=str(exc))

        # Python-only path — shape uniforme para que proxy no tenga python=None
        if not self.config.enabled:
            return BridgeResult(
                ok=True,
                data={
                    "score": py_report.score,
                    "level": py_report.level,
                    "reasons": py_report.reasons,
                    "python": {"score": py_report.score, "level": py_report.level, "reasons": py_report.reasons},
                    "go": None,
                    "go_error": "disabled",
                    "discrepancy": None,
                    "consensus": "python-only",
                },
                source="python-fallback",
            )

        # Parallel path: run Go concurrently, Python already done
        if self.config.parallel:
            # Use thread to not block; Go via subprocess is IO-bound
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                fut = pool.submit(self.score_risk_go, tool, tool_input)
                try:
                    go_result = fut.result(timeout=self.config.timeout + 1.5)
                except concurrent.futures.TimeoutError:
                    go_result = BridgeResult(ok=False, data={}, source="error", error="go timeout")
                except Exception as exc:
                    go_result = BridgeResult(ok=False, data={}, source="error", error=str(exc))
            # reconcile
            from candix.engine_bridge.reconcile import merge_risk

            return merge_risk(py_report, go_result)

        # Legacy Go-preferente (parallel=False)
        go_result = self.score_risk_go(tool, tool_input)
        if go_result.ok:
            return go_result
        # fallback to Python (legado)
        return BridgeResult(
            ok=True,
            data={
                "score": py_report.score,
                "level": py_report.level,
                "reasons": py_report.reasons,
                "python": {"score": py_report.score, "level": py_report.level, "reasons": py_report.reasons},
                "go": None,
                "go_error": go_result.error if 'go_result' in locals() else "unavailable",
                "consensus": "python-fallback",
            },
            source="python-fallback",
        )

    def normalize_target(self, raw: str) -> BridgeResult:
        """Normalise target **en paralelo** Python + Go."""
        py_target = None
        try:
            py_target = self._python_normalize(raw)
        except Exception:
            py_target = None

        if not self.config.enabled:
            if py_target is None:
                return BridgeResult(ok=False, data={}, source="python-fallback", error="unparseable")
            d = py_target.to_dict()
            return BridgeResult(ok=True, data={**d, "python": d, "go": None, "consensus": "python-only"}, source="python-fallback")

        if self.config.parallel:
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                fut = pool.submit(self.normalize_target_go, raw)
                try:
                    go_result = fut.result(timeout=self.config.timeout + 1.5)
                except Exception as exc:
                    go_result = BridgeResult(ok=False, data={}, source="error", error=str(exc))
            from candix.engine_bridge.reconcile import merge_targets

            return merge_targets(py_target, go_result)

        # legacy
        go_result = self.normalize_target_go(raw)
        if go_result.ok:
            return go_result
        if py_target is None:
            return BridgeResult(ok=False, data={}, source="python-fallback", error="unparseable")
        return BridgeResult(ok=True, data=py_target.to_dict(), source="python-fallback")
