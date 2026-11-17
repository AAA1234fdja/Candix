"""HTTP + subprocess client for the Go engine."""

from __future__ import annotations

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
    source: str  # "go-http" | "go-subprocess" | "python-fallback" | "error"
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"ok": self.ok, "data": self.data, "source": self.source, "error": self.error}


class EngineClient:
    """Talk to the Go engine via HTTP or via the ``bridge`` CLI."""

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

    # ---------------------------------------------------------------- high-level
    def score_risk(self, tool: str, tool_input: dict[str, Any]) -> BridgeResult:
        """Score risk, preferring Go and falling back to Python."""
        # Try HTTP health first if enabled
        if self.config.enabled:
            # For now HTTP does not expose ScoreRisk directly, so use subprocess path
            # but we still check health to report source
            h = self.health()
            if h.ok:
                # If server is up we could add a dedicated endpoint later;
                # for now delegate to subprocess which is always correct
                pass
        # Try Go subprocess
        if self.config.use_subprocess:
            go_result = self.score_risk_go(tool, tool_input)
            if go_result.ok:
                return go_result
        # Fallback to Python re-implementation
        try:
            from candix.agent import intercept as py_intercept

            report = py_intercept.score_tool(tool, tool_input)
            return BridgeResult(
                ok=True,
                data={"score": report.score, "level": report.level, "reasons": report.reasons},
                source="python-fallback",
            )
        except Exception as exc:
            return BridgeResult(ok=False, data={}, source="error", error=str(exc))

    def normalize_target(self, raw: str) -> BridgeResult:
        if self.config.use_subprocess:
            go_result = self.normalize_target_go(raw)
            if go_result.ok:
                return go_result
        # Python fallback
        try:
            from candix.agent import intercept as py_intercept

            target = py_intercept.normalise_target(raw)  # type: ignore
            if target is None:
                return BridgeResult(ok=False, data={}, source="python-fallback", error="unparseable")
            return BridgeResult(ok=True, data=target.to_dict(), source="python-fallback")
        except Exception as exc:
            return BridgeResult(ok=False, data={}, source="error", error=str(exc))
