"""Helper to optionally launch the Go engine server."""

from __future__ import annotations

import subprocess
import time
import urllib.request
from pathlib import Path

from candix.engine_bridge.config import BridgeConfig


class EngineLauncher:
    def __init__(self, config: BridgeConfig | None = None) -> None:
        self.config = config or BridgeConfig()
        self._proc: subprocess.Popen | None = None

    def is_running(self) -> bool:
        import urllib.error

        url = self.config.url.rstrip("/") + "/api/health"
        try:
            with urllib.request.urlopen(url, timeout=1.0) as r:
                return 200 <= r.status < 300
        except Exception:
            return False

    def start(self) -> bool:
        """Start ``go run ./engine/cmd/candix`` if not running.

        Returns True if health becomes reachable within 10s.
        Requires Go toolchain and no existing listener on the port.
        """
        if self.is_running():
            return True
        if not self.config.has_go_toolchain():
            return False
        engine_root = self.config.engine_root()
        if not (engine_root / "cmd" / "candix" / "main.go").exists():
            return False
        cmd = ["go", "run", "./engine/cmd/candix", "-addr", self.config.url.replace("http://", "").replace("https://", "")]
        try:
            self._proc = subprocess.Popen(
                cmd,
                cwd=str(engine_root.parent),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            # wait up to 10s for health
            for _ in range(20):
                time.sleep(0.5)
                if self.is_running():
                    return True
                if self._proc.poll() is not None:
                    return False
            return self.is_running()
        except Exception:
            return False

    def stop(self) -> None:
        if self._proc and self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self._proc.kill()
