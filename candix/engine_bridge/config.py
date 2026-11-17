"""Configuration for the Go engine bridge."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class BridgeConfig:
    """How Candix connects to the Go engine.

    The bridge is *opt-in* — default ``enabled=False`` keeps the pure-Python
    path for CI/air-gapped hosts. Set ``enabled=True`` and/or
    ``CANDIX_ENGINE_URL`` to delegate to Go.

    Attributes:
        enabled: try Go first, fall back to Python on error
        url: HTTP base of a running engine (``http://127.0.0.1:8787``)
        timeout: HTTP timeout in seconds
        use_subprocess: if HTTP is unavailable, try ``go run ./engine/cmd/bridge``
        bridge_bin: explicit path to built ``bridge`` binary (``./engine/cmd/bridge``)
        auto_start: try to start engine via ``engine/cmd/candix`` if not reachable
    """

    enabled: bool = False
    url: str = "http://127.0.0.1:8787"
    timeout: float = 2.0
    use_subprocess: bool = True
    bridge_bin: str = ""
    auto_start: bool = False
    extra_env: dict[str, str] = field(default_factory=dict)

    def engine_root(self) -> Path:
        # repo root is two levels above candix/engine_bridge
        return Path(__file__).resolve().parents[2] / "engine"

    def bridge_source(self) -> Path:
        return self.engine_root() / "cmd" / "bridge" / "main.go"

    def has_go_toolchain(self) -> bool:
        import shutil

        return shutil.which("go") is not None
