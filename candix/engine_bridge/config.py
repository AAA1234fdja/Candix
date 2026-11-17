"""Configuration for the Go engine bridge."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class BridgeConfig:
    """How Candix connects to the Go engine — **interconectado a la par**.

    Python y Go corren en paralelo, no uno delegando al otro. Cada veredicto
    (risk/target) se calcula en ambos motores simultáneamente y se reconcilia:
    ``score = max(python, go)`` con razones unidas; discrepancias se marcan
    para auditoría pero el resultado es siempre fail-safe.

    Attributes:
        enabled: si False, solo Python (CI/air-gapped). Si True, Python+Go en
            paralelo vía HTTP o subprocess con reconciliación.
        parallel: cuando enabled, ejecutar ambos y reconciliar (True = interconectado,
            False = legado Go-preferente)
        url: HTTP base del engine Go (``http://127.0.0.1:8787``)
        timeout: timeout HTTP y subprocess en segundos
        use_subprocess: fallback a ``go run ./engine/cmd/bridge`` sin HTTP/DB
        bridge_bin: binario bridge precompilado (opcional)
        auto_start: intentar lanzar engine si no responde
    """

    enabled: bool = False
    parallel: bool = True
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

    @classmethod
    def from_env(cls) -> "BridgeConfig":
        """Create config honoring CANDIX_ENGINE_* env vars."""
        import os

        cfg = cls()
        if os.environ.get("CANDIX_ENGINE_URL"):
            cfg.url = os.environ["CANDIX_ENGINE_URL"]
            cfg.enabled = True
        val = os.environ.get("CANDIX_ENGINE_ENABLED", "").lower()
        if val in {"1", "true", "yes", "on"}:
            cfg.enabled = True
        if val in {"0", "false", "no", "off"}:
            cfg.enabled = False
        pval = os.environ.get("CANDIX_ENGINE_PARALLEL", "").lower()
        if pval in {"1", "true", "yes", "on"}:
            cfg.parallel = True
        if pval in {"0", "false", "no", "off"}:
            cfg.parallel = False
        return cfg
