from __future__ import annotations

import os
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class BridgeConfig:
    enabled: bool = False
    parallel: bool = True
    url: str = "http://127.0.0.1:8787"
    timeout: float = 4.0
    use_subprocess: bool = True
    bridge_bin: str = ""
    auto_start: bool = False
    extra_env: dict[str, str] = field(default_factory=dict)

    def engine_root(self) -> Path:
        return Path(__file__).resolve().parents[2] / "engine"

    def bridge_source(self) -> Path:
        return self.engine_root() / "cmd" / "bridge" / "main.go"

    def has_go_toolchain(self) -> bool:
        return shutil.which("go") is not None

    def cache_dir(self) -> Path:
        return Path(os.environ.get("CANDIX_CACHE_DIR", "")) or (self.engine_root().parent / ".cache")

    def bridge_bin_path(self) -> Path | None:
        if self.bridge_bin:
            p = Path(self.bridge_bin)
            if p.exists():
                return p
        cached = self.cache_dir() / "candix-bridge"
        if cached.exists():
            return cached
        local = self.engine_root() / "bin" / "bridge"
        if local.exists():
            return local
        return None

    def ensure_bridge_bin(self) -> Path | None:
        existing = self.bridge_bin_path()
        if existing is not None:
            return existing
        if not self.use_subprocess or not self.has_go_toolchain():
            return None
        if not self.bridge_source().exists():
            return None
        out = self.cache_dir() / "candix-bridge"
        out.parent.mkdir(parents=True, exist_ok=True)
        tmp = out.with_suffix(".tmp")
        try:
            proc = subprocess.run(
                ["go", "build", "-o", str(tmp), "./engine/cmd/bridge"],
                cwd=str(self.engine_root().parent),
                capture_output=True,
                text=True,
                timeout=30.0,
            )
            if proc.returncode != 0:
                return None
            tmp.replace(out)
            try:
                out.chmod(0o755)
            except OSError:
                pass
            return out
        except Exception:
            return None

    @classmethod
    def from_env(cls) -> "BridgeConfig":
        cfg = cls()
        if os.environ.get("CANDIX_ENGINE_URL"):
            cfg.url = os.environ["CANDIX_ENGINE_URL"]
            cfg.enabled = True
        for key in ("CANDIX_ENGINE_ENABLED", "CANDIX_ENGINE__ENABLED"):
            val = os.environ.get(key, "").lower()
            if val in {"1", "true", "yes", "on"}:
                cfg.enabled = True
            elif val in {"0", "false", "no", "off"}:
                cfg.enabled = False
        for key in ("CANDIX_ENGINE_PARALLEL", "CANDIX_ENGINE__PARALLEL"):
            val = os.environ.get(key, "").lower()
            if val in {"1", "true", "yes", "on"}:
                cfg.parallel = True
            elif val in {"0", "false", "no", "off"}:
                cfg.parallel = False
        if os.environ.get("CANDIX_ENGINE_TIMEOUT"):
            try:
                cfg.timeout = float(os.environ["CANDIX_ENGINE_TIMEOUT"])
            except ValueError:
                pass
        if os.environ.get("CANDIX_ENGINE_BRIDGE_BIN"):
            cfg.bridge_bin = os.environ["CANDIX_ENGINE_BRIDGE_BIN"]
        return cfg

    @classmethod
    def from_config(cls, cfg: object) -> "BridgeConfig":
        base = cls.from_env()
        section: dict[str, object] = {}
        try:
            if hasattr(cfg, "section"):
                section = cfg.section("engine")  # type: ignore
            elif isinstance(cfg, dict):
                sec = cfg.get("engine")
                if isinstance(sec, dict):
                    section = sec  # type: ignore
            elif hasattr(cfg, "get"):
                val = cfg.get("engine")  # type: ignore
                if isinstance(val, dict):
                    section = val  # type: ignore
            elif hasattr(cfg, "data"):
                data = getattr(cfg, "data")
                if isinstance(data, dict) and isinstance(data.get("engine"), dict):
                    section = data["engine"]  # type: ignore
        except Exception:
            section = {}
        if not isinstance(section, dict) or not section:
            return base
        env_enabled_set = any(os.environ.get(k) for k in ("CANDIX_ENGINE_ENABLED", "CANDIX_ENGINE__ENABLED", "CANDIX_ENGINE_URL"))
        env_parallel_set = any(os.environ.get(k) for k in ("CANDIX_ENGINE_PARALLEL", "CANDIX_ENGINE__PARALLEL"))
        if "enabled" in section and not env_enabled_set:
            base.enabled = bool(section["enabled"])
        if "parallel" in section and not env_parallel_set:
            base.parallel = bool(section["parallel"])
        if "url" in section and not os.environ.get("CANDIX_ENGINE_URL"):
            base.url = str(section["url"])
        if "timeout" in section and not os.environ.get("CANDIX_ENGINE_TIMEOUT"):
            try:
                base.timeout = float(section["timeout"])  # type: ignore
            except (ValueError, TypeError):
                pass
        if "use_subprocess" in section:
            base.use_subprocess = bool(section["use_subprocess"])
        if "auto_start" in section:
            base.auto_start = bool(section["auto_start"])
        if "bridge_bin" in section and not os.environ.get("CANDIX_ENGINE_BRIDGE_BIN"):
            base.bridge_bin = str(section["bridge_bin"])
        return base

    def to_dict(self) -> dict[str, object]:
        return {
            "enabled": self.enabled,
            "parallel": self.parallel,
            "url": self.url,
            "timeout": self.timeout,
            "use_subprocess": self.use_subprocess,
            "bridge_bin": self.bridge_bin,
            "auto_start": self.auto_start,
        }
