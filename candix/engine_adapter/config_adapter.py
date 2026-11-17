"""Config adapter — engine/config ↔ candix/core/config."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any


class ConfigAdapter:
    """Lee config.json / CANDIX_ENGINE_PG_DSN igual que engine/config."""

    def __init__(self, path: str | Path | None = None):
        self.path = Path(path) if path else Path(os.getenv("CANDIX_ENGINE_CONFIG", "")) or (Path.home() / ".config" / "candix" / "config.json")
        self._data: dict[str, Any] = {}
        self._load()

    def _load(self) -> None:
        if self.path.exists():
            try:
                self._data = json.loads(self.path.read_text())
            except Exception:
                self._data = {}
        # env override — PG DSN
        if os.getenv("CANDIX_ENGINE_PG_DSN"):
            self._data["pg_dsn"] = os.getenv("CANDIX_ENGINE_PG_DSN")
        if os.getenv("CANDIX_ENGINE_TRUSTED_PROXIES"):
            self._data["trusted_proxies"] = os.getenv("CANDIX_ENGINE_TRUSTED_PROXIES")

    def get(self, key: str, default: Any = None) -> Any:
        return self._data.get(key, default)

    def to_dict(self) -> dict[str, Any]:
        return dict(self._data)

    def pg_dsn(self) -> str:
        return str(self._data.get("pg_dsn", os.getenv("CANDIX_ENGINE_PG_DSN", "")))

    def skill_dir(self) -> Path | None:
        v = self._data.get("skill_dir") or os.getenv("CANDIX_SKILL_DIR")
        return Path(v) if v else None

    def base_dir(self) -> Path:
        return Path(self._data.get("base_dir", Path.home() / ".local" / "share" / "candix"))

    @classmethod
    def from_env(cls) -> ConfigAdapter:
        return cls()
