"""Bridge helpers for egress — a la par Python + Go."""

from __future__ import annotations

from typing import Any

from candix.agent.egress import Governor, Profile, profile_by_name
from candix.engine_bridge.config import BridgeConfig


def profile_via_engine(name: str, cfg: BridgeConfig | None = None) -> dict[str, Any]:
    if cfg is None or not cfg.enabled:
        p, ok = profile_by_name(name)
        return {"source": "python", "profile": p.__dict__, "ok": ok}
    from candix.engine_bridge.client import EngineClient
    client = EngineClient(cfg)
    res = client._run_bridge("egress-profile", f'{{"name": {name!r}}}')
    if res.ok:
        return {"source": "go-subprocess", "profile": res.data.get("profile"), "ok": res.data.get("ok")}
    p, ok = profile_by_name(name)
    return {"source": "python-fallback", "profile": p.__dict__, "ok": ok, "go_error": res.error}
