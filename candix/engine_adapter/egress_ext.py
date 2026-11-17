"""Egress ext — conexión total engine/egress + pace.go"""

from __future__ import annotations

from candix.engine_bridge.config import BridgeConfig
from candix.engine_bridge.client import EngineClient
from candix.agent.egress import Governor, Profile, profile_by_name, current_governor, set_profile


class EgressAdapter:
    def __init__(self, bridge_config: BridgeConfig | None = None):
        self.config = bridge_config or BridgeConfig()
        self.client = EngineClient(self.config)
        self.governor = current_governor()

    def profile(self, name: str | None = None) -> Profile:
        if self.config.enabled and name:
            try:
                import json
                r = self.client._run_bridge("egress-profile", json.dumps({"name": name}))
                if r.ok:
                    p = r.data.get("profile", {})
                    return Profile(name=p.get("Name", p.get("name", name)), rps=float(p.get("RPS", p.get("rps", 0))), burst=int(p.get("Burst", p.get("burst", 0))), max_per_host=int(p.get("MaxPerHost", p.get("max_per_host", 0))), max_global=int(p.get("MaxGlobal", p.get("max_global", 0))), jitter=float(p.get("Jitter", p.get("jitter", 0))), cache_ttl=float(p.get("CacheTTL", p.get("cache_ttl", 0))), max_retries=int(p.get("MaxRetries", p.get("max_retries", 0))), base_delay=float(p.get("BaseDelay", p.get("base_delay", 0))), max_delay=float(p.get("MaxDelay", p.get("max_delay", 0))))
            except Exception:
                pass
        import os
        n = name or os.getenv("CANDIX_ENGINE_NOISE_PROFILE", "off")
        p, _ = profile_by_name(n)
        return p

    def set_noise_profile(self, name: str) -> Governor:
        p, ok = profile_by_name(name)
        if not ok:
            p = Profile(name="off")
        self.governor = set_profile(p)
        return self.governor

    def acquire(self, url: str, timeout: float | None = None):
        from candix.agent.egress import host_key
        key = host_key(url)
        return self.governor.acquire(key, timeout=timeout)

    def snapshot(self) -> dict:
        return {"profile": self.governor.p.__dict__, "snapshot": [h.__dict__ for h in self.governor.snapshot()], "off": self.governor.off()}
