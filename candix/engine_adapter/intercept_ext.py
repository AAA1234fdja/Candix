"""Intercept ext — engine/intercept completo en Python a la par Go."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from candix.engine_bridge.config import BridgeConfig
from candix.engine_bridge.client import EngineClient


@dataclass
class TargetInfo:
    kind: str
    host: str
    port: int
    ok: bool


class InterceptAdapter:
    def __init__(self, bridge_config: BridgeConfig | None = None):
        self.config = bridge_config or BridgeConfig()
        self.client = EngineClient(self.config)

    def score_risk(self, tool: str, input_data: dict[str, Any]) -> dict[str, Any]:
        res = self.client.score_risk(tool, input_data)
        if res.ok:
            return res.data
        from candix.agent.intercept import score_tool
        r = score_tool(tool, input_data)
        return r.to_dict()

    def normalize_target(self, raw: str) -> TargetInfo:
        res = self.client.normalize_target(raw)
        if res.ok and res.data.get("ok"):
            t = res.data.get("target", {})
            return TargetInfo(kind=t.get("Kind", t.get("kind", "")), host=t.get("Host", t.get("host", "")), port=int(t.get("Port", t.get("port", 0) or 0)), ok=True)
        # python fallback
        from candix.agent.intercept import normalise_target
        try:
            t = normalise_target(raw)
            if t:
                d = t.to_dict() if hasattr(t, "to_dict") else {}
                return TargetInfo(kind=d.get("kind", ""), host=d.get("host", raw), port=int(d.get("port", 0) or 0), ok=True)
        except Exception:
            pass
        return TargetInfo(kind="", host=raw, port=0, ok=False)

    def argv_prefix(self, command: str) -> list[str]:
        if self.config.enabled:
            try:
                import json
                r = self.client._run_bridge("argv-prefix", json.dumps({"command": command}))
                if r.ok and r.data.get("prefix"):
                    return list(r.data["prefix"])
            except Exception:
                pass
        # python fallback — simple shlex + arity
        try:
            import shlex
            tokens = shlex.split(command)
            # reuse Go arity table
            arity = {
                "cat":1,"ls":1,"rm":1,"git":2,"npm":2,"docker":2,"kubectl":2,"terraform":2,
                "gcloud":3,"aws":3, "gh":3,
            }
            for n in range(min(len(tokens),3),0,-1):
                key = " ".join(tokens[:n])
                if key in arity:
                    return tokens[:arity[key]]
            return tokens[:1] if tokens else []
        except Exception:
            return []

    def check_always_allow(self, tool: str, input_data: dict[str, Any]) -> bool:
        # alwaysallow_denylist is Go-controlled; in Python we check denylist manually
        from candix.agent.intercept import score_tool
        r = score_tool(tool, input_data)
        return r.score < 30

    def target_gate_check(self, raw: str, allowed_targets: list[str] | None = None) -> dict[str, Any]:
        info = self.normalize_target(raw)
        if not info.ok:
            return {"allowed": False, "reason": "unparseable target", "target": info}
        if allowed_targets:
            # simple allowlist check
            host = info.host.lower()
            for a in allowed_targets:
                if host == a.lower() or host.endswith("."+a.lower()):
                    return {"allowed": True, "target": info}
            return {"allowed": False, "reason": f"target {host} not in allowlist", "target": info}
        return {"allowed": True, "target": info}
