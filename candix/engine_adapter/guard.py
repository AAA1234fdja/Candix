"""Guard adapter — espejo Python de engine/guard.

Audit ring 2000, attribution, targetOnly, hook registry.
Delegates to Go bridge when enabled, otherwise pure Python.
"""

from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any

from candix.engine_bridge.config import BridgeConfig
from candix.engine_bridge.client import EngineClient


@dataclass
class AuditEntry:
    ts: int
    tool: str
    action: str  # allow|block
    reason: str = ""
    command: str = ""


class GuardAdapter:
    def __init__(self, bridge_config: BridgeConfig | None = None, target_only: bool = False):
        self.config = bridge_config or BridgeConfig()
        self.client = EngineClient(self.config)
        self.target_only = target_only
        self._audit: deque[AuditEntry] = deque(maxlen=2000)
        self._attrib: dict[str, int] = {}

    def audit(self) -> list[AuditEntry]:
        if self.config.enabled:
            try:
                r = self.client._run_bridge("guard-audit", "{}")
                if r.ok and "audit" in r.data:
                    return [AuditEntry(**e) for e in r.data["audit"]]
            except Exception:
                pass
        return list(self._audit)

    def attributions(self) -> dict[str, int]:
        if self.config.enabled:
            try:
                r = self.client._run_bridge("guard-audit", "{}")
                if r.ok:
                    return dict(r.data.get("attributions", {}))
            except Exception:
                pass
        return dict(self._attrib)

    def check(self, tool: str, input_data: dict[str, Any]) -> dict[str, Any]:
        """PreToolUse — retorna {allowed, reason, rule}"""
        # Python local evaluation
        from candix.agent.guard import ScopeGuard  # fallback
        # Bridge parallel check
        if self.config.enabled:
            try:
                r = self.client._run_bridge("guard-check", __import__("json").dumps({"tool": tool, "input": input_data}))
                if r.ok:
                    allowed = not r.data.get("denied", False)
                    self._audit.append(AuditEntry(int(time.time()*1000), tool, "allow" if allowed else "block", reason=str(r.data.get("risk", {}).get("reasons", [""])[0] if r.data.get("risk", {}).get("reasons") else "")))
                    return {"allowed": allowed, "reason": r.data.get("risk", {}).get("reasons", [""])[0] if r.data.get("risk", {}).get("reasons") else "", "bridge": r.data, "local": allowed}
            except Exception as e:
                pass
        # fallback: risk gate
        from candix.agent.intercept import score_tool
        report = score_tool(tool, input_data)
        allowed = report.score < 70
        self._audit.append(AuditEntry(int(time.time()*1000), tool, "allow" if allowed else "block", reason="; ".join(report.reasons)))
        if not allowed:
            self._attrib[tool] = self._attrib.get(tool, 0) + 1
        return {"allowed": allowed, "score": report.score, "level": report.level, "reasons": report.reasons}

    def snapshot(self) -> dict[str, Any]:
        return {"audit": [e.__dict__ for e in self.audit()], "attributions": self.attributions(), "target_only": self.target_only}
