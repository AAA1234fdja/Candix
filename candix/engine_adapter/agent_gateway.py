"""Agent gateway — engine/agent assembly, planner, worker, toolcatalog."""

from __future__ import annotations

import os
from typing import Any

from candix.engine_bridge.config import BridgeConfig
from candix.engine_bridge.client import EngineClient


class AgentGateway:
    def __init__(self, bridge_config: BridgeConfig | None = None):
        self.config = bridge_config or BridgeConfig()
        self.client = EngineClient(self.config)

    def constraints_block(self, exploration_id: int | None = None) -> str:
        if self.config.enabled:
            try:
                r = self.client._run_bridge("agent-constraints", "{}")
                if r.ok and r.data.get("constraints"):
                    return str(r.data["constraints"])
            except Exception:
                pass
        from candix.agent.constraints import constraint_block
        return constraint_block([])

    def assembly_info(self) -> dict[str, Any]:
        # engine/agent/assembly.go provides agent assembly; expose via bridge + fallback
        return {"deferred_tools": [], "global_names": [], "unlock": None}

    def planner_prompt(self, goal: str, ctx: dict | None = None) -> str:
        # engine/agent/prompt.go + planner.go
        base = f"Goal: {goal}\n"
        if ctx and ctx.get("assets"):
            base += f"Assets: {len(ctx['assets'])} known\n"
        cb = self.constraints_block()
        if cb:
            base += "\n" + cb + "\n"
        return base

    def worker_capabilities(self) -> list[str]:
        # engine/agent/toolcatalog.go
        try:
            from candix.agent.toolset import all_tools
            return [t.name for t in all_tools()]
        except Exception:
            return ["Bash", "Write", "Read", "WebFetch", "Greps"]

    def budget_line(self, task_tokens: int = 0, task_turns: int = 0, intent_tokens: int = 0, intent_turns: int = 0) -> str:
        if self.config.enabled:
            try:
                import json
                r = self.client._run_bridge("budget-new", json.dumps({"task_tokens": task_tokens, "task_turns": task_turns, "intent_tokens": intent_tokens, "intent_turns": intent_turns}))
                if r.ok and r.data.get("line"):
                    return str(r.data["line"])
            except Exception:
                pass
        from candix.agent.budget_ledger import BudgetLedger, new_budget
        ledger = BudgetLedger.new(new_budget(task_tokens, task_turns), new_budget(intent_tokens, intent_turns))
        if ledger:
            return ledger.state().line()
        return ""

    def tool_augment(self, agent_key: str) -> dict[str, Any]:
        # engine/agent/assembly.go ToolAugment hook
        return {"agent": agent_key, "extra": [], "deferred": []}
