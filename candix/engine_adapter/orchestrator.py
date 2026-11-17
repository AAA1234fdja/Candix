"""Orchestrator — Engine unificado que conecta todo sin falta."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from candix.engine_bridge.config import BridgeConfig
from candix.engine_bridge.client import EngineClient
from candix.engine_adapter.config_adapter import ConfigAdapter
from candix.engine_adapter.db import DbClient, DbConfig
from candix.engine_adapter.server_client import ServerClient
from candix.engine_adapter.guard import GuardAdapter
from candix.engine_adapter.intercept_ext import InterceptAdapter
from candix.engine_adapter.egress_ext import EgressAdapter
from candix.engine_adapter.traffic import TrafficAdapter
from candix.engine_adapter.agent_gateway import AgentGateway
from candix.engine_adapter.evidence import EvidenceAdapter
from candix.engine_adapter.llmpool import LlmPoolAdapter
from candix.engine_adapter.enrich import EnrichEngine
from candix.engine_adapter.notify_ext import NotifyDispatcher
from candix.engine_adapter.report import ReportEngine
from candix.engine_adapter.mcp_bridge import McpRegistry
from candix.engine_adapter.sidequestion import SideQuestionService
from candix.engine_adapter.llmrec import LlmRecorder
from candix.engine_adapter.extension import ExtensionBridge


@dataclass
class EngineHealth:
    bridge: dict[str, Any] = field(default_factory=dict)
    server: dict[str, Any] = field(default_factory=dict)
    db: dict[str, Any] = field(default_factory=dict)
    guard: dict[str, Any] = field(default_factory=dict)
    egress: dict[str, Any] = field(default_factory=dict)
    traffic: dict[str, Any] = field(default_factory=dict)
    enrich: dict[str, Any] = field(default_factory=dict)
    notify: dict[str, Any] = field(default_factory=dict)
    report: dict[str, Any] = field(default_factory=dict)
    mcp: dict[str, Any] = field(default_factory=dict)
    sidequestion: dict[str, Any] = field(default_factory=dict)
    llmrec: dict[str, Any] = field(default_factory=dict)
    extension: dict[str, Any] = field(default_factory=dict)


class Engine:
    """Conexión total engine Go ↔ Python — 0 subsistemas desconectados."""

    def __init__(self, bridge_config: BridgeConfig | None = None, config_adapter: ConfigAdapter | None = None):
        self.bridge_config = bridge_config or BridgeConfig.from_env()
        self.config = config_adapter or ConfigAdapter()
        self._client = EngineClient(self.bridge_config)

        self.db = DbClient(DbConfig(dsn=self.config.pg_dsn()))
        self.server = ServerClient(self.bridge_config.url)
        self.guard = GuardAdapter(self.bridge_config)
        self.guard_target_only = GuardAdapter(self.bridge_config, target_only=True)
        self.intercept = InterceptAdapter(self.bridge_config)
        self.egress = EgressAdapter(self.bridge_config)
        self.traffic = TrafficAdapter()
        self.agent = AgentGateway(self.bridge_config)
        self.evidence = EvidenceAdapter()
        self.llmpool = LlmPoolAdapter(self.bridge_config.url)
        # nuevos conectados sin falta
        self.enrich = EnrichEngine()
        self.notify = NotifyDispatcher()
        self.report = ReportEngine()
        self.mcp = McpRegistry()
        self.sidequestion = SideQuestionService()
        self.llmrec = LlmRecorder(model="candix", profile_name="default")
        self.extension = ExtensionBridge()

    @classmethod
    def from_env(cls) -> Engine:
        return cls(BridgeConfig.from_env(), ConfigAdapter.from_env())

    @classmethod
    def from_config(cls, cfg: Any) -> Engine:
        return cls(BridgeConfig.from_config(cfg), ConfigAdapter())

    def health(self) -> EngineHealth:
        bridge_h = {"enabled": self.bridge_config.enabled, "has_go": self.bridge_config.has_go_toolchain(), "url": self.bridge_config.url}
        try:
            bridge_h["bridge_version"] = self._client._run_bridge("version", "{}").data
        except Exception as e:
            bridge_h["bridge_error"] = str(e)
        server_h = self.server.health().data if self.server.health().ok else {"ok": False, "error": self.server.health().error}
        return EngineHealth(
            bridge=bridge_h, server=server_h, db=self.db.health(), guard=self.guard.snapshot(),
            egress=self.egress.snapshot(), traffic=self.traffic.snapshot(),
            enrich={"results": len(self.enrich.results())}, notify={"channels": len(self.notify.channels)},
            report={"ok": True}, mcp={"servers": len(self.mcp._clients)},
            sidequestion={"provider": bool(self.sidequestion.provider)}, llmrec={"records": len(self.llmrec.records)},
            extension=self.extension.snapshot(),
        )

    def is_available(self) -> bool:
        return self.server.is_available() or self.bridge_config.enabled

    def score_risk(self, tool: str, input_data: dict[str, Any]) -> dict[str, Any]:
        return self.intercept.score_risk(tool, input_data)
    def normalize_target(self, raw: str):
        return self.intercept.normalize_target(raw)
    def argv_prefix(self, command: str) -> list[str]:
        return self.intercept.argv_prefix(command)
    def guard_check(self, tool: str, input_data: dict[str, Any]) -> dict[str, Any]:
        return self.guard.check(tool, input_data)
    def budget_line(self, **kw: Any) -> str:
        return self.agent.budget_line(**kw)
    def to_dict(self) -> dict[str, Any]:
        h = self.health()
        return {"bridge": h.bridge, "server": h.server, "db": h.db, "egress": h.egress, "traffic": h.traffic, "enrich": h.enrich, "notify": h.notify, "report": h.report, "mcp": h.mcp, "llm_profiles": [p.__dict__ for p in self.llmpool.list_profiles()]}
