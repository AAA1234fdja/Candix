"""candix.engine_adapter — Python gateway to the Go engine (engine/).

Conexión total sin falta: cada subsistema Go tiene su espejo Python
funcionando a la par (parallel dual) con fallback puro-Python.

Subsistemas conectados:
  config   ↔ engine/config
  db       ↔ engine/db (PG con SQLite fallback)
  guard    ↔ engine/guard
  intercept↔ engine/intercept (risk, target, argv, alwaysallow)
  egress   ↔ engine/egress (pace, governor)
  traffic  ↔ engine/traffic
  agent    ↔ engine/agent (assembly, planner, worker, toolcatalog)
  server   ↔ engine/server (manager, orchestration, API)
  evidence ↔ engine/evidence
  llmpool  ↔ engine/llmpool
  notify   ↔ engine/notify (webhook/dingtalk/feishu/telegram/email)
  report   ↔ engine/report (markdown/quality)
  enrich   ↔ engine/enrich (dns/http probe)
  mcphttp  ↔ engine/mcphttp (Streamable HTTP + SSE)
  sidequestion ↔ engine/sidequestion
  llmrec   ↔ engine/llmrec (recording)
  extension↔ engine/extension (browser capture)

Uso:
    from candix.engine_adapter import Engine
    eng = Engine.from_env()
    eng.health()
    eng.score_risk("Bash", {"command": "rm -rf /"})
"""

from candix.engine_adapter.orchestrator import Engine
from candix.engine_adapter.server_client import ServerClient
from candix.engine_adapter.db import DbClient
from candix.engine_adapter.guard import GuardAdapter
from candix.engine_adapter.intercept_ext import InterceptAdapter
from candix.engine_adapter.traffic import TrafficAdapter
from candix.engine_adapter.egress_ext import EgressAdapter
from candix.engine_adapter.agent_gateway import AgentGateway
from candix.engine_adapter.config_adapter import ConfigAdapter
from candix.engine_adapter.evidence import EvidenceAdapter
from candix.engine_adapter.llmpool import LlmPoolAdapter
from candix.engine_adapter.enrich import EnrichEngine
from candix.engine_adapter.notify_ext import NotifyDispatcher, REGISTRY as NotifyRegistry
from candix.engine_adapter.report import ReportEngine
from candix.engine_adapter.mcp_bridge import McpRegistry, McpClient
from candix.engine_adapter.sidequestion import SideQuestionService
from candix.engine_adapter.llmrec import LlmRecorder
from candix.engine_adapter.extension import ExtensionBridge

__all__ = [
    "Engine",
    "ServerClient",
    "DbClient",
    "GuardAdapter",
    "InterceptAdapter",
    "TrafficAdapter",
    "EgressAdapter",
    "AgentGateway",
    "ConfigAdapter",
    "EvidenceAdapter",
    "LlmPoolAdapter",
    "EnrichEngine",
    "NotifyDispatcher",
    "NotifyRegistry",
    "ReportEngine",
    "McpRegistry",
    "McpClient",
    "SideQuestionService",
    "LlmRecorder",
    "ExtensionBridge",
]
