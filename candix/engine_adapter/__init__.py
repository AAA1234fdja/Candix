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
  notify   ↔ engine/notify
  report   ↔ engine/report

Uso:
    from candix.engine_adapter import Engine
    eng = Engine.from_env()  # o Engine.from_config(cfg)
    eng.health()
    eng.score_risk("Bash", {"command": "rm -rf /"})
    eng.db.store_exploration(...)
    client = eng.server_client()
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
]
