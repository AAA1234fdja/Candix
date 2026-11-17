"""Bridge to the Go engine (Artex).

Candix Python is the primary harness, but the Go engine remains the
authoritative implementation for risk scoring, target normalisation and
the full HTTP/DB stack. This package connects them via code:

* HTTP client for a running engine (`:8787` / `CANDIX_ENGINE_URL`)
* Subprocess CLI bridge (`engine/cmd/bridge`) that calls Go's
  ``intercept.ScoreRisk``/``NormalizeTarget`` directly without needing
  Postgres or the full server
* Optional proxy so ``candix.agent.intercept`` can delegate to Go when
  ``engine.enabled=true`` and fall back to Python otherwise
"""

from __future__ import annotations

from candix.engine_bridge.client import EngineClient, BridgeResult
from candix.engine_bridge.config import BridgeConfig
from candix.engine_bridge.intercept_proxy import InterceptProxy

__all__ = ["EngineClient", "BridgeResult", "BridgeConfig", "InterceptProxy"]
