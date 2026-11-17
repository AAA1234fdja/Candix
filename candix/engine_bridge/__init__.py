"""Bridge to the Go engine (Artex) — **interconectado a la par**.

Python y Go no se delegan — se ejecutan **en paralelo** y reconcilian
fail-safe (score=max, razones unidas). Ver ``config.BridgeConfig`` y
``client.EngineClient`` / ``intercept_proxy.InterceptProxy``.
"""

from __future__ import annotations

from candix.engine_bridge.client import EngineClient, BridgeResult
from candix.engine_bridge.config import BridgeConfig
from candix.engine_bridge.intercept_proxy import InterceptProxy

__all__ = ["EngineClient", "BridgeResult", "BridgeConfig", "InterceptProxy"]
