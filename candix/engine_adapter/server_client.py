"""Server client — Python gateway to engine/server HTTP API.

Cubre tasks, assets, findings, intercept, LLM, traffic, health.
Funciona contra Go vivo o en modo offline (mock) para CI.
"""

from __future__ import annotations

import json
import os
import urllib.request
import urllib.error
import urllib.parse
from dataclasses import dataclass
from typing import Any


@dataclass
class ApiResult:
    ok: bool
    status: int
    data: Any
    error: str = ""


class ServerClient:
    def __init__(self, base_url: str = "", token: str = ""):
        self.base_url = (base_url or os.getenv("CANDIX_ENGINE_URL", "http://127.0.0.1:8787")).rstrip("/")
        self.token = token or os.getenv("CANDIX_ENGINE_TOKEN", "")
        self.timeout = float(os.getenv("CANDIX_ENGINE_TIMEOUT", "4.0"))

    def _headers(self) -> dict[str, str]:
        h = {"Content-Type": "application/json", "Accept": "application/json"}
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        return h

    def _request(self, method: str, path: str, body: Any = None, params: dict | None = None) -> ApiResult:
        url = self.base_url + path
        if params:
            url += "?" + urllib.parse.urlencode(params)
        data = None
        if body is not None:
            data = json.dumps(body, ensure_ascii=False).encode()
        req = urllib.request.Request(url, data=data, headers=self._headers(), method=method)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read().decode(errors="replace")
                try:
                    data = json.loads(raw) if raw else {}
                except Exception:
                    data = {"raw": raw}
                return ApiResult(ok=True, status=resp.status, data=data)
        except urllib.error.HTTPError as e:
            raw = e.read().decode(errors="replace") if e.fp else ""
            try:
                data = json.loads(raw) if raw else {}
            except Exception:
                data = {"raw": raw}
            return ApiResult(ok=False, status=e.code, data=data, error=str(e))
        except Exception as e:
            return ApiResult(ok=False, status=0, data={}, error=str(e))

    # --- health ---
    def health(self) -> ApiResult:
        return self._request("GET", "/api/health")

    def is_available(self) -> bool:
        return self.health().ok

    # --- tasks ---
    def list_tasks(self) -> ApiResult:
        return self._request("GET", "/api/tasks")

    def create_task(self, description: str, goal: str, **extra: Any) -> ApiResult:
        return self._request("POST", "/api/tasks", {"description": description, "goal": goal, **extra})

    def get_task(self, task_id: str) -> ApiResult:
        return self._request("GET", f"/api/tasks/{task_id}")

    def delete_task(self, task_id: str) -> ApiResult:
        return self._request("DELETE", f"/api/tasks/{task_id}")

    def task_stats(self, task_id: str) -> ApiResult:
        return self._request("GET", f"/api/stats", params={"task": task_id})

    # --- assets / companies ---
    def list_assets(self, **params: Any) -> ApiResult:
        return self._request("GET", "/api/assets", params=params)

    def list_companies(self) -> ApiResult:
        return self._request("GET", "/api/companies")

    # --- findings ---
    def list_findings(self, exploration_id: int | None = None) -> ApiResult:
        p = {"exploration_id": exploration_id} if exploration_id else None  # type: ignore
        return self._request("GET", "/api/exploration/findings", params=p)

    def get_finding(self, finding_id: int) -> ApiResult:
        return self._request("GET", f"/api/exploration/findings/{finding_id}")

    # --- intercept ---
    def list_pending_intercepts(self) -> ApiResult:
        return self._request("GET", "/api/intercept/pending")

    def decide_intercept(self, pending_id: int, decision: str, reason: str = "") -> ApiResult:
        return self._request("POST", f"/api/intercept/pending/{pending_id}/decide", {"decision": decision, "reason": reason})

    def intercept_history(self, **params: Any) -> ApiResult:
        return self._request("GET", "/api/intercept/history", params=params)

    # --- LLM ---
    def list_llm_profiles(self) -> ApiResult:
        return self._request("GET", "/api/llm/profiles")

    def get_settings(self) -> ApiResult:
        return self._request("GET", "/api/settings")

    # --- traffic ---
    def list_traffic(self, task_id: str, **params: Any) -> ApiResult:
        return self._request("GET", f"/api/traffic", params={"task": task_id, **params})

    # --- exploration activities ---
    def list_activities(self, exploration_id: int, **params: Any) -> ApiResult:
        return self._request("GET", f"/api/exploration/activity/{exploration_id}", params=params)
