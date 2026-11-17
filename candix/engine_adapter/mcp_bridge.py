"""MCP bridge — engine/mcphttp Streamable HTTP + SSE en Python."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any

try:
    import httpx  # type: ignore
    HAS_HTTPX = True
except ImportError:
    httpx = None  # type: ignore
    HAS_HTTPX = False


PROTOCOL_VERSION = "2025-11-25"

@dataclass
class McpTool:
    name: str  # mcp__server__tool
    server: str
    original_name: str
    description: str
    input_schema: dict[str, Any] = field(default_factory=dict)

class McpClient:
    def __init__(self, server: str, url: str, headers: dict[str, str] | None = None, insecure: bool = False, timeout: int = 120):
        self.server = server
        self.url = url
        self.headers = headers or {}
        self.insecure = insecure
        self.timeout = timeout
        self.session_id = ""
        self.protocol = PROTOCOL_VERSION
        self._tools: list[McpTool] = []

    def initialize(self) -> None:
        if not HAS_HTTPX:
            return
        try:
            with httpx.Client(timeout=self.timeout, verify=not self.insecure) as c:  # type: ignore
                r = c.post(self.url, json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": self.protocol, "capabilities": {}, "clientInfo": {"name": "candix", "version": "0.2"}}}, headers={**self.headers, "Accept": "application/json, text/event-stream"})
                if r.status_code < 300:
                    self.session_id = r.headers.get("Mcp-Session-Id", "")
                    # notify initialized
                    c.post(self.url, json={"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}}, headers=self._headers())
        except Exception:
            pass

    def _headers(self) -> dict[str, str]:
        h = dict(self.headers)
        h["Accept"] = "application/json, text/event-stream"
        if self.session_id:
            h["Mcp-Session-Id"] = self.session_id
        return h

    def list_tools(self) -> list[McpTool]:
        if not HAS_HTTPX:
            return []
        try:
            with httpx.Client(timeout=self.timeout, verify=not self.insecure) as c:  # type: ignore
                r = c.post(self.url, json={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}, headers=self._headers())
                data = r.json()
                tools = data.get("result", {}).get("tools", [])
                out: list[McpTool] = []
                for t in tools:
                    out.append(McpTool(name=f"mcp__{self.server}__{t['name']}", server=self.server, original_name=t["name"], description=t.get("description", ""), input_schema=t.get("inputSchema", {})))
                self._tools = out
                return out
        except Exception:
            return []

    def call(self, tool: str, arguments: Any = None) -> str:
        # tool may be original or fully qualified
        short = tool.removeprefix(f"mcp__{self.server}__")
        if not HAS_HTTPX:
            raise RuntimeError("httpx not available")
        with httpx.Client(timeout=self.timeout, verify=not self.insecure) as c:  # type: ignore
            r = c.post(self.url, json={"jsonrpc": "2.0", "id": 99, "method": "tools/call", "params": {"name": short, "arguments": arguments or {}}}, headers=self._headers())
            data = r.json()
            if data.get("error"):
                raise RuntimeError(f"mcp rpc error: {data['error']}")
            content = data.get("result", {}).get("content", [])
            text = "".join(block.get("text", "") for block in content)
            if data.get("result", {}).get("isError"):
                raise RuntimeError(text)
            return text

    def close(self) -> None:
        if not self.session_id or not HAS_HTTPX:
            return
        try:
            with httpx.Client(timeout=5, verify=not self.insecure) as c:  # type: ignore
                c.request("DELETE", self.url, headers={"Mcp-Session-Id": self.session_id, **self.headers})
        except Exception:
            pass

class McpRegistry:
    def __init__(self):
        self._clients: dict[str, McpClient] = {}

    def connect(self, server: str, url: str, headers: dict[str, str] | None = None, insecure: bool = False) -> McpClient:
        client = McpClient(server, url, headers, insecure)
        try:
            client.initialize()
        except Exception:
            pass
        self._clients[server] = client
        return client

    def get(self, server: str) -> McpClient | None:
        return self._clients.get(server)

    def all_tools(self) -> list[McpTool]:
        out: list[McpTool] = []
        for c in self._clients.values():
            out.extend(c.list_tools())
        return out

    def close_all(self) -> None:
        for c in list(self._clients.values()):
            try:
                c.close()
            except Exception:
                pass
        self._clients.clear()
