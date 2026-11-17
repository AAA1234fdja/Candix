"""Traffic adapter — engine/traffic proxy capture en Python."""

from __future__ import annotations

import os
import time
import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class Exchange:
    id: str
    ts: int
    host: str
    method: str
    url: str
    url_template: str
    status: int
    content_type: str
    req_len: int
    resp_len: int
    path: str
    request: dict = field(default_factory=dict)
    response: dict = field(default_factory=dict)


class TrafficAdapter:
    """Captura HTTP espejo de engine/traffic — proxy + file tree + SQLite index."""

    def __init__(self, data_dir: str | Path | None = None):
        self.data_dir = Path(data_dir or os.getenv("CANDIX_DATA_DIR", "data/traffic"))
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self._exchanges: list[Exchange] = []
        self._index_path = self.data_dir / "index.db"
        self._init_index()

    def _init_index(self) -> None:
        import sqlite3
        try:
            conn = sqlite3.connect(str(self._index_path))
            conn.executescript("""
            CREATE TABLE IF NOT EXISTS exchanges (
                id TEXT PRIMARY KEY, ts INTEGER, host TEXT, method TEXT,
                url_template TEXT, url TEXT, status INTEGER,
                content_type TEXT, req_len INTEGER, resp_len INTEGER, path TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_ex_host ON exchanges(host);
            CREATE INDEX IF NOT EXISTS idx_ex_ts ON exchanges(ts);
            """)
            conn.commit()
            conn.close()
        except Exception:
            pass

    def record(self, method: str, url: str, status: int = 200, req_headers: dict | None = None, resp_headers: dict | None = None, req_body: bytes | None = None, resp_body: bytes | None = None) -> Exchange:
        from urllib.parse import urlparse
        host = urlparse(url).hostname or "unknown"
        ts = int(time.time()*1000)
        eid = hashlib.sha256(f"{ts}{method}{url}".encode()).hexdigest()[:16]
        ex = Exchange(id=eid, ts=ts, host=host, method=method, url=url, url_template=url, status=status, content_type=(resp_headers or {}).get("content-type",""), req_len=len(req_body or b""), resp_len=len(resp_body or b""), path=str(self.data_dir / eid), request={"headers": req_headers or {}, "body": (req_body or b"").decode(errors="replace")[:4000]}, response={"headers": resp_headers or {}, "body": (resp_body or b"").decode(errors="replace")[:4000]})
        self._exchanges.append(ex)
        # persist file
        try:
            p = Path(ex.path)
            p.mkdir(parents=True, exist_ok=True)
            (p / "request.txt").write_text(f"{method} {url}\n{req_headers}\n\n{(req_body or b'').decode(errors='replace')}")
            (p / "response.txt").write_text(f"{status}\n{resp_headers}\n\n{(resp_body or b'').decode(errors='replace')}")
            import sqlite3
            conn = sqlite3.connect(str(self._index_path))
            conn.execute("INSERT OR REPLACE INTO exchanges VALUES (?,?,?,?,?,?,?,?,?,?,?)", (eid, ts, host, method, url, url, status, ex.content_type, ex.req_len, ex.resp_len, ex.path))
            conn.commit()
            conn.close()
        except Exception:
            pass
        return ex

    def list(self, host: str | None = None, limit: int = 100) -> list[Exchange]:
        items = self._exchanges[::-1]
        if host:
            items = [e for e in items if e.host == host]
        return items[:limit]

    def get(self, eid: str) -> Exchange | None:
        for e in self._exchanges:
            if e.id == eid:
                return e
        return None

    def validate_url(self, url: str) -> bool:
        return url.startswith("http://") or url.startswith("https://")

    def proxy_addr(self) -> str:
        return os.getenv("CANDIX_ENGINE_PROXY_ADDR", "")

    def snapshot(self) -> dict[str, Any]:
        return {"count": len(self._exchanges), "data_dir": str(self.data_dir), "proxy": self.proxy_addr()}
