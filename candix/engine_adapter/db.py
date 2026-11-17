"""DB adapter — engine/db PostgreSQL con SQLite fallback.

Mirrors the Go db package's public API surface for Python.
Uses psycopg if available, else sqlite3 in-memory for CI.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import psycopg  # psycopg3
    HAS_PSYCOPG = True
except ImportError:
    try:
        import psycopg2 as psycopg  # type: ignore
        HAS_PSYCOPG = True
    except ImportError:
        psycopg = None  # type: ignore
        HAS_PSYCOPG = False


@dataclass
class DbConfig:
    dsn: str = ""
    use_sqlite_fallback: bool = True
    sqlite_path: str = ":memory:"


class DbClient:
    """Conexión total a engine/db — schema, exploration, assets, findings."""

    def __init__(self, config: DbConfig | None = None, dsn: str = ""):
        self.config = config or DbConfig(dsn=dsn or self._dsn_from_env())
        self._conn: Any = None
        self._lock = threading.Lock()
        self._is_pg = False
        self._connect()

    def _dsn_from_env(self) -> str:
        import os
        return os.getenv("CANDIX_ENGINE_PG_DSN", os.getenv("DATABASE_URL", ""))

    def _connect(self) -> None:
        dsn = self.config.dsn
        if dsn and HAS_PSYCOPG:
            try:
                self._conn = psycopg.connect(dsn)  # type: ignore
                self._conn.autocommit = True
                self._is_pg = True
                self._init_schema_pg()
                return
            except Exception:
                pass
        # fallback sqlite — crea schema mínimo compatible
        self._conn = sqlite3.connect(self.config.sqlite_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._is_pg = False
        self._init_schema_sqlite()

    def _init_schema_sqlite(self) -> None:
        self._conn.executescript("""
        CREATE TABLE IF NOT EXISTS explorations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            task_id TEXT, goal TEXT, status TEXT DEFAULT 'running',
            created_at INTEGER, updated_at INTEGER, data TEXT
        );
        CREATE TABLE IF NOT EXISTS assets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            exploration_id INTEGER, kind TEXT, label TEXT,
            attributes TEXT, created_at INTEGER
        );
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            exploration_id INTEGER, severity TEXT, title TEXT,
            url TEXT, payload TEXT, created_at INTEGER
        );
        CREATE TABLE IF NOT EXISTS activities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            exploration_id INTEGER, kind TEXT, payload TEXT, created_at INTEGER
        );
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version TEXT PRIMARY KEY, checksum TEXT
        );
        """)
        self._conn.commit()

    def _init_schema_pg(self) -> None:
        try:
            with self._conn.cursor() as cur:
                cur.execute("SELECT 1 FROM schema_migrations LIMIT 1")
        except Exception:
            pass  # Go engine owns real schema — Python no migra PG

    # --- exploration ---
    def create_exploration(self, task_id: str, goal: str, data: dict | None = None) -> int:
        import time
        payload = json.dumps(data or {}, ensure_ascii=False)
        now = int(time.time())
        with self._lock:
            cur = self._conn.cursor()
            if self._is_pg:
                cur.execute("INSERT INTO explorations (task_id, goal, data, created_at, updated_at) VALUES (%s,%s,%s,%s,%s) RETURNING id", (task_id, goal, payload, now, now))
                row = cur.fetchone()
                return int(row[0])
            else:
                cur.execute("INSERT INTO explorations (task_id, goal, data, created_at, updated_at) VALUES (?,?,?,?,?)", (task_id, goal, payload, now, now))
                self._conn.commit()
                return int(cur.lastrowid)

    def get_exploration(self, exp_id: int) -> dict | None:
        with self._lock:
            cur = self._conn.cursor()
            q = "SELECT * FROM explorations WHERE id=%s" if self._is_pg else "SELECT * FROM explorations WHERE id=?"
            cur.execute(q, (exp_id,))
            row = cur.fetchone()
            if not row:
                return None
            return dict(row) if not self._is_pg else {"id": row[0], "task_id": row[1], "goal": row[2], "status": row[3], "created_at": row[4], "updated_at": row[5], "data": row[6]}

    def list_explorations(self, limit: int = 50) -> list[dict]:
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(f"SELECT * FROM explorations ORDER BY id DESC LIMIT {int(limit)}")
            rows = cur.fetchall()
            return [dict(r) for r in rows] if rows and not self._is_pg else [{"id": r[0], "task_id": r[1]} for r in rows] if rows else []

    # --- assets ---
    def add_asset(self, exploration_id: int, kind: str, label: str, attributes: dict | None = None) -> int:
        import time
        payload = json.dumps(attributes or {}, ensure_ascii=False)
        now = int(time.time())
        with self._lock:
            cur = self._conn.cursor()
            if self._is_pg:
                cur.execute("INSERT INTO assets (exploration_id, kind, label, attributes, created_at) VALUES (%s,%s,%s,%s,%s) RETURNING id", (exploration_id, kind, label, payload, now))
                return int(cur.fetchone()[0])
            else:
                cur.execute("INSERT INTO assets (exploration_id, kind, label, attributes, created_at) VALUES (?,?,?,?,?)", (exploration_id, kind, label, payload, now))
                self._conn.commit()
                return int(cur.lastrowid)

    def list_assets(self, exploration_id: int) -> list[dict]:
        with self._lock:
            cur = self._conn.cursor()
            q = "SELECT * FROM assets WHERE exploration_id=%s" if self._is_pg else "SELECT * FROM assets WHERE exploration_id=?"
            cur.execute(q, (exploration_id,))
            rows = cur.fetchall()
            return [dict(r) for r in rows] if rows and not self._is_pg else [{"id": r[0], "kind": r[2]} for r in rows] if rows else []

    # --- findings ---
    def add_finding(self, exploration_id: int, title: str, severity: str = "medium", url: str = "", payload: dict | None = None) -> int:
        import time
        data = json.dumps(payload or {}, ensure_ascii=False)
        now = int(time.time())
        with self._lock:
            cur = self._conn.cursor()
            if self._is_pg:
                cur.execute("INSERT INTO findings (exploration_id, severity, title, url, payload, created_at) VALUES (%s,%s,%s,%s,%s,%s) RETURNING id", (exploration_id, severity, title, url, data, now))
                return int(cur.fetchone()[0])
            else:
                cur.execute("INSERT INTO findings (exploration_id, severity, title, url, payload, created_at) VALUES (?,?,?,?,?,?)", (exploration_id, severity, title, url, data, now))
                self._conn.commit()
                return int(cur.lastrowid)

    # --- activities ---
    def add_activity(self, exploration_id: int, kind: str, payload: dict | None = None) -> int:
        import time
        data = json.dumps(payload or {}, ensure_ascii=False)
        now = int(time.time())
        with self._lock:
            cur = self._conn.cursor()
            if self._is_pg:
                cur.execute("INSERT INTO activities (exploration_id, kind, payload, created_at) VALUES (%s,%s,%s,%s) RETURNING id", (exploration_id, kind, data, now))
                return int(cur.fetchone()[0])
            else:
                cur.execute("INSERT INTO activities (exploration_id, kind, payload, created_at) VALUES (?,?,?,?)", (exploration_id, kind, data, now))
                self._conn.commit()
                return int(cur.lastrowid)

    def health(self) -> dict:
        try:
            cur = self._conn.cursor()
            cur.execute("SELECT 1")
            cur.fetchone()
            return {"ok": True, "pg": self._is_pg, "dsn_present": bool(self.config.dsn)}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def close(self) -> None:
        try:
            self._conn.close()
        except Exception:
            pass
