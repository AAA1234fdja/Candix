"""A small intentionally vulnerable HTTP application.

Routes (see :data:`ROUTES` for the full map) cover the vulnerability classes
Candix detects: SQL injection, reflected XSS, command injection, path traversal,
SSRF, SSTI, XXE, open redirect, IDOR, weak JWT handling, insecure cookies, CORS
reflection, directory listing, exposed backups and default credentials.

Safety properties:

* binds to ``127.0.0.1`` unless explicitly told otherwise;
* never executes arbitrary commands - the ping route emulates shell output;
* never reads files outside its own sandbox directory;
* outbound fetches are restricted to loopback;
* state is in-memory and discarded on shutdown.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import html
import json
import os
import re
import sqlite3
import threading
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable

VERSION = "1.4.2"
JWT_SECRET = "secret"
FAKE_PASSWD = """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
labuser:x:1000:1000:Lab User:/home/labuser:/bin/bash
"""

ROUTES: dict[str, str] = {
    "/": "landing page with a search form",
    "/search": "reflected XSS via q",
    "/product": "SQL injection via id",
    "/login": "SQL injection authentication bypass",
    "/ping": "command injection via host (emulated)",
    "/download": "path traversal via file",
    "/fetch": "SSRF via url (loopback only)",
    "/render": "server-side template injection via tpl",
    "/xml": "XXE via POSTed XML",
    "/redirect": "open redirect via next",
    "/profile": "IDOR via id",
    "/api/users": "IDOR on JSON API",
    "/api/data": "JSON endpoint for parameter fuzzing",
    "/admin": "weak JWT handling",
    "/graphql": "GraphQL introspection enabled",
    "/headers": "missing security headers",
    "/cookie": "insecure session cookie",
    "/cors": "CORS origin reflection",
    "/crlf": "CRLF injection in Location header",
    "/host": "Host header reflected in links",
    "/cache": "cache poisoning via X-Forwarded-Host",
    "/dir/": "directory listing",
    "/backup.zip": "exposed backup archive",
    "/.env": "exposed environment file",
    "/.git/config": "exposed VCS metadata",
    "/server-status": "exposed server status",
    "/basic/": "default credentials admin/admin",
    "/rate": "unthrottled login attempts",
    "/upload": "unrestricted file upload (metadata only)",
    "/internal/metadata": "simulated cloud metadata endpoint",
    "/internal/service": "loopback-only internal service",
    "/health": "health check",
}


def _db() -> sqlite3.Connection:
    connection = sqlite3.connect(":memory:", check_same_thread=False)
    connection.executescript(
        """
        CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT, price REAL, secret TEXT);
        INSERT INTO products VALUES (1, 'Candix mug', 12.5, 'internal-note-1');
        INSERT INTO products VALUES (2, 'Sticker pack', 3.0, 'internal-note-2');
        INSERT INTO products VALUES (3, 'Hoodie', 45.0, 'internal-note-3');
        CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, email TEXT, role TEXT);
        INSERT INTO users VALUES (1, 'alice', 'alice-password', 'alice@lab.test', 'user');
        INSERT INTO users VALUES (2, 'bob', 'bob-password', 'bob@lab.test', 'user');
        INSERT INTO users VALUES (3, 'admin', 'admin-password', 'admin@lab.test', 'admin');
        """
    )
    return connection


@dataclass
class LabServer:
    host: str = "127.0.0.1"
    port: int = 0
    verbose: bool = False

    def __post_init__(self) -> None:
        self.httpd: ThreadingHTTPServer | None = None
        self.thread: threading.Thread | None = None
        self._db = _db()
        self._cache: dict[str, str] = {}

    @property
    def base_url(self) -> str:
        port = self.port or (self.httpd.server_address[1] if self.httpd else 0)
        return f"http://{self.host}:{port}"

    def start(self) -> "LabServer":
        handler = _make_handler(self)
        self.httpd = ThreadingHTTPServer((self.host, self.port), handler)
        self.httpd.daemon_threads = True
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True, name="candix-lab")
        self.thread.start()
        return self

    def stop(self) -> None:
        if self.httpd is not None:
            self.httpd.shutdown()
            self.httpd.server_close()
            self.httpd = None
        if self.thread is not None:
            self.thread.join(timeout=2)
            self.thread = None

    def wait(self) -> None:
        if self.thread is not None:
            self.thread.join()

    def __enter__(self) -> "LabServer":
        return self.start()

    def __exit__(self, *exc: object) -> None:
        self.stop()


def build_server(host: str = "127.0.0.1", port: int = 0, *, verbose: bool = False) -> LabServer:
    return LabServer(host=host, port=port, verbose=verbose)


def _make_handler(server: LabServer) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "LabServer/1.4.2"
        sys_version = "Python/3.11"

        # ----------------------------------------------------------
        # plumbing
        # ----------------------------------------------------------
        def log_message(self, fmt: str, *args: Any) -> None:
            if server.verbose:
                print(f"[lab] {self.address_string()} {fmt % args}")

        def _read_body(self) -> bytes:
            cached = getattr(self, "_body_cache", None)
            if cached is not None:
                return cached
            length = int(self.headers.get("Content-Length") or 0)
            if length <= 0:
                self._body_cache = b""
                return b""
            self._body_cache = self.rfile.read(min(length, 1_000_000))
            return self._body_cache

        def _query(self) -> dict[str, list[str]]:
            parsed = urllib.parse.urlsplit(self.path)
            return urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

        def _body_form(self) -> dict[str, list[str]]:
            body = self._read_body().decode("utf-8", "replace")
            return urllib.parse.parse_qs(body, keep_blank_values=True)

        def _param(self, name: str, default: str = "") -> str:
            values = self._query().get(name) or self._body_form().get(name)
            return (values or [default])[0]

        def _send(
            self,
            status: int,
            body: str | bytes,
            content_type: str = "text/html; charset=utf-8",
            headers: dict[str, str] | None = None,
        ) -> None:
            payload = body.encode("utf-8") if isinstance(body, str) else body
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("X-Lab", "candix")
            for name, value in (headers or {}).items():
                self.send_header(name, value)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(payload)

        def _html(self, title: str, body: str, headers: dict[str, str] | None = None) -> None:
            page = f"""<!doctype html>
<html><head><title>{title}</title></head>
<body><h1>{title}</h1>{body}
<hr><p>LabServer {VERSION}</p></body></html>"""
            self._send(200, page, headers=headers)

        def _json(self, payload: Any, status: int = 200, headers: dict[str, str] | None = None) -> None:
            self._send(status, json.dumps(payload), "application/json", headers=headers)

        # ----------------------------------------------------------
        # routing
        # ----------------------------------------------------------
        def do_HEAD(self) -> None:
            self.do_GET()

        def do_OPTIONS(self) -> None:
            self._send(
                204,
                b"",
                headers={
                    "Access-Control-Allow-Origin": self.headers.get("Origin", "*"),
                    "Access-Control-Allow-Credentials": "true",
                    "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
                    "Access-Control-Allow-Headers": "*",
                },
            )

        def _reset_request_state(self) -> None:
            self._body_cache = None

        def do_GET(self) -> None:
            self._reset_request_state()
            parsed = urllib.parse.urlsplit(self.path)
            path = parsed.path
            try:
                self._dispatch(path, "GET")
            except Exception as exc:  # pragma: no cover - lab defensive handler
                self._send(
                    500,
                    f"<h1>Internal Server Error</h1><pre>Traceback: {type(exc).__name__}: {exc}</pre>",
                )

        def do_POST(self) -> None:
            self._reset_request_state()
            parsed = urllib.parse.urlsplit(self.path)
            try:
                self._dispatch(parsed.path, "POST")
            except Exception as exc:  # pragma: no cover
                self._send(
                    500,
                    f"<h1>Internal Server Error</h1><pre>Traceback: {type(exc).__name__}: {exc}</pre>",
                )

        def _dispatch(self, path: str, method: str) -> None:
            if method == "GET":
                self._read_body()  # drain unexpected bodies so keep-alive stays in sync
            router: dict[str, Callable[[], None]] = {
                "/": self._index,
                "/search": self._search,
                "/product": self._product,
                "/login": self._login,
                "/ping": self._ping,
                "/download": self._download,
                "/fetch": self._fetch,
                "/render": self._render,
                "/xml": self._xml,
                "/redirect": self._redirect,
                "/profile": self._profile,
                "/api/users": self._api_users,
                "/api/data": self._api_data,
                "/admin": self._admin,
                "/graphql": self._graphql,
                "/headers": self._headers,
                "/cookie": self._cookie,
                "/cors": self._cors,
                "/crlf": self._crlf,
                "/host": self._host,
                "/cache": self._cache_route,
                "/dir/": self._dir,
                "/dir": self._dir,
                "/backup.zip": self._backup,
                "/.env": self._env,
                "/.git/config": self._git,
                "/server-status": self._server_status,
                "/basic/": self._basic,
                "/rate": self._rate,
                "/upload": self._upload,
                "/internal/metadata": self._metadata,
                "/internal/service": self._internal_service,
                "/health": lambda: self._json({"status": "ok", "version": VERSION}),
            }
            handler = router.get(path)
            if handler is None and path.startswith("/api/data/"):
                handler = self._api_data
            if handler is None:
                self._send(404, "<h1>404 Not Found</h1>")
                return
            handler()

        # ----------------------------------------------------------
        # routes
        # ----------------------------------------------------------
        def _index(self) -> None:
            self._html(
                "Candix Lab",
                """
<form action="/search" method="get"><input name="q" value=""><button>Search</button></form>
<ul>
<li><a href="/product?id=1">Product 1</a></li>
<li><a href="/profile?id=1">Profile</a></li>
<li><a href="/api/users?id=1">API user</a></li>
</ul>
<!-- internal note: never expose .env or backups -->
""",
            )

        def _search(self) -> None:
            query = self._param("q")
            results = "" if not query else f"<p>No results for <b>{query}</b></p>"
            self._html("Search", f"<form action='/search' method='get'><input name='q' value='{query}'></form>{results}")

        def _product(self) -> None:
            product_id = self._param("id", "1")
            query = f"SELECT id, name, price, secret FROM products WHERE id = {product_id}"
            try:
                cursor = server._db.execute(query)
                rows = cursor.fetchall()
            except sqlite3.Error as exc:
                self._send(500, f"<h1>Database error</h1><pre>{exc}</pre><p>Query: {html.escape(query)}</p>")
                return
            if not rows:
                self._send(404, "<h1>Product not found</h1>")
                return
            items = "".join(f"<li>{row[0]}: {row[1]} - {row[2]}</li>" for row in rows)
            self._html("Product", f"<ul>{items}</ul><p>Product id: {product_id}</p>")

        def _login(self) -> None:
            if self.command == "GET":
                self._html(
                    "Login",
                    "<form method='post' action='/login'><input name='username'><input name='password' type='password'><button>Sign in</button></form>",
                )
                return
            username = self._param("username")
            password = self._param("password")
            query = f"SELECT id, username, role FROM users WHERE username = '{username}' AND password = '{password}'"
            try:
                row = server._db.execute(query).fetchone()
            except sqlite3.Error as exc:
                self._send(500, f"<h1>Database error</h1><pre>{exc}</pre>")
                return
            if row:
                self._send(
                    200,
                    f"<h1>Welcome {html.escape(row[1])}</h1><p>role={row[2]}</p>",
                    headers={"Set-Cookie": "session=user-session-1; Path=/"},
                )
            else:
                self._send(401, "<h1>Invalid credentials</h1>")

        def _ping(self) -> None:
            host = self._param("host", "127.0.0.1")
            # Emulated shell: only echo/whoami/id/uptime are recognised.
            output = ""
            if "echo" in host:
                match = re.search(r"echo\s+([A-Za-z0-9_.-]+)", host)
                output = match.group(1) if match else ""
            if "whoami" in host:
                output += "www-data\n"
            if re.search(r"\bid\b", host) and "echo" not in host:
                output = "uid=33(www-data) gid=33(www-data) groups=33(www-data)\n"
            if not output:
                output = f"PING {host} (127.0.0.1): 56 data bytes\n64 bytes from 127.0.0.1: time=0.04 ms\n"
            self._html("Ping", f"<pre>{output}</pre>")

        def _download(self) -> None:
            requested = self._param("file", "welcome.txt")
            base = Path(__file__).parent / "sandbox"
            base.mkdir(exist_ok=True)
            (base / "welcome.txt").write_text("Welcome to the Candix lab sandbox.\n", encoding="utf-8")
            (base / "notes.txt").write_text("Nothing sensitive here.\n", encoding="utf-8")
            if "/etc/passwd" in requested or requested.endswith("passwd"):
                self._send(200, FAKE_PASSWD, "text/plain")
                return
            candidate = (base / requested).resolve()
            try:
                candidate.relative_to(base.resolve())
            except ValueError:
                self._send(403, "<h1>Forbidden</h1>")
                return
            if not candidate.exists() or not candidate.is_file():
                self._send(404, "<h1>File not found</h1>")
                return
            self._send(200, candidate.read_bytes(), "application/octet-stream")

        def _fetch(self) -> None:
            url = self._param("url")
            if not url:
                self._html("Fetch", "<form><input name='url'></form>")
                return
            parsed = urllib.parse.urlsplit(url)
            if parsed.hostname not in {"127.0.0.1", "localhost"}:
                self._send(400, "<h1>Only loopback destinations are allowed in the lab</h1>")
                return
            try:
                with urllib.request.urlopen(url, timeout=3) as response:
                    payload = response.read(65536).decode("utf-8", "replace")
            except Exception as exc:
                self._send(502, f"<h1>Fetch failed</h1><pre>{exc}</pre>")
                return
            self._html("Fetch result", f"<pre>{html.escape(payload)}</pre>")

        def _render(self) -> None:
            template = self._param("tpl", "Hello {{name}}")
            rendered = template
            match = re.search(r"\{\{\s*(\d+)\s*\*\s*(\d+)\s*\}\}", rendered)
            if match:
                rendered = rendered.replace(match.group(0), str(int(match.group(1)) * int(match.group(2))))
            if "{{config}}" in rendered:
                rendered = rendered.replace("{{config}}", "SECRET_KEY=lab-secret; DEBUG=True")
            if "{{7*'7'}}" in rendered:
                rendered = rendered.replace("{{7*'7'}}", "7777777")
            self._html("Template", f"<div>{rendered}</div><p>Rendered server-side.</p>")

        def _xml(self) -> None:
            body = self._read_body().decode("utf-8", "replace")
            if not body:
                self._html("XML", "<form method='post'><textarea name='xml'></textarea><button>Send</button></form>")
                return
            if "file:///etc/passwd" in body or "file:///etc/hostname" in body:
                self._send(200, f"<result>{FAKE_PASSWD}</result>", "application/xml")
                return
            entity = re.search(r'<!ENTITY\s+\w+\s+"([^"]+)"', body)
            if entity:
                self._send(200, f"<result>{html.escape(entity.group(1))}</result>", "application/xml")
                return
            self._send(400, "<result>Malformed XML</result>", "application/xml")

        def _redirect(self) -> None:
            target = self._param("next", "/")
            self.send_response(302)
            self.send_header("Location", target)
            self.send_header("Content-Length", "0")
            if "X-Candix" in urllib.parse.unquote(target):
                self.send_header("X-Candix", "injected")
            self.end_headers()

        def _profile(self) -> None:
            user_id = self._param("id", "1")
            row = server._db.execute(
                "SELECT id, username, email, role FROM users WHERE id = ?", (user_id,)
            ).fetchone()
            if not row:
                self._send(404, "<h1>Profile not found</h1>")
                return
            self._html(
                "Profile",
                f"<p>id={row[0]} user={row[1]} email={row[2]} role={row[3]}</p>",
            )

        def _api_users(self) -> None:
            user_id = self._param("id", "1")
            row = server._db.execute(
                "SELECT id, username, email, role FROM users WHERE id = ?", (user_id,)
            ).fetchone()
            if not row:
                self._json({"error": "not found"}, 404)
                return
            self._json({"id": row[0], "username": row[1], "email": row[2], "role": row[3]})

        def _api_data(self) -> None:
            payload = {
                "items": [{"id": 1, "name": "alpha"}, {"id": 2, "name": "beta"}],
                "query": {key: values[0] for key, values in self._query().items()},
                "total": 2,
            }
            self._json(payload)

        def _admin(self) -> None:
            token = self.headers.get("Authorization", "").replace("Bearer ", "").strip()
            if not token:
                cookie = self.headers.get("Cookie", "")
                match = re.search(r"jwt=([^;]+)", cookie)
                token = match.group(1) if match else ""
            if self._token_is_admin(token):
                self._json({"admin": True, "flag": "CDX-lab-admin-access"})
            else:
                self._json({"error": "forbidden"}, 403)

        def _token_is_admin(self, token: str) -> bool:
            if not token:
                return False
            parts = token.split(".")
            if len(parts) != 3:
                return False
            header = _b64url_decode(parts[0])
            payload = _b64url_decode(parts[1])
            signature = parts[2]
            try:
                header_data = json.loads(header or "{}")
                payload_data = json.loads(payload or "{}")
            except json.JSONDecodeError:
                return False
            if header_data.get("alg") == "none":
                return payload_data.get("role") == "admin"
            expected = hmac.new(JWT_SECRET.encode(), f"{parts[0]}.{parts[1]}".encode(), hashlib.sha256).digest()
            if not hmac.compare_digest(_b64url_encode(expected), signature):
                return False
            return payload_data.get("role") == "admin"

        def _issue_token(self, role: str = "user") -> str:
            header = _b64url_encode(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
            payload = _b64url_encode(
                json.dumps({"sub": "alice", "role": role, "iat": int(time.time())}, separators=(",", ":")).encode()
            )
            signature = _b64url_encode(
                hmac.new(JWT_SECRET.encode(), f"{header}.{payload}".encode(), hashlib.sha256).digest()
            )
            return f"{header}.{payload}.{signature}"

        def _graphql(self) -> None:
            if self.command == "POST":
                body = self._read_body().decode("utf-8", "replace")
                if "__schema" in body or "IntrospectionQuery" in body:
                    self._json(
                        {
                            "data": {
                                "__schema": {
                                    "queryType": {"name": "Query"},
                                    "types": [
                                        {"name": "User", "fields": [{"name": "id"}, {"name": "email"}, {"name": "role"}]},
                                        {"name": "Query", "fields": [{"name": "user"}, {"name": "users"}]},
                                    ],
                                }
                            }
                        }
                    )
                    return
                if "login" in body:
                    self._json({"data": {"login": {"token": self._issue_token("admin")}}})
                    return
                self._json({"errors": [{"message": "Cannot query field"}]}, 400)
                return
            self._html(
                "GraphQL",
                "<p>POST GraphQL queries here.</p><p>Example: { __typename }</p>",
            )

        def _headers(self) -> None:
            self._send(200, "<html><body><h1>No hardening here</h1></body></html>")

        def _cookie(self) -> None:
            self._send(
                200,
                "<html><body>cookie set</body></html>",
                headers={"Set-Cookie": "sessionid=abc123; Path=/",},
            )

        def _cors(self) -> None:
            origin = self.headers.get("Origin", "")
            headers = {
                "Access-Control-Allow-Origin": origin or "*",
                "Access-Control-Allow-Credentials": "true",
                "Vary": "Origin",
            }
            self._send(200, '{"ok":true,"secret":"cors-lab-data"}', "application/json", headers=headers)

        def _crlf(self) -> None:
            target = urllib.parse.unquote(self._param("next", "/"))
            self.send_response(302)
            self.send_header("Location", "/" + target)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def _host(self) -> None:
            host = self.headers.get("X-Forwarded-Host") or self.headers.get("Host") or "localhost"
            self._send(200, f"<html><body><a href='http://{host}/login'>Reset password</a></body></html>")

        def _cache_route(self) -> None:
            key = "cache:" + urllib.parse.urlsplit(self.path).path
            if key not in server._cache:
                forwarded = self.headers.get("X-Forwarded-Host", "")
                server._cache[key] = f"<html><body>cached page host={html.escape(forwarded)}</body></html>"
            self._send(200, server._cache[key], headers={"X-Cache": "HIT"})

        def _dir(self) -> None:
            entries = ["welcome.txt", "notes.txt", "backup.zip", "config.php.bak"]
            links = "".join(f"<li><a href='/dir/{name}'>{name}</a></li>" for name in entries)
            self._html("Index of /dir/", f"<ul>{links}</ul>")

        def _backup(self) -> None:
            self._send(200, "PK\x03\x04 fake backup containing database credentials\n", "application/zip")

        def _env(self) -> None:
            self._send(
                200,
                "APP_ENV=production\nAPP_KEY=base64:labsecretlabsecret\nDB_PASSWORD=lab-db-password\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n",
                "text/plain",
            )

        def _git(self) -> None:
            self._send(200, "[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n\turl = https://git.lab.test/app.git\n", "text/plain")

        def _server_status(self) -> None:
            self._send(200, "Server Version: LabServer/1.4.2\nTotal Accesses: 42\nUptime: 1200 seconds\n", "text/plain")

        def _basic(self) -> None:
            header = self.headers.get("Authorization", "")
            if header.startswith("Basic "):
                try:
                    decoded = base64.b64decode(header[6:]).decode()
                except (ValueError, UnicodeDecodeError):
                    decoded = ""
                if decoded in {"admin:admin", "admin:password", "lab:lab"}:
                    self._json({"authenticated": True, "user": decoded.split(":")[0]})
                    return
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Basic realm="lab"')
            self.send_header("Content-Length", "0")
            self.end_headers()

        def _rate(self) -> None:
            username = self._param("username", "alice")
            password = self._param("password", "")
            if username == "alice" and password == "alice-password":
                self._json({"ok": True})
            else:
                self._json({"error": "invalid"}, 401)

        def _upload(self) -> None:
            if self.command == "GET":
                self._html("Upload", "<form method='post' enctype='multipart/form-data'><input type='file' name='file'><button>Upload</button></form>")
                return
            body = self._read_body()
            self._json({"stored": True, "bytes": len(body), "filename": "upload.bin"})

        def _metadata(self) -> None:
            self._json(
                {
                    "instance-id": "i-0labcandix0001",
                    "ami-id": "ami-0abc123",
                    "iam": {"security-credentials": {"role": "lab-role"}},
                    "AccessKeyId": "ASIAIOSFODNN7EXAMPLE",
                }
            )

        def _internal_service(self) -> None:
            if self.client_address[0] not in {"127.0.0.1", "::1"}:
                self._send(403, "forbidden")
                return
            self._json({"internal": True, "flag": "CDX-lab-ssrf"})

    return Handler


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(value: str) -> str:
    padding = "=" * (-len(value) % 4)
    try:
        return base64.urlsafe_b64decode(value + padding).decode("utf-8", "replace")
    except (ValueError, base64.binascii.Error):  # type: ignore[attr-defined]
        return ""


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Run the deliberately vulnerable Candix lab server")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args(argv)
    server = build_server(args.host, args.port, verbose=args.verbose)
    server.start()
    print(f"Candix lab listening on {server.base_url} (routes: {len(ROUTES)})")
    print("WARNING: intentionally vulnerable. Loopback only. Press Ctrl+C to stop.")
    try:
        server.wait()
    except KeyboardInterrupt:
        print("\nstopping")
    finally:
        server.stop()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
