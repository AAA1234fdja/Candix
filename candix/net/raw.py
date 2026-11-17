"""Raw HTTP/1.1 writer for framing and desynchronisation tests."""

from __future__ import annotations

import socket
import ssl
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit


@dataclass
class RawResponse:
    status_line: str = ""
    status: int = 0
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    raw: str = ""
    elapsed: float = 0.0
    truncated: bool = False

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 400

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "status_line": self.status_line,
            "headers": dict(self.headers),
            "body_length": len(self.body),
            "body": self.body[:2000],
            "elapsed": round(self.elapsed, 3),
            "truncated": self.truncated,
        }


class RawError(Exception):
    """Raised when a raw exchange cannot complete."""


def build_request(
    method: str,
    path: str,
    host: str,
    *,
    headers: list[tuple[str, str]] | None = None,
    body: bytes = b"",
    http_version: str = "HTTP/1.1",
    include_length: bool = True,
) -> bytes:
    lines = [f"{method.upper()} {path} {http_version}", f"Host: {host}"]
    supplied = {name.lower() for name, _ in (headers or [])}
    for name, value in headers or []:
        lines.append(f"{name}: {value}")
    if include_length and "content-length" not in supplied and body:
        lines.append(f"Content-Length: {len(body)}")
    if "connection" not in supplied:
        lines.append("Connection: close")
    if "user-agent" not in supplied:
        lines.append("User-Agent: candix-raw/1.0")
    return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1") + body


def parse_response(raw: bytes) -> RawResponse:
    text = raw.decode("latin-1", "replace")
    head, _, body = text.partition("\r\n\r\n")
    lines = head.split("\r\n")
    status_line = lines[0] if lines else ""
    status = 0
    if status_line.startswith("HTTP/"):
        parts = status_line.split(" ", 2)
        try:
            status = int(parts[1])
        except (IndexError, ValueError):
            status = 0
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" not in line:
            continue
        name, _, value = line.partition(":")
        headers[name.strip().lower()] = value.strip()
    return RawResponse(status_line=status_line, status=status, headers=headers, body=body, raw=text)


def send_raw_request(
    url: str,
    *,
    method: str = "GET",
    path: str = "",
    headers: list[tuple[str, str]] | None = None,
    body: bytes = b"",
    timeout: float = 5.0,
    http_version: str = "HTTP/1.1",
    use_tls: bool | None = None,
    verify_tls: bool = False,
    read_limit: int = 65536,
    settle: float = 0.15,
) -> RawResponse:
    """Open a socket, write one handcrafted request and read until the peer closes."""

    parts = urlsplit(url if "://" in url else f"http://{url}")
    secure = (parts.scheme == "https") if use_tls is None else use_tls
    host = parts.hostname or "127.0.0.1"
    port = parts.port or (443 if secure else 80)
    target = path or (parts.path or "/") + (f"?{parts.query}" if parts.query and not path else "")
    started = time.monotonic()
    raw_socket = socket.create_connection((host, port), timeout=timeout)
    if secure:
        context = ssl.create_default_context()
        if not verify_tls:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        raw_socket = context.wrap_socket(raw_socket, server_hostname=host)
    payload = build_request(method, target, parts.netloc or host, headers=headers, body=body, http_version=http_version)
    try:
        raw_socket.sendall(payload)
        if settle:
            time.sleep(settle)
        chunks: list[bytes] = []
        total = 0
        while total < read_limit:
            try:
                chunk = raw_socket.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
    finally:
        try:
            raw_socket.close()
        except OSError:
            pass
    raw = b"".join(chunks)
    response = parse_response(raw)
    response.elapsed = time.monotonic() - started
    response.truncated = total >= read_limit
    return response


def paired_smuggle_probe(
    url: str,
    *,
    host_header: str = "",
    timeout: float = 5.0,
) -> dict[str, Any]:
    """Send a CL.TE shaped pair and report whether the second response desynchronises."""

    parts = urlsplit(url if "://" in url else f"http://{url}")
    host = host_header or parts.netloc or (parts.hostname or "")
    path = parts.path or "/"
    body = b"0\r\n\r\n"
    headers = [
        ("Content-Length", str(len(body) + 6)),
        ("Transfer-Encoding", "chunked"),
    ]
    first = send_raw_request(url, method="POST", path=path, headers=headers, body=b"0\r\n\r\nG", timeout=timeout)
    second = send_raw_request(url, method="GET", path=path, timeout=timeout)
    return {
        "url": url,
        "first": first.to_dict(),
        "second": second.to_dict(),
        "desync_suspected": first.status >= 500 or second.status >= 500,
        "host": host,
    }


def pipeline_probe(url: str, *, count: int = 3, timeout: float = 5.0) -> dict[str, Any]:
    """Send several requests on one connection and count the responses."""

    parts = urlsplit(url if "://" in url else f"http://{url}")
    secure = parts.scheme == "https"
    host = parts.hostname or "127.0.0.1"
    port = parts.port or (443 if secure else 80)
    sock = socket.create_connection((host, port), timeout=timeout)
    if secure:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        sock = context.wrap_socket(sock, server_hostname=host)
    path = parts.path or "/"
    request = build_request("GET", path, parts.netloc or host, headers=[("Connection", "keep-alive")])
    try:
        sock.sendall(request * max(1, count))
        time.sleep(0.2)
        data = b""
        while True:
            try:
                chunk = sock.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            data += chunk
    finally:
        sock.close()
    responses = data.count(b"HTTP/1.")
    return {"url": url, "sent": count, "responses": responses, "pipelined": responses > 1}
