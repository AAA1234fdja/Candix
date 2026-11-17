"""Minimal RFC 6455 client used by the WebSocket checks."""

from __future__ import annotations

import base64
import hashlib
import os
import socket
import ssl
import struct
import time
from dataclasses import dataclass, field
from typing import Any, Iterable
from urllib.parse import urlsplit

GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

OPCODE_CONTINUATION = 0x0
OPCODE_TEXT = 0x1
OPCODE_BINARY = 0x2
OPCODE_CLOSE = 0x8
OPCODE_PING = 0x9
OPCODE_PONG = 0xA

OPCODE_NAMES = {
    OPCODE_CONTINUATION: "continuation",
    OPCODE_TEXT: "text",
    OPCODE_BINARY: "binary",
    OPCODE_CLOSE: "close",
    OPCODE_PING: "ping",
    OPCODE_PONG: "pong",
}


class WebSocketError(Exception):
    """Raised for handshake or framing failures."""


@dataclass
class Frame:
    opcode: int
    payload: bytes
    fin: bool = True

    @property
    def kind(self) -> str:
        return OPCODE_NAMES.get(self.opcode, f"0x{self.opcode:x}")

    @property
    def text(self) -> str:
        return self.payload.decode("utf-8", "replace")

    def to_dict(self) -> dict[str, Any]:
        return {"opcode": self.kind, "length": len(self.payload), "fin": self.fin, "sample": self.text[:200]}


@dataclass
class Handshake:
    status: int
    headers: dict[str, str]
    raw: str = ""
    accepted: bool = False
    protocol: str = ""
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "headers": dict(self.headers),
            "accepted": self.accepted,
            "protocol": self.protocol,
            "error": self.error,
        }


def accept_key(key: str) -> str:
    digest = hashlib.sha1((key + GUID).encode("ascii")).digest()
    return base64.b64encode(digest).decode("ascii")


def build_handshake(url: str, *, origin: str = "", extra_headers: Iterable[tuple[str, str]] = ()) -> tuple[bytes, str]:
    parts = urlsplit(url)
    host = parts.netloc
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    key = base64.b64encode(os.urandom(16)).decode("ascii")
    lines = [
        f"GET {path} HTTP/1.1",
        f"Host: {host}",
        "Upgrade: websocket",
        "Connection: Upgrade",
        f"Sec-WebSocket-Key: {key}",
        "Sec-WebSocket-Version: 13",
        f"User-Agent: candix-websocket/1.0",
    ]
    if origin:
        lines.append(f"Origin: {origin}")
    for name, value in extra_headers:
        lines.append(f"{name}: {value}")
    return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1"), key


def parse_handshake(raw: bytes) -> Handshake:
    text = raw.decode("latin-1", "replace")
    head, _, _rest = text.partition("\r\n\r\n")
    lines = head.split("\r\n")
    if not lines or not lines[0].startswith("HTTP/"):
        return Handshake(status=0, headers={}, raw=head, error="malformed response")
    parts = lines[0].split(" ", 2)
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
    accepted = status == 101 and headers.get("upgrade", "").lower() == "websocket"
    return Handshake(status=status, headers=headers, raw=head, accepted=accepted, protocol=headers.get("sec-websocket-protocol", ""))


def encode_frame(payload: bytes | str, *, opcode: int = OPCODE_TEXT, mask: bool = True, fin: bool = True) -> bytes:
    if isinstance(payload, str):
        payload = payload.encode("utf-8")
    header = bytearray()
    header.append((0x80 if fin else 0x00) | (opcode & 0x0F))
    length = len(payload)
    mask_bit = 0x80 if mask else 0x00
    if length < 126:
        header.append(mask_bit | length)
    elif length < (1 << 16):
        header.append(mask_bit | 126)
        header.extend(struct.pack("!H", length))
    else:
        header.append(mask_bit | 127)
        header.extend(struct.pack("!Q", length))
    if not mask:
        return bytes(header) + payload
    key = os.urandom(4)
    masked = bytes(byte ^ key[index % 4] for index, byte in enumerate(payload))
    return bytes(header) + key + masked


def decode_frame(buffer: bytes) -> tuple[Frame | None, bytes]:
    if len(buffer) < 2:
        return None, buffer
    first, second = buffer[0], buffer[1]
    fin = bool(first & 0x80)
    opcode = first & 0x0F
    masked = bool(second & 0x80)
    length = second & 0x7F
    offset = 2
    if length == 126:
        if len(buffer) < offset + 2:
            return None, buffer
        length = struct.unpack("!H", buffer[offset : offset + 2])[0]
        offset += 2
    elif length == 127:
        if len(buffer) < offset + 8:
            return None, buffer
        length = struct.unpack("!Q", buffer[offset : offset + 8])[0]
        offset += 8
    key = b""
    if masked:
        if len(buffer) < offset + 4:
            return None, buffer
        key = buffer[offset : offset + 4]
        offset += 4
    if len(buffer) < offset + length:
        return None, buffer
    payload = buffer[offset : offset + length]
    if masked:
        payload = bytes(byte ^ key[index % 4] for index, byte in enumerate(payload))
    return Frame(opcode=opcode, payload=payload, fin=fin), buffer[offset + length :]


@dataclass
class WebSocketClient:
    url: str
    origin: str = ""
    timeout: float = 5.0
    verify_tls: bool = False
    headers: list[tuple[str, str]] = field(default_factory=list)
    sock: Any = None
    handshake: Handshake | None = None
    _buffer: bytes = b""

    # ------------------------------------------------------------------
    def connect(self) -> Handshake:
        parts = urlsplit(self.url)
        secure = parts.scheme == "wss"
        host = parts.hostname or "127.0.0.1"
        port = parts.port or (443 if secure else 80)
        raw_socket = socket.create_connection((host, port), timeout=self.timeout)
        if secure:
            context = ssl.create_default_context()
            if not self.verify_tls:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            raw_socket = context.wrap_socket(raw_socket, server_hostname=host)
        self.sock = raw_socket
        request, key = build_handshake(self.url, origin=self.origin, extra_headers=self.headers)
        self.sock.sendall(request)
        buffer = b""
        deadline = time.monotonic() + self.timeout
        while b"\r\n\r\n" not in buffer and time.monotonic() < deadline:
            try:
                chunk = self.sock.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            buffer += chunk
        head, _, rest = buffer.partition(b"\r\n\r\n")
        handshake = parse_handshake(buffer)
        if handshake.accepted:
            expected = accept_key(key)
            if handshake.headers.get("sec-websocket-accept") != expected:
                handshake.accepted = False
                handshake.error = "Sec-WebSocket-Accept mismatch"
        else:
            handshake.error = handshake.error or f"unexpected status {handshake.status}"
        self.handshake = handshake
        self._buffer = rest
        return handshake

    # ------------------------------------------------------------------
    def send(self, payload: str | bytes, *, opcode: int = OPCODE_TEXT) -> int:
        if self.sock is None:
            raise WebSocketError("client is not connected")
        frame = encode_frame(payload, opcode=opcode)
        self.sock.sendall(frame)
        return len(payload)

    def send_json(self, payload: dict[str, Any]) -> int:
        import json

        return self.send(json.dumps(payload))

    def recv(self, *, timeout: float | None = None) -> Frame | None:
        if self.sock is None:
            raise WebSocketError("client is not connected")
        self.sock.settimeout(timeout or self.timeout)
        while True:
            frame, self._buffer = decode_frame(self._buffer)
            if frame is not None:
                if frame.opcode == OPCODE_PING:
                    self.sock.sendall(encode_frame(frame.payload, opcode=OPCODE_PONG))
                    continue
                return frame
            try:
                chunk = self.sock.recv(4096)
            except socket.timeout:
                return None
            if not chunk:
                return None
            self._buffer += chunk

    def drain(self, *, limit: int = 10, timeout: float | None = None) -> list[Frame]:
        frames: list[Frame] = []
        for _ in range(limit):
            frame = self.recv(timeout=timeout)
            if frame is None:
                break
            frames.append(frame)
            if frame.opcode == OPCODE_CLOSE:
                break
        return frames

    def ping(self, payload: bytes = b"candix") -> bool:
        if self.sock is None:
            return False
        self.sock.sendall(encode_frame(payload, opcode=OPCODE_PING))
        return bool(self.drain(limit=2))

    def close(self) -> None:
        if self.sock is None:
            return
        try:
            self.sock.sendall(encode_frame(b"\x03\xe8", opcode=OPCODE_CLOSE))
        except OSError:
            pass
        try:
            self.sock.close()
        finally:
            self.sock = None

    def __enter__(self) -> "WebSocketClient":
        self.connect()
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()


def probe(url: str, *, origin: str = "", timeout: float = 5.0, message: str | None = None) -> dict[str, Any]:
    """Attempt a handshake (and optional message) and summarise the result."""

    client = WebSocketClient(url=url, origin=origin, timeout=timeout)
    try:
        handshake = client.connect()
    except OSError as exc:
        return {"url": url, "connected": False, "error": str(exc)}
    result: dict[str, Any] = {"url": url, "connected": handshake.accepted, "handshake": handshake.to_dict()}
    if handshake.accepted and message:
        try:
            client.send(message)
            frames = client.drain(limit=3, timeout=timeout)
            result["frames"] = [frame.to_dict() for frame in frames]
        except OSError as exc:
            result["error"] = str(exc)
    client.close()
    return result
