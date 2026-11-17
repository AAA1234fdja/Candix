"""Minimal DNS client for CNAME chains, TXT records and resolution checks.

The harness must work without third-party libraries, and the system resolver
often hides CNAME chains. This module speaks just enough DNS (A, CNAME, TXT,
NS) to support subdomain takeover detection and certificate inventory.
"""

from __future__ import annotations

import random
import socket
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

TYPE_A = 1
TYPE_NS = 2
TYPE_CNAME = 5
TYPE_TXT = 16
TYPE_AAAA = 28

TYPE_NAMES = {TYPE_A: "A", TYPE_NS: "NS", TYPE_CNAME: "CNAME", TYPE_TXT: "TXT", TYPE_AAAA: "AAAA"}


@dataclass
class DnsRecord:
    name: str
    record_type: str
    value: str
    ttl: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "type": self.record_type, "value": self.value, "ttl": self.ttl}


@dataclass
class DnsAnswer:
    name: str
    records: list[DnsRecord] = field(default_factory=list)
    error: str = ""
    server: str = ""

    def of_type(self, record_type: str) -> list[DnsRecord]:
        return [record for record in self.records if record.record_type == record_type]

    def values(self, record_type: str) -> list[str]:
        return [record.value for record in self.of_type(record_type)]

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "records": [record.to_dict() for record in self.records],
            "error": self.error,
            "server": self.server,
        }


def system_resolvers() -> list[str]:
    resolvers: list[str] = []
    try:
        content = Path("/etc/resolv.conf").read_text(encoding="utf-8")
    except OSError:
        return ["8.8.8.8", "1.1.1.1"]
    for line in content.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[0] in {"nameserver", "server"}:
            candidate = parts[1].split("#")[0]
            if candidate:
                resolvers.append(candidate)
    return resolvers or ["8.8.8.8", "1.1.1.1"]


def _encode_name(name: str) -> bytes:
    output = b""
    for label in name.rstrip(".").split("."):
        if not label:
            continue
        raw = label.encode("idna")
        output += struct.pack("!B", len(raw)) + raw
    return output + b"\x00"


def _build_query(name: str, record_type: int, query_id: int) -> bytes:
    header = struct.pack("!HHHHHH", query_id, 0x0100, 1, 0, 0, 0)
    return header + _encode_name(name) + struct.pack("!HH", record_type, 1)


def _decode_name(packet: bytes, offset: int, depth: int = 0) -> tuple[str, int]:
    labels: list[str] = []
    while True:
        if offset >= len(packet) or depth > 10:
            break
        length = packet[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0 == 0xC0:
            pointer = struct.unpack("!H", packet[offset : offset + 2])[0] & 0x3FFF
            pointed, _ = _decode_name(packet, pointer, depth + 1)
            labels.append(pointed)
            offset += 2
            break
        labels.append(packet[offset + 1 : offset + 1 + length].decode("idna", "replace"))
        offset += 1 + length
    return ".".join(label for label in labels if label), offset


def query(name: str, record_type: int = TYPE_A, *, timeout: float = 3.0, server: str | None = None) -> DnsAnswer:
    servers = [server] if server else system_resolvers()
    last_error = ""
    for resolver in servers[:2]:
        query_id = random.randint(0, 65535)
        packet = _build_query(name, record_type, query_id)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            sock.sendto(packet, (resolver, 53))
            data, _ = sock.recvfrom(4096)
        except (socket.timeout, OSError) as exc:
            last_error = f"{type(exc).__name__}: {exc}"
            continue
        finally:
            sock.close()
        if len(data) < 12:
            last_error = "short DNS response"
            continue
        answer_id, flags, qdcount, ancount, _, _ = struct.unpack("!HHHHHH", data[:12])
        if answer_id != query_id:
            last_error = "DNS transaction id mismatch"
            continue
        rcode = flags & 0x000F
        if rcode != 0:
            return DnsAnswer(name=name, error=f"rcode={rcode}", server=resolver)
        offset = 12
        for _ in range(qdcount):
            _, offset = _decode_name(data, offset)
            offset += 4
        records: list[DnsRecord] = []
        for _ in range(ancount):
            record_name, offset = _decode_name(data, offset)
            if offset + 10 > len(data):
                break
            rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", data[offset : offset + 10])
            offset += 10
            rdata = data[offset : offset + rdlength]
            offset += rdlength
            value = ""
            if rtype == TYPE_A and rdlength == 4:
                value = ".".join(str(part) for part in rdata)
            elif rtype == TYPE_AAAA and rdlength == 16:
                value = socket.inet_ntop(socket.AF_INET6, rdata)
            elif rtype in {TYPE_CNAME, TYPE_NS}:
                value, _ = _decode_name(data, offset - rdlength)
            elif rtype == TYPE_TXT:
                parts: list[str] = []
                index = 0
                while index < len(rdata):
                    length = rdata[index]
                    parts.append(rdata[index + 1 : index + 1 + length].decode("utf-8", "replace"))
                    index += 1 + length
                value = "".join(parts)
            if value:
                records.append(
                    DnsRecord(
                        name=record_name,
                        record_type=TYPE_NAMES.get(rtype, str(rtype)),
                        value=value,
                        ttl=ttl,
                    )
                )
        return DnsAnswer(name=name, records=records, server=resolver)
    return DnsAnswer(name=name, error=last_error or "no resolver answered")


def resolve(host: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        return []
    addresses: list[str] = []
    for info in infos:
        address = info[4][0]
        if address not in addresses:
            addresses.append(address)
    return addresses


def cname_chain(host: str, *, max_depth: int = 6) -> list[str]:
    chain: list[str] = []
    current = host
    for _ in range(max_depth):
        answer = query(current, TYPE_CNAME)
        cnames = answer.values("CNAME")
        if not cnames:
            break
        target = cnames[0].rstrip(".")
        chain.append(target)
        current = target
    return chain


def txt_records(host: str) -> list[str]:
    return query(host, TYPE_TXT).values("TXT")


def is_resolvable(host: str) -> bool:
    return bool(resolve(host))


def summary(host: str) -> dict[str, Any]:
    a = query(host, TYPE_A)
    return {
        "host": host,
        "addresses": a.values("A"),
        "cname": cname_chain(host),
        "error": a.error,
        "server": a.server,
    }
