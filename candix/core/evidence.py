"""Evidence capture with a tamper-evident hash chain.

Every proof produced by the harness - an HTTP exchange that demonstrates an
injection, a differential response pair, a file listing - is written to an
append-only evidence directory. Each record embeds the SHA-256 of its canonical
JSON body and the hash of the previous record, so an auditor can prove that
nothing was inserted or altered after collection.
"""

from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Iterator

from candix.core.clock import isoformat, utcnow
from candix.core.errors import ReportError
from candix.core.ids import evidence_id, sha256
from candix.core.redact import RedactionPolicy, SecretRegistry, redact_headers, redact_text

MAX_BODY = 8192


@dataclass
class Exchange:
    """A single request/response pair as observed on the wire."""

    method: str
    url: str
    request_headers: dict[str, str] = field(default_factory=dict)
    request_body: str = ""
    status: int = 0
    reason: str = ""
    response_headers: dict[str, str] = field(default_factory=dict)
    response_body: str = ""
    elapsed: float = 0.0
    error: str = ""
    http_version: str = "HTTP/1.1"

    def request_text(self, max_body: int = MAX_BODY) -> str:
        lines = [f"{self.method} {_request_target(self.url)} {self.http_version}"]
        host = _host_header(self.url)
        if host and not any(name.lower() == "host" for name in self.request_headers):
            lines.append(f"Host: {host}")
        for name, value in self.request_headers.items():
            if name.lower() == "host":
                continue
            lines.append(f"{name}: {value}")
        lines.append("")
        body = self.request_body or ""
        if len(body) > max_body:
            body = body[:max_body] + f"\n... [{len(body) - max_body} bytes truncated]"
        lines.append(body)
        return "\n".join(lines)

    def response_text(self, max_body: int = MAX_BODY) -> str:
        lines = [f"{self.http_version} {self.status} {self.reason}".rstrip()]
        for name, value in self.response_headers.items():
            lines.append(f"{name}: {value}")
        lines.append("")
        body = self.response_body or ""
        if len(body) > max_body:
            body = body[:max_body] + f"\n... [{len(body) - max_body} bytes truncated]"
        lines.append(body)
        return "\n".join(lines)

    def to_curl(self) -> str:
        parts = ["curl", "-i", "-sS", "-X", self.method.upper()]
        for name, value in self.request_headers.items():
            parts.extend(["-H", _shell_quote(f"{name}: {value}")])
        if self.request_body:
            parts.extend(["--data-raw", _shell_quote(self.request_body)])
        parts.append(_shell_quote(self.url))
        return " ".join(parts)

    def to_dict(self) -> dict[str, Any]:
        return {
            "method": self.method,
            "url": self.url,
            "request": {
                "headers": self.request_headers,
                "body": self.request_body,
            },
            "response": {
                "status": self.status,
                "reason": self.reason,
                "headers": self.response_headers,
                "body": self.response_body,
            },
            "elapsed_ms": round(self.elapsed * 1000.0, 3),
            "error": self.error,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Exchange":
        request = data.get("request", {})
        response = data.get("response", {})
        return cls(
            method=data.get("method", "GET"),
            url=data.get("url", ""),
            request_headers=dict(request.get("headers", {})),
            request_body=str(request.get("body", "")),
            status=int(response.get("status", 0)),
            reason=str(response.get("reason", "")),
            response_headers=dict(response.get("headers", {})),
            response_body=str(response.get("body", "")),
            elapsed=float(data.get("elapsed_ms", 0.0)) / 1000.0,
            error=str(data.get("error", "")),
        )


def _host_header(url: str) -> str:
    from candix.net.url import URL

    try:
        parsed = URL.parse(url)
    except ValueError:
        return ""
    return parsed.netloc


def _request_target(url: str) -> str:
    from candix.net.url import URL

    try:
        parsed = URL.parse(url)
    except ValueError:
        return "/"
    target = parsed.path or "/"
    query = parsed.query.render()
    if query:
        target += "?" + query
    return target


def _shell_quote(value: str) -> str:
    if not value:
        return "''"
    if all(char.isalnum() or char in "-_./:=?&%+@," for char in value):
        return value
    return "'" + value.replace("'", "'\\''") + "'"


@dataclass
class Evidence:
    """One proof artifact attached to a finding."""

    kind: str  # "http" | "diff" | "artifact" | "note" | "tls" | "timing"
    summary: str
    exchange: Exchange | None = None
    control: Exchange | None = None
    notes: str = ""
    data: dict[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=evidence_id)
    created_at: str = field(default_factory=isoformat)
    sequence: int = 0
    sha256: str = ""
    prev_sha256: str = ""
    path: str = ""

    def canonical(self) -> str:
        payload = {
            "kind": self.kind,
            "summary": self.summary,
            "notes": self.notes,
            "data": self.data,
            "exchange": self.exchange.to_dict() if self.exchange else None,
            "control": self.control.to_dict() if self.control else None,
            "created_at": self.created_at,
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

    def redacted(self, policy: RedactionPolicy, registry: SecretRegistry | None = None) -> "Evidence":
        clone = Evidence(
            kind=self.kind,
            summary=redact_text(self.summary, policy),
            notes=redact_text(self.notes, policy),
            data=_redact_data(self.data, policy, registry),
            id=self.id,
            created_at=self.created_at,
        )
        clone.exchange = _redact_exchange(self.exchange, policy, registry) if self.exchange else None
        clone.control = _redact_exchange(self.control, policy, registry) if self.control else None
        return clone

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "summary": self.summary,
            "created_at": self.created_at,
            "notes": self.notes,
            "data": self.data,
            "exchange": self.exchange.to_dict() if self.exchange else None,
            "control": self.control.to_dict() if self.control else None,
            "sequence": self.sequence,
            "sha256": self.sha256,
            "prev_sha256": self.prev_sha256,
            "path": self.path,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "Evidence":
        return cls(
            kind=payload.get("kind", "note"),
            summary=payload.get("summary", ""),
            exchange=Exchange.from_dict(payload["exchange"]) if payload.get("exchange") else None,
            control=Exchange.from_dict(payload["control"]) if payload.get("control") else None,
            notes=payload.get("notes", ""),
            data=dict(payload.get("data", {})),
            id=payload.get("id", evidence_id()),
            created_at=payload.get("created_at", isoformat()),
            sequence=int(payload.get("sequence", 0)),
            sha256=payload.get("sha256", ""),
            prev_sha256=payload.get("prev_sha256", ""),
            path=payload.get("path", ""),
        )


def _redact_exchange(
    exchange: Exchange | None,
    policy: RedactionPolicy,
    registry: SecretRegistry | None,
) -> Exchange | None:
    if exchange is None:
        return None
    body = exchange.response_body
    if registry is not None:
        body = registry.apply(body)
    clone = Exchange(
        method=exchange.method,
        url=exchange.url,
        request_headers=redact_headers(exchange.request_headers, policy),
        request_body=exchange.request_body,
        status=exchange.status,
        reason=exchange.reason,
        response_headers=redact_headers(exchange.response_headers, policy),
        response_body=redact_text(body, policy),
        elapsed=exchange.elapsed,
        error=redact_text(exchange.error, policy),
        http_version=exchange.http_version,
    )
    clone.url = _redact_url_soft(exchange.url, policy)
    clone.request_body = redact_text(exchange.request_body, policy)
    return clone


def _redact_url_soft(url: str, policy: RedactionPolicy) -> str:
    from candix.core.redact import redact_url

    try:
        return redact_url(url, policy)
    except Exception:  # pragma: no cover - defensive
        return redact_text(url, policy)


def _redact_data(data: Any, policy: RedactionPolicy, registry: SecretRegistry | None) -> Any:
    if isinstance(data, dict):
        return {key: _redact_data(value, policy, registry) for key, value in data.items()}
    if isinstance(data, list):
        return [_redact_data(value, policy, registry) for value in data]
    if isinstance(data, str):
        return registry.apply(data) if registry is not None else redact_text(data, policy)
    return data


class EvidenceStore:
    """Append-only evidence repository with an integrity manifest."""

    def __init__(
        self,
        root: Path | str,
        *,
        policy: RedactionPolicy | None = None,
        registry: SecretRegistry | None = None,
        max_records: int = 5000,
    ) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.policy = policy or RedactionPolicy()
        self.registry = registry
        self.max_records = max_records
        self._records: list[Evidence] = []
        self._last_hash = "0" * 64
        self._by_finding: dict[str, list[Evidence]] = {}
        self._load_existing()

    def _load_existing(self) -> None:
        manifest = self.root / "manifest.jsonl"
        if not manifest.exists():
            return
        for line in manifest.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                record = Evidence.from_dict(json.loads(line))
            except (ValueError, KeyError):  # pragma: no cover - corrupted manifest
                continue
            self._records.append(record)
            self._last_hash = record.sha256 or self._last_hash
        self._index()

    def _index(self) -> None:
        self._by_finding.clear()
        for record in self._records:
            finding = record.data.get("finding_id", "")
            self._by_finding.setdefault(finding, []).append(record)

    @property
    def count(self) -> int:
        return len(self._records)

    def add(self, finding_id_value: str, evidence: Evidence) -> Evidence:
        if len(self._records) >= self.max_records:
            raise ReportError("evidence store capacity reached", capacity=self.max_records)
        redacted = evidence.redacted(self.policy, self.registry)
        redacted.data.setdefault("finding_id", finding_id_value)
        redacted.sequence = len(self._records) + 1
        redacted.prev_sha256 = self._last_hash
        canonical = redacted.canonical()
        redacted.sha256 = sha256(canonical)
        filename = f"{redacted.sequence:05d}-{redacted.id}.json"
        path = self.root / filename
        path.write_text(json.dumps(redacted.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")
        try:
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:  # pragma: no cover - platform dependent
            pass
        redacted.path = str(path)
        self._records.append(redacted)
        self._by_finding.setdefault(finding_id_value, []).append(redacted)
        self._last_hash = redacted.sha256
        with (self.root / "manifest.jsonl").open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(redacted.to_dict(), ensure_ascii=False) + "\n")
        return redacted

    def for_finding(self, finding_id_value: str) -> list[Evidence]:
        return list(self._by_finding.get(finding_id_value, ()))

    def all(self) -> Iterator[Evidence]:
        return iter(self._records)

    def verify(self) -> tuple[bool, list[str]]:
        """Recompute the hash chain and report every broken link."""

        problems: list[str] = []
        previous = "0" * 64
        for record in self._records:
            if record.prev_sha256 != previous:
                problems.append(f"record {record.sequence}: prev hash mismatch")
            recomputed = sha256(record.canonical())
            if recomputed != record.sha256:
                problems.append(f"record {record.sequence}: digest mismatch")
            previous = record.sha256
        return (not problems, problems)

    def export(self) -> list[dict[str, Any]]:
        return [record.to_dict() for record in self._records]


class NullEvidenceStore(EvidenceStore):
    """Store that discards artifacts; used with ``--no-evidence``."""

    def __init__(self) -> None:
        self.root = Path(os.devnull).parent
        self.policy = RedactionPolicy()
        self.registry = None
        self.max_records = 0
        self._records = []
        self._last_hash = "0" * 64
        self._by_finding = {}

    def add(self, finding_id_value: str, evidence: Evidence) -> Evidence:  # type: ignore[override]
        evidence.data.setdefault("finding_id", finding_id_value)
        return evidence


def summarize_exchange(exchange: Exchange, *, limit: int = 120) -> str:
    snippet = exchange.response_body[:limit].replace("\n", " ").strip()
    return f"{exchange.method} {_request_target(exchange.url)} -> {exchange.status} ({snippet})"


def collect_artifacts(records: Iterable[Evidence], kind: str) -> list[Evidence]:
    return [record for record in records if record.kind == kind]
