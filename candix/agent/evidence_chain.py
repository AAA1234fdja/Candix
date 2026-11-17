"""A tamper-evident chain from claim to captured exchange.

Every record stores the digest of the previous one, so dropping or editing an
entry breaks verification. Records also carry the anchors that connect them to
the asset graph: endpoint, finding, fact and intent ids. A report can therefore
say "this claim came from this response, taken by this intent, at this time"
without trusting the report itself.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

GENESIS = "0" * 64


def _canonical(payload: dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest(payload: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()


@dataclass
class Record:
    kind: str
    claim: str = ""
    body: dict[str, Any] = field(default_factory=dict)
    anchors: dict[str, str] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)
    previous: str = GENESIS
    digest: str = ""

    def compute(self) -> str:
        payload = {
            "kind": self.kind,
            "claim": self.claim,
            "body": self.body,
            "anchors": self.anchors,
            "created_at": round(self.created_at, 6),
            "previous": self.previous,
        }
        self.digest = digest(payload)
        return self.digest

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "claim": self.claim,
            "body": self.body,
            "anchors": dict(self.anchors),
            "created_at": self.created_at,
            "previous": self.previous,
            "digest": self.digest,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "Record":
        return cls(
            kind=str(payload.get("kind", "")),
            claim=str(payload.get("claim", "")),
            body=dict(payload.get("body") or {}),
            anchors=dict(payload.get("anchors") or {}),
            created_at=float(payload.get("created_at", 0.0)),
            previous=str(payload.get("previous", GENESIS)),
            digest=str(payload.get("digest", "")),
        )


@dataclass
class ChainSettings:
    hash_bodies: bool = True
    max_body_chars: int = 20_000
    include_headers: bool = True
    redact_headers: tuple[str, ...] = ("authorization", "cookie", "set-cookie", "x-api-key", "proxy-authorization")


class EvidenceChain:
    def __init__(self, settings: ChainSettings | None = None) -> None:
        self.settings = settings or ChainSettings()
        self.records: list[Record] = []

    # ------------------------------------------------------------------
    def append(self, kind: str, *, claim: str = "", body: dict[str, Any] | None = None, **anchors: str) -> Record:
        previous = self.records[-1].digest if self.records else GENESIS
        record = Record(
            kind=kind,
            claim=claim[:400],
            body=self._clean(body or {}),
            anchors={key: str(value) for key, value in anchors.items() if value},
            previous=previous,
        )
        record.compute()
        self.records.append(record)
        return record

    def _clean(self, body: dict[str, Any]) -> dict[str, Any]:
        cleaned = self._scrub(json.loads(_canonical(body)) if body else {})
        text = _canonical(cleaned)
        if len(text) > self.settings.max_body_chars:
            cleaned = {"truncated": True, "digest": hashlib.sha256(text.encode()).hexdigest(), "size": len(text)}
        return cleaned

    def _scrub(self, value: Any) -> Any:
        if isinstance(value, dict):
            output: dict[str, Any] = {}
            for key, item in value.items():
                if isinstance(item, dict) and str(key).lower() == "headers":
                    if not self.settings.include_headers:
                        output[key] = {"omitted": "true"}
                    else:
                        output[key] = {
                            name: ("[redacted]" if str(name).lower() in self.settings.redact_headers else text)
                            for name, text in item.items()
                        }
                    continue
                output[key] = self._scrub(item)
            return output
        if isinstance(value, list):
            return [self._scrub(item) for item in value]
        return value

    # ------------------------------------------------------------------
    def bind_exchange(
        self,
        *,
        finding_id: str,
        endpoint_id: str,
        request: dict[str, Any],
        response: dict[str, Any],
        intent_id: str = "",
        note: str = "",
    ) -> Record:
        return self.append(
            "exchange",
            claim=note or "captured exchange",
            body={"request": request, "response": response},
            finding=finding_id,
            endpoint=endpoint_id,
            intent=intent_id,
        )

    def bind_finding(self, finding: dict[str, Any], *, endpoint_id: str = "", intent_id: str = "") -> Record:
        return self.append(
            "finding",
            claim=str(finding.get("title", "")),
            body={key: finding.get(key) for key in ("severity", "url", "parameter", "category", "verified", "exploited")},
            finding=str(finding.get("id", "")),
            endpoint=endpoint_id,
            intent=intent_id,
        )

    def bind_fact(self, fact: Any) -> Record:
        payload = fact.to_dict() if hasattr(fact, "to_dict") else dict(fact)
        return self.append(
            "fact",
            claim=str(payload.get("claim", "")),
            body={"source": payload.get("source"), "confidence": payload.get("confidence")},
            fact=str(payload.get("id", "")),
            endpoint=str((payload.get("subject") or "")),
        )

    def bind_proof(self, proof: dict[str, Any], *, intent_id: str = "") -> Record:
        return self.append(
            "proof",
            claim=str(proof.get("claim", proof.get("title", "proof"))),
            body={"summary": proof.get("summary", ""), "facts": proof.get("facts", [])},
            intent=intent_id,
        )

    # ------------------------------------------------------------------
    def verify(self) -> list[str]:
        problems: list[str] = []
        previous = GENESIS
        for index, record in enumerate(self.records):
            if record.previous != previous:
                problems.append(f"record {index}: previous digest mismatch")
            expected = record.digest
            record.compute()
            if record.digest != expected:
                problems.append(f"record {index}: body was modified")
            previous = record.digest
        return problems

    def head(self) -> str:
        return self.records[-1].digest if self.records else GENESIS

    def kinds(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for record in self.records:
            counts[record.kind] = counts.get(record.kind, 0) + 1
        return counts

    def find(self, **anchors: str) -> list[Record]:
        return [record for record in self.records if all(record.anchors.get(key) == value for key, value in anchors.items())]

    def to_dict(self) -> dict[str, Any]:
        return {
            "head": self.head(),
            "records": [record.to_dict() for record in self.records],
            "kinds": self.kinds(),
        }

    def save(self, path: str | Path) -> str:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(self.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")
        return str(target)

    @classmethod
    def load(cls, path: str | Path) -> "EvidenceChain":
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        chain = cls()
        chain.records = [Record.from_dict(item) for item in payload.get("records", [])]
        return chain

    # ------------------------------------------------------------------
    def bundle(self, *, include_bodies: bool = False) -> dict[str, Any]:
        records = []
        for record in self.records:
            item = {"kind": record.kind, "claim": record.claim, "anchors": record.anchors, "digest": record.digest}
            if include_bodies:
                item["body"] = record.body
            records.append(item)
        return {"head": self.head(), "count": len(records), "kinds": self.kinds(), "records": records}

    def summary(self) -> str:
        if not self.records:
            return "empty evidence chain"
        kinds = ", ".join(f"{name}={count}" for name, count in sorted(self.kinds().items()))
        return f"{len(self.records)} record(s), head {self.head()[:12]} ({kinds})"


def build_chain(result: Any, assets: Any = None) -> EvidenceChain:
    """Derive a chain from a finished run without re-reading the network."""

    chain = EvidenceChain()
    for finding in getattr(result, "findings", []):
        endpoint_id = ""
        if assets is not None:
            try:
                from candix.agent.graph import endpoint_key

                endpoint_id = endpoint_key(str(finding.get("method", "GET")), str(finding.get("url", "")))
            except Exception:
                endpoint_id = ""
        chain.bind_finding(finding, endpoint_id=endpoint_id)
    for proof in getattr(result, "proofs", []):
        chain.bind_proof(proof)
    return chain


def export_markdown(chain: EvidenceChain, *, limit: int = 40) -> str:
    lines = ["# Evidence chain", "", f"Head: `{chain.head()}`", "", "| # | kind | claim | digest |", "| --- | --- | --- | --- |"]
    for index, record in enumerate(chain.records[:limit], start=1):
        lines.append(f"| {index} | {record.kind} | {record.claim[:60].replace('|', '/')} | `{record.digest[:16]}` |")
    return "\n".join(lines) + "\n"
