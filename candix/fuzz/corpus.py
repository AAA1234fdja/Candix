"""Seed corpus and response learning."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from candix.core.endpoint import Endpoint, Param

_TOKEN_RE = re.compile(r"[A-Za-z0-9_./-]{3,64}")
_STRUCTURED_RE = re.compile(r"[\[\]{}()<>\"'=]", re.IGNORECASE)


@dataclass
class Seed:
    endpoint: Endpoint
    param: Param
    baseline_status: int = 0
    baseline_length: int = 0
    baseline_hash: str = ""
    baseline_body: str = ""
    tokens: set[str] = field(default_factory=set)
    samples: int = 0

    @property
    def key(self) -> str:
        return f"{self.endpoint.method.upper()} {self.endpoint.url} {self.param.location}:{self.param.name}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "url": self.endpoint.url,
            "method": self.endpoint.method,
            "parameter": self.param.name,
            "location": self.param.location,
            "original": self.param.value,
            "baseline_status": self.baseline_status,
            "baseline_length": self.baseline_length,
            "samples": self.samples,
        }


class Corpus:
    """Keeps seeds, learned tokens and interesting responses on disk."""

    def __init__(self, directory: str | Path | None = None, *, limit: int = 400) -> None:
        self.directory = Path(directory) if directory else None
        self.limit = limit
        self.seeds: dict[str, Seed] = {}
        self.tokens: dict[str, int] = {}
        self.interesting: list[dict[str, Any]] = []
        if self.directory:
            self.directory.mkdir(parents=True, exist_ok=True)
            (self.directory / "responses").mkdir(exist_ok=True)

    # ------------------------------------------------------------------
    def add_seed(self, endpoint: Endpoint, param: Param) -> Seed:
        seed = Seed(endpoint=endpoint, param=param)
        self.seeds.setdefault(seed.key, seed)
        return self.seeds[seed.key]

    def add_seeds(self, pairs: Iterable[tuple[Endpoint, Param]]) -> list[Seed]:
        return [self.add_seed(endpoint, param) for endpoint, param in pairs]

    def record_baseline(self, seed: Seed, *, status: int, length: int, body: str) -> None:
        seed.baseline_status = status
        seed.baseline_length = length
        seed.baseline_hash = hashlib.sha256(body.encode("utf-8", "replace")).hexdigest()
        seed.baseline_body = body[:4096]
        seed.samples += 1
        for token in _TOKEN_RE.findall(body[:8192]):
            if len(token) < 4 and not token.isalnum():
                continue
            self.tokens[token] = self.tokens.get(token, 0) + 1

    def top_tokens(self, limit: int = 40) -> list[str]:
        ordered = sorted(self.tokens.items(), key=lambda pair: (-pair[1], pair[0]))
        return [token for token, _ in ordered[:limit]]

    def structured_tokens(self, limit: int = 40) -> list[str]:
        return [token for token in self.top_tokens(limit * 3) if _STRUCTURED_RE.search(token)][:limit]

    # ------------------------------------------------------------------
    def keep(self, payload: dict[str, Any], *, body: str = "", label: str = "") -> Path | None:
        if len(self.interesting) >= self.limit:
            return None
        entry = dict(payload)
        entry["label"] = label
        digest = hashlib.sha256(json.dumps(entry, sort_keys=True, default=str).encode()).hexdigest()[:16]
        entry["id"] = digest
        self.interesting.append(entry)
        if not self.directory:
            return None
        target = self.directory / "responses" / f"{digest}.txt"
        target.write_text(
            f"# {label}\n{json.dumps(entry, indent=2, sort_keys=True, default=str)}\n\n{body[:20000]}",
            encoding="utf-8",
        )
        return target

    def save_index(self) -> Path | None:
        if not self.directory:
            return None
        index = {
            "seeds": [seed.to_dict() for seed in self.seeds.values()],
            "interesting": self.interesting,
            "tokens": sorted(self.tokens.items(), key=lambda pair: -pair[1])[:200],
        }
        path = self.directory / "index.json"
        path.write_text(json.dumps(index, indent=2, sort_keys=True), encoding="utf-8")
        return path

    def to_dict(self) -> dict[str, Any]:
        return {
            "seeds": len(self.seeds),
            "tokens": len(self.tokens),
            "interesting": len(self.interesting),
            "directory": str(self.directory) if self.directory else "",
        }
