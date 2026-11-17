"""What earlier runs against this kind of target already taught us.

A fresh run should not rediscover that the crawler pays off here and the fuzzer
does not. Priors are kept per target fingerprint, decayed, and never shared
across unrelated hosts.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlsplit

VERSION = 1
DEFAULT_FILENAME = "agent-priors.json"


def fingerprint(targets: Iterable[str]) -> str:
    hosts = set()
    for target in targets:
        try:
            host = urlsplit(str(target)).netloc or str(target)
        except ValueError:
            host = str(target)
        hosts.add(host.lower())
    if not hosts:
        return "unknown"
    return hashlib.sha256("|".join(sorted(hosts)).encode("utf-8")).hexdigest()[:12]


def default_path() -> Path:
    override = os.environ.get("CANDIX_AGENT_PRIORS", "")
    if override:
        return Path(override)
    return Path.home() / ".candix" / DEFAULT_FILENAME


@dataclass
class Prior:
    tool: str
    alpha: float = 1.0
    beta: float = 1.0
    pulls: int = 0
    wins: int = 0
    requests: int = 0
    findings: int = 0
    updated_at: float = field(default_factory=time.time)

    @property
    def mean(self) -> float:
        return self.alpha / (self.alpha + self.beta)

    @property
    def win_rate(self) -> float:
        return self.wins / self.pulls if self.pulls else 0.0

    @property
    def yield_per_100(self) -> float:
        return round(100.0 * self.findings / self.requests, 2) if self.requests else 0.0

    def observe(self, *, reward: float, requests: int = 0, findings: int = 0) -> None:
        reward = max(0.0, min(1.0, reward))
        self.pulls += 1
        self.requests += max(0, requests)
        self.findings += max(0, findings)
        self.alpha += 0.2 + reward
        self.beta += 1.2 - reward
        if reward >= 0.5:
            self.wins += 1
        self.updated_at = time.time()

    def decay(self, *, factor: float = 0.97) -> None:
        self.alpha = 1.0 + (self.alpha - 1.0) * factor
        self.beta = 1.0 + (self.beta - 1.0) * factor

    def to_dict(self) -> dict[str, Any]:
        return {
            "alpha": round(self.alpha, 3),
            "beta": round(self.beta, 3),
            "pulls": self.pulls,
            "wins": self.wins,
            "requests": self.requests,
            "findings": self.findings,
            "mean": round(self.mean, 3),
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, tool: str, payload: dict[str, Any]) -> "Prior":
        return cls(
            tool=tool,
            alpha=float(payload.get("alpha", 1.0)),
            beta=float(payload.get("beta", 1.0)),
            pulls=int(payload.get("pulls", 0)),
            wins=int(payload.get("wins", 0)),
            requests=int(payload.get("requests", 0)),
            findings=int(payload.get("findings", 0)),
            updated_at=float(payload.get("updated_at", time.time())),
        )


@dataclass
class TargetMemory:
    key: str
    runs: int = 0
    tools: dict[str, Prior] = field(default_factory=dict)
    updated_at: float = field(default_factory=time.time)

    def prior(self, tool: str) -> Prior:
        return self.tools.setdefault(tool, Prior(tool=tool))

    def ranked(self) -> list[Prior]:
        return sorted(self.tools.values(), key=lambda item: (-item.mean, -item.pulls))

    def to_dict(self) -> dict[str, Any]:
        return {
            "runs": self.runs,
            "updated_at": self.updated_at,
            "tools": {name: prior.to_dict() for name, prior in self.tools.items()},
        }

    @classmethod
    def from_dict(cls, key: str, payload: dict[str, Any]) -> "TargetMemory":
        memory = cls(key=key, runs=int(payload.get("runs", 0)), updated_at=float(payload.get("updated_at", time.time())))
        for name, block in (payload.get("tools") or {}).items():
            memory.tools[name] = Prior.from_dict(name, block)
        return memory


class Learner:
    """Cross-run priors, seeded into the bandit and updated after each run."""

    def __init__(self, *, path: str | Path | None = None, targets: Iterable[str] = (), enabled: bool = True) -> None:
        self.enabled = enabled
        self.path = Path(path) if path else default_path()
        self.key = fingerprint(targets)
        self.data: dict[str, TargetMemory] = {}
        self.loaded = False
        if enabled:
            self.load()

    # ------------------------------------------------------------ storage
    def load(self) -> bool:
        try:
            if not self.path.is_file():
                self.loaded = True
                return False
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            self.loaded = True
            return False
        if int(payload.get("version", 0)) != VERSION:
            self.loaded = True
            return False
        for key, block in (payload.get("targets") or {}).items():
            self.data[key] = TargetMemory.from_dict(key, block)
        self.loaded = True
        return True

    def save(self) -> str:
        if not self.enabled:
            return ""
        payload = {"version": VERSION, "updated_at": time.time(), "targets": {key: memory.to_dict() for key, memory in self.data.items()}}
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(self.path.suffix + ".tmp")
            tmp.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
            tmp.replace(self.path)
        except OSError:
            return ""
        return str(self.path)

    # ------------------------------------------------------------ queries
    def memory(self, *, create: bool = True) -> TargetMemory | None:
        if not self.enabled:
            return None
        existing = self.data.get(self.key)
        if existing is None and create:
            existing = self.data[self.key] = TargetMemory(key=self.key)
        return existing

    def prior(self, tool: str) -> Prior:
        memory = self.memory()
        if memory is None:
            return Prior(tool=tool)
        return memory.prior(tool)

    def known(self) -> bool:
        memory = self.data.get(self.key)
        return bool(memory and memory.tools)

    def ranking(self, *, limit: int = 10) -> list[Prior]:
        memory = self.memory(create=False)
        return memory.ranked()[:limit] if memory else []

    def expected_reward(self, tool: str) -> float:
        return self.prior(tool).mean

    # ------------------------------------------------------------ writes
    def record(self, tool: str, *, reward: float, requests: int = 0, findings: int = 0) -> Prior:
        prior = self.prior(tool)
        prior.observe(reward=reward, requests=requests, findings=findings)
        return prior

    def record_run(self, outcomes: dict[str, dict[str, float]]) -> int:
        memory = self.memory()
        if memory is None:
            return 0
        memory.runs += 1
        memory.updated_at = time.time()
        count = 0
        for tool, block in outcomes.items():
            self.record(
                tool,
                reward=float(block.get("reward", 0.0)),
                requests=int(block.get("requests", 0)),
                findings=int(block.get("findings", 0)),
            )
            count += 1
        return count

    def decay(self, *, factor: float = 0.97) -> None:
        memory = self.memory(create=False)
        if memory is None:
            return
        for prior in memory.tools.values():
            prior.decay(factor=factor)

    def seed_bandit(self, bandit: Any, *, strength: float = 1.0) -> int:
        """Copy priors into a bandit, so turn one already prefers what worked."""

        memory = self.memory(create=False)
        if memory is None:
            return 0
        seeded = 0
        for name, prior in memory.tools.items():
            arm = getattr(bandit, "arms", {}).get(name)
            if arm is None or prior.pulls < 1:
                continue
            arm.alpha = max(arm.alpha, 1.0 + (prior.alpha - 1.0) * strength)
            arm.beta = max(arm.beta, 1.0 + (prior.beta - 1.0) * strength)
            arm.pulls = max(arm.pulls, int(prior.pulls * strength))
            arm.reward = max(arm.reward, prior.mean * arm.pulls)
            seeded += 1
        return seeded

    def outcomes(self, tool_stats: Iterable[dict[str, Any]]) -> dict[str, dict[str, float]]:
        result: dict[str, dict[str, float]] = {}
        for stat in tool_stats:
            name = str(stat.get("tool", ""))
            if not name:
                continue
            calls = float(stat.get("calls", 0) or 0)
            findings = float(stat.get("findings", 0) or 0)
            errors = float(stat.get("errors", 0) or 0)
            if not calls:
                continue
            reward = min(1.0, findings / max(1.0, calls)) * (1.0 - min(1.0, errors / calls))
            result[name] = {"reward": round(reward, 3), "requests": calls, "findings": findings}
        return result

    # ------------------------------------------------------------ reporting
    def summary(self) -> str:
        memory = self.memory(create=False)
        if memory is None or not memory.tools:
            return "no priors for this target"
        best = memory.ranked()[0]
        return f"{len(memory.tools)} tool prior(s) over {memory.runs} run(s); best {best.tool} ({best.mean:.2f})"

    def markdown(self) -> str:
        lines = ["## Priors", "", self.summary(), ""]
        if not self.known():
            return "\n".join(lines)
        lines += ["| tool | mean | pulls | findings/100 req |", "| --- | --- | --- | --- |"]
        for prior in self.ranking(limit=12):
            lines.append(f"| {prior.tool} | {prior.mean:.2f} | {prior.pulls} | {prior.yield_per_100} |")
        return "\n".join(lines) + "\n"

    def to_dict(self) -> dict[str, Any]:
        memory = self.memory(create=False)
        return {
            "enabled": self.enabled,
            "target": self.key,
            "known": self.known(),
            "summary": self.summary(),
            "priors": [prior.to_dict() | {"tool": prior.tool, "win_rate": round(prior.win_rate, 3), "yield_per_100": prior.yield_per_100} for prior in self.ranking(limit=20)],
            "runs": memory.runs if memory else 0,
        }


def blend(local: Learner, remote: Learner, *, weight: float = 0.5) -> dict[str, float]:
    """Average two learners' beliefs, for the case where host names change."""

    names = {prior.tool for prior in local.ranking(limit=50)} | {prior.tool for prior in remote.ranking(limit=50)}
    return {name: round(weight * local.expected_reward(name) + (1 - weight) * remote.expected_reward(name), 3) for name in sorted(names)}
