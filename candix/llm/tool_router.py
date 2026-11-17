"""Pick the tool an intent is really asking for."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterable

KEYWORDS: dict[str, tuple[str, ...]] = {
    "recon.crawl": ("crawl", "spider", "links", "pages", "discover", "map the site", "urls"),
    "recon.fingerprint": ("fingerprint", "stack", "server", "headers", "technology", "framework", "banner"),
    "endpoints.list": ("endpoints", "routes", "list", "inventory"),
    "web.probe": ("sensitive", "dotfile", "backup", ".env", ".git", "exposed file", "swagger"),
    "api.spec": ("openapi", "swagger", "spec", "schema", "documentation"),
    "graphql.query": ("graphql", "introspection", "gql", "types"),
    "ws.probe": ("websocket", "ws", "socket", "handshake"),
    "auth.flow": ("login", "session", "cookie", "logout", "authenticate", "mfa"),
    "jwt.inspect": ("jwt", "token", "bearer", "alg", "signature"),
    "oauth.flow": ("oauth", "oidc", "redirect_uri", "authorize", "well-known"),
    "detect.run": ("detect", "scan", "test for", "check for", "vulnerabilities", "xss", "sqli", "ssrf", "idor", "lfi"),
    "fuzz.run": ("fuzz", "mutate", "payloads", "brute", "campaign"),
    "exploit.run": ("exploit", "prove", "verify", "poc", "demonstrate"),
    "facts.add": ("record", "note the fact", "remember", "journal the fact"),
    "goal.prove": ("prove the goal", "conclude", "finish the goal", "answer the goal"),
    "findings.list": ("findings", "issues", "what did we find"),
    "notes.write": ("notes", "summary", "write down"),
    "evidence.capture": ("evidence", "capture", "exchange"),
    "http.request": ("single request", "raw request", "manual request", "one url"),
    "http.batch": ("many urls", "batch", "multiple requests", "in parallel"),
    "http.replay": ("replay", "repeat", "re-send"),
    "payloads.search": ("payload", "wordlist", "seclist"),
    "finish": ("done", "stop", "nothing left", "give up", "finished"),
}

PHASE_HINTS: dict[str, tuple[str, ...]] = {
    "recon": ("recon.crawl", "recon.fingerprint", "web.probe", "api.spec", "graphql.query", "ws.probe", "oauth.flow"),
    "detect": ("detect.run", "auth.flow", "jwt.inspect", "fuzz.run"),
    "exploit": ("exploit.run", "jwt.inspect"),
    "report": ("findings.list", "goal.prove", "notes.write"),
    "triage": ("findings.list", "evidence.capture", "facts.add"),
}

COST_PENALTY = {"detect.run": 0.1, "fuzz.run": 0.2, "exploit.run": 0.15, "recon.crawl": 0.05}


@dataclass
class ToolChoice:
    name: str
    score: float
    reasons: list[str] = field(default_factory=list)

    def explain(self) -> str:
        if not self.reasons:
            return f"{self.name}: no strong signal"
        return f"{self.name} ({self.score:.2f}): " + ", ".join(self.reasons)

    def to_dict(self) -> dict[str, Any]:
        return {"tool": self.name, "score": round(self.score, 3), "reasons": self.reasons}


def _words(text: str) -> set[str]:
    return set(re.findall(r"[a-z0-9_.]+", text.lower()))


def score_tool(name: str, text: str, *, phase: str = "", tools: Iterable[str] = ()) -> ToolChoice:
    lowered = text.lower()
    words = _words(text)
    score = 0.0
    reasons: list[str] = []
    for keyword in KEYWORDS.get(name, ()):
        if " " in keyword:
            if keyword in lowered:
                score += 1.4
                reasons.append(f"phrase '{keyword}'")
        elif keyword in words:
            score += 1.0
            reasons.append(f"word '{keyword}'")
        elif keyword in lowered:
            score += 0.3
    if name in words:
        score += 2.0
        reasons.append("tool named directly")
    if phase and name in PHASE_HINTS.get(phase, ()):
        score += 0.5
        reasons.append(f"fits {phase} phase")
    if name in COST_PENALTY:
        score -= COST_PENALTY[name]
    return ToolChoice(name=name, score=round(score, 3), reasons=reasons[:4])


def route(text: str, *, tools: Iterable[str], phase: str = "", limit: int = 3, min_score: float = 0.4) -> list[ToolChoice]:
    choices = [score_tool(name, text, phase=phase, tools=tools) for name in tools]
    ranked = sorted((item for item in choices if item.score >= min_score), key=lambda item: -item.score)
    return ranked[:limit]


def choose(text: str, *, tools: Iterable[str], phase: str = "", fallback: str = "detect.run", min_score: float = 0.4) -> ToolChoice:
    ranked = route(text, tools=tools, phase=phase, limit=1, min_score=min_score)
    if ranked:
        return ranked[0]
    if fallback in tools:
        return ToolChoice(name=fallback, score=0.0, reasons=["fallback"])
    return ToolChoice(name="", score=0.0, reasons=["no tool matched"])


def ensure_allowed(choice: ToolChoice, *, allowed: Iterable[str], deny: Iterable[str] = ()) -> ToolChoice:
    deny_list = set(deny)
    if choice.name in deny_list:
        return ToolChoice(name="", score=0.0, reasons=[f"{choice.name} is denied"])
    allowed_list = set(allowed)
    if allowed_list and choice.name not in allowed_list:
        return ToolChoice(name="", score=0.0, reasons=[f"{choice.name} is not allowed"])
    return choice


def fallback_chain(text: str, *, tools: Iterable[str], phase: str = "", limit: int = 3) -> list[str]:
    ranked = route(text, tools=tools, phase=phase, limit=limit, min_score=0.2)
    chain = [item.name for item in ranked]
    for phase_default in PHASE_HINTS.get(phase, ()):
        if phase_default in tools and phase_default not in chain:
            chain.append(phase_default)
        if len(chain) >= limit:
            break
    return chain


def arguments_for(tool: str, *, targets: Iterable[str], intents: int = 1) -> dict[str, Any]:
    urls = list(targets)
    if tool == "recon.crawl":
        return {"urls": urls, "max_pages": 40, "depth": 2}
    if tool == "detect.run":
        return {"max_findings": max(5, intents * 5)}
    if tool == "fuzz.run":
        return {"iterations": max(20, intents * 20), "targets": urls}
    if tool == "exploit.run":
        return {"max_attempts": max(1, intents), "min_severity": "high"}
    if tool == "http.batch":
        return {"urls": urls}
    if tool == "web.probe":
        return {"url": urls[0] if urls else ""}
    if tool == "http.request":
        return {"urls": urls}
    if tool == "api.spec":
        return {"urls": urls}
    if tool == "graphql.query":
        return {"urls": urls, "introspect": True}
    if tool in {"auth.flow", "ws.probe", "jwt.inspect"}:
        return {"urls": urls}
    if tool == "findings.list":
        return {"limit": 20}
    if tool in {"notes.write", "facts.add"}:
        return {"text": "", "claim": ""}
    return {}


def ambiguity(choices: Iterable[ToolChoice]) -> str:
    items = list(choices)
    if len(items) < 2:
        return ""
    if abs(items[0].score - items[1].score) < 0.25:
        return f"{items[0].name} and {items[1].name} are nearly tied; prefer the phase fit"
    return ""


def phase_of_tool(tool: str) -> str:
    for phase, names in PHASE_HINTS.items():
        if tool in names:
            return phase
    return "recon"


def describe_router(tools: Iterable[str]) -> str:
    lines = ["| tool | phase | keywords |", "| --- | --- | --- |"]
    for name in sorted(tools):
        lines.append(f"| `{name}` | {phase_of_tool(name)} | {', '.join(KEYWORDS.get(name, ())[:4])} |")
    return "\n".join(lines) + "\n"
