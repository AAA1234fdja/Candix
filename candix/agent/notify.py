"""Deliver run results to the places people actually watch."""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable

from candix.agent.knowledge import summarize
from candix.core.severity import Severity, _SEVERITY_RANK

SEVERITY_ORDER = ("info", "low", "medium", "high", "critical")


def severity_rank(value: Any) -> int:
    """Rank a severity string, tolerating unknown values."""

    text = str(getattr(value, "value", value) or "info").strip().lower()
    for member in Severity:
        if member.value == text:
            return _SEVERITY_RANK[member]
    return _SEVERITY_RANK[Severity.INFO]


@dataclass
class Message:
    title: str
    body: str
    severity: str = "info"
    fields: dict[str, str] = field(default_factory=dict)
    findings: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"title": self.title, "body": self.body, "severity": self.severity, "fields": self.fields, "findings": self.findings[:20]}

    def markdown(self) -> str:
        lines = [f"**{self.title}**", "", self.body.strip(), ""]
        for key, value in self.fields.items():
            lines.append(f"- {key}: {value}")
        for finding in self.findings[:10]:
            lines.append(f"- [{finding.get('severity', '?')}] {finding.get('title', '')} — {finding.get('url', '')}")
        return "\n".join(lines).rstrip() + "\n"


@dataclass
class Delivery:
    channel: str
    ok: bool
    detail: str = ""
    status: int = 0
    attempts: int = 1

    def to_dict(self) -> dict[str, Any]:
        return {"channel": self.channel, "ok": self.ok, "detail": self.detail, "status": self.status, "attempts": self.attempts}


class Channel:
    name = "channel"

    def send(self, message: Message) -> Delivery:
        raise NotImplementedError


class ConsoleChannel(Channel):
    name = "console"

    def __init__(self, writer: Callable[[str], None] | None = None) -> None:
        self.writer = writer or print

    def send(self, message: Message) -> Delivery:
        self.writer(message.markdown())
        return Delivery(self.name, True, "printed")


class FileChannel(Channel):
    name = "file"

    def __init__(self, path: str) -> None:
        self.path = path

    def send(self, message: Message) -> Delivery:
        try:
            with open(self.path, "a", encoding="utf-8") as handle:
                handle.write(json.dumps({"at": time.time(), **message.to_dict()}) + "\n")
        except OSError as error:
            return Delivery(self.name, False, str(error))
        return Delivery(self.name, True, self.path)


class WebhookChannel(Channel):
    name = "webhook"

    def __init__(self, url: str, *, headers: dict[str, str] | None = None, timeout: float = 10.0, retries: int = 2) -> None:
        self.url = url
        self.headers = {"Content-Type": "application/json", **(headers or {})}
        self.timeout = timeout
        self.retries = retries

    def payload(self, message: Message) -> dict[str, Any]:
        return message.to_dict()

    def send(self, message: Message) -> Delivery:
        body = json.dumps(self.payload(message)).encode("utf-8")
        last = "no attempt"
        for attempt in range(1, self.retries + 2):
            request = urllib.request.Request(self.url, data=body, headers=self.headers, method="POST")
            try:
                with urllib.request.urlopen(request, timeout=self.timeout) as response:
                    return Delivery(self.name, True, f"HTTP {response.status}", response.status, attempt)
            except urllib.error.HTTPError as error:
                last = f"HTTP {error.code}"
                if error.code < 500:
                    return Delivery(self.name, False, last, error.code, attempt)
            except (urllib.error.URLError, OSError) as error:
                last = str(error)
            time.sleep(min(2.0, 0.25 * attempt))
        return Delivery(self.name, False, last, 0, self.retries + 1)


class SlackWebhook(WebhookChannel):
    name = "slack"

    def payload(self, message: Message) -> dict[str, Any]:
        colour = {"critical": "danger", "high": "danger", "medium": "warning"}.get(message.severity, "good")
        return {
            "attachments": [
                {
                    "color": colour,
                    "title": message.title,
                    "text": message.body + "\n" + "\n".join(f"• {key}: {value}" for key, value in message.fields.items()),
                    "fields": [
                        {"title": finding.get("severity", "?"), "value": f"{finding.get('title', '')} — {finding.get('url', '')}", "short": False}
                        for finding in message.findings[:5]
                    ],
                }
            ]
        }


class DiscordWebhook(WebhookChannel):
    name = "discord"

    def payload(self, message: Message) -> dict[str, Any]:
        colour = {"critical": 0xE01B24, "high": 0xE01B24, "medium": 0xFF7800}.get(message.severity, 0x2EC27E)
        return {"embeds": [{"title": message.title[:250], "description": message.body[:1800], "color": colour}]}


class CommandChannel(Channel):
    """Run a local command with the message on stdin; useful for pager bridges.

    The command is gated by :class:`candix.agent.intercept.CommandGate` before it
    runs: an interpreter, a launcher or a destructive command is refused even
    when the operator configured the channel.
    """

    name = "command"

    def __init__(self, argv: list[str], *, timeout: float = 20.0, allowed_prefixes: Iterable[str] = (), max_risk: int = 70, gate: Any = None) -> None:
        self.argv = argv
        self.timeout = timeout
        self.gate = gate
        self.allowed_prefixes = tuple(allowed_prefixes)
        self.max_risk = max_risk

    def _decide(self) -> Any:
        from candix.agent.intercept import CommandGate

        gate = self.gate or CommandGate(allowed_prefixes=self.allowed_prefixes, max_risk=self.max_risk)
        return gate.check(" ".join(self.argv))

    def send(self, message: Message) -> Delivery:
        import subprocess

        decision = self._decide()
        if not decision.allowed:
            return Delivery(self.name, False, f"blocked: {decision.reason}")
        try:
            done = subprocess.run(
                self.argv,
                input=message.markdown().encode("utf-8"),
                capture_output=True,
                timeout=self.timeout,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            return Delivery(self.name, False, str(error))
        return Delivery(self.name, done.returncode == 0, f"exit {done.returncode}", done.returncode)


@dataclass
class Router:
    channels: list[Channel] = field(default_factory=list)
    min_severity: str = "info"
    dedupe_window: float = 3600.0
    dry_run: bool = False
    _sent: dict[str, float] = field(default_factory=dict, init=False)

    def add(self, channel: Channel) -> None:
        self.channels.append(channel)

    def keeps(self, message: Message) -> bool:
        return severity_rank(message.severity) >= severity_rank(self.min_severity)

    def fingerprint(self, message: Message) -> str:
        parts = [message.title, message.severity, *sorted(str(item.get("id", item.get("title", ""))) for item in message.findings)]
        return "|".join(parts)

    def recently_sent(self, message: Message, *, now: float | None = None) -> bool:
        stamp = self._sent.get(self.fingerprint(message))
        if not stamp:
            return False
        return ((now or time.time()) - stamp) < self.dedupe_window

    def dispatch(self, message: Message) -> list[Delivery]:
        if not self.keeps(message):
            return [Delivery("router", True, f"below {self.min_severity} threshold")]
        if self.recently_sent(message):
            return [Delivery("router", True, "suppressed as a duplicate")]
        if self.dry_run:
            return [Delivery(channel.name, True, "dry run") for channel in self.channels]
        deliveries = [channel.send(message) for channel in self.channels]
        if any(item.ok for item in deliveries):
            self._sent[self.fingerprint(message)] = time.time()
        return deliveries


def build_message(result: Any, *, title: str | None = None) -> Message:
    findings = list(getattr(result, "findings", []) or [])
    severity = max((str(item.get("severity", "info")).lower() for item in findings), key=severity_rank, default="info")
    goal = str(getattr(getattr(result, "goal", ""), "statement", ""))
    stop = str(getattr(result, "stop_reason", "") or "")
    body_lines = [f"Goal: {goal}", f"Stop reason: {stop or 'completed'}"]
    for finding in findings[:5]:
        body_lines.append(f"- {summarize(finding)}")
    return Message(
        title=title or f"Candix agent run: {len(findings)} finding(s), worst {severity}",
        body="\n".join(body_lines),
        severity=severity,
        fields={
            "findings": str(len(findings)),
            "proofs": str(len(getattr(result, "proofs", []) or [])),
            "intents": str(len(getattr(result, "intents", []) or [])),
        },
        findings=findings,
    )


def from_config(config: dict[str, Any]) -> Router:
    router = Router(min_severity=str(config.get("min_severity", "info")), dry_run=bool(config.get("dry_run", False)))
    if config.get("console", True):
        router.add(ConsoleChannel())
    if config.get("file"):
        router.add(FileChannel(str(config["file"])))
    webhook = str(config.get("webhook", ""))
    if webhook:
        router.add(WebhookChannel(webhook, headers=config.get("headers") or {}))
    if config.get("slack"):
        router.add(SlackWebhook(str(config["slack"])))
    if config.get("discord"):
        router.add(DiscordWebhook(str(config["discord"])))
    if config.get("command"):
        router.add(CommandChannel([str(item) for item in config["command"]]))
    return router


def should_notify(findings: Iterable[dict[str, Any]], *, min_severity: str = "high", new_only: bool = True) -> bool:
    for finding in findings:
        if new_only and finding.get("baseline"):
            continue
        if severity_rank(str(finding.get("severity", "info"))) >= severity_rank(min_severity):
            return True
    return False


def summarize_deliveries(deliveries: Iterable[Delivery]) -> str:
    items = list(deliveries)
    ok = sum(1 for item in items if item.ok)
    return f"{ok}/{len(items)} channel(s) delivered"


def redact_message(message: Message) -> Message:
    def scrub(text: str) -> str:
        import re

        text = re.sub(r"(?i)(authorization\s*[:=]\s*)(?:bearer\s+|basic\s+)?\S+", r"\1[redacted]", text)
        text = re.sub(r"(?i)(cookie\s*[:=]\s*)[^\n]+", r"\1[redacted]", text)
        text = re.sub(r"(?i)(bearer\s+)[A-Za-z0-9._\-]+", r"\1[redacted]", text)
        text = re.sub(r"(?i)((?:api[_-]?key|token)\s*[:=]\s*)\S+", r"\1[redacted]", text)
        text = re.sub(r"(?i)(password=)[^&\s]+", r"\1[redacted]", text)
        return text

    return Message(
        title=scrub(message.title),
        body=scrub(message.body),
        severity=message.severity,
        fields={key: scrub(value) for key, value in message.fields.items()},
        findings=message.findings,
    )
