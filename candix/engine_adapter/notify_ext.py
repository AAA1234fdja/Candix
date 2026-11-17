"""Notify extended — engine/notify canales completos en Python.

Soporta DingTalk, Feishu, WeCom, Webhook, Telegram, Email igual que Go.
"""

from __future__ import annotations

import smtplib
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from email.mime.text import MIMEText
from typing import Any

try:
    import httpx  # type: ignore
    HAS_HTTPX = True
except ImportError:
    httpx = None  # type: ignore
    HAS_HTTPX = False


@dataclass
class NotifyMessage:
    title: str
    body: str
    severity: str = "info"
    findings: list[dict[str, Any]] = field(default_factory=list)
    url: str = ""


class Channel(ABC):
    @abstractmethod
    def kind(self) -> str: ...
    @abstractmethod
    def validate(self, cfg: dict[str, Any]) -> None: ...
    @abstractmethod
    def send(self, cfg: dict[str, Any], msg: NotifyMessage) -> int: ...

    def default_rate_per_min(self) -> int:
        return 20
    def secret_keys(self) -> list[str]:
        return []
    def destination_keys(self) -> list[str]:
        return []


class WebhookChannel(Channel):
    def kind(self) -> str: return "webhook"
    def validate(self, cfg: dict[str, Any]) -> None:
        if not cfg.get("url"):
            raise ValueError("webhook url is required")
    def send(self, cfg: dict[str, Any], msg: NotifyMessage) -> int:
        if not HAS_HTTPX:
            return 0
        url = str(cfg.get("url", ""))
        headers = cfg.get("headers") or {}
        payload = {"title": msg.title, "body": msg.body, "severity": msg.severity, "findings": msg.findings}
        try:
            with httpx.Client(timeout=10) as c:  # type: ignore
                r = c.post(url, json=payload, headers=headers)
                return 1 if r.status_code < 300 else 0
        except Exception:
            return 0


class DingTalkChannel(Channel):
    def kind(self) -> str: return "dingtalk"
    def validate(self, cfg: dict[str, Any]) -> None:
        if not cfg.get("webhook"):
            raise ValueError("dingtalk webhook is required")
    def secret_keys(self) -> list[str]: return ["secret"]
    def destination_keys(self) -> list[str]: return ["webhook"]
    def send(self, cfg: dict[str, Any], msg: NotifyMessage) -> int:
        if not HAS_HTTPX:
            return 0
        url = str(cfg.get("webhook", ""))
        try:
            payload = {"msgtype": "markdown", "markdown": {"title": msg.title, "text": f"### {msg.title}\n{msg.body}"}}
            with httpx.Client(timeout=10) as c:  # type: ignore
                r = c.post(url, json=payload)
                return 1 if r.status_code < 300 else 0
        except Exception:
            return 0


class FeishuChannel(Channel):
    def kind(self) -> str: return "feishu"
    def validate(self, cfg: dict[str, Any]) -> None:
        if not cfg.get("webhook"):
            raise ValueError("feishu webhook is required")
    def send(self, cfg: dict[str, Any], msg: NotifyMessage) -> int:
        if not HAS_HTTPX:
            return 0
        url = str(cfg.get("webhook", ""))
        try:
            payload = {"msg_type": "text", "content": {"text": f"{msg.title}\n{msg.body}"}}
            with httpx.Client(timeout=10) as c:  # type: ignore
                r = c.post(url, json=payload)
                return 1 if r.status_code < 300 else 0
        except Exception:
            return 0


class TelegramChannel(Channel):
    def kind(self) -> str: return "telegram"
    def validate(self, cfg: dict[str, Any]) -> None:
        if not cfg.get("bot_token") or not cfg.get("chat_id"):
            raise ValueError("telegram bot_token and chat_id required")
    def secret_keys(self) -> list[str]: return ["bot_token"]
    def destination_keys(self) -> list[str]: return ["chat_id"]
    def default_rate_per_min(self) -> int: return 20
    def send(self, cfg: dict[str, Any], msg: NotifyMessage) -> int:
        if not HAS_HTTPX:
            return 0
        token = cfg.get("bot_token")
        chat_id = cfg.get("chat_id")
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        try:
            with httpx.Client(timeout=10) as c:  # type: ignore
                r = c.post(url, json={"chat_id": chat_id, "text": f"*{msg.title}*\n{msg.body}", "parse_mode": "Markdown"})
                return 1 if r.status_code < 300 else 0
        except Exception:
            return 0


class EmailChannel(Channel):
    def kind(self) -> str: return "email"
    def validate(self, cfg: dict[str, Any]) -> None:
        if not cfg.get("to") or not cfg.get("smtp_host"):
            raise ValueError("email to and smtp_host required")
    def secret_keys(self) -> list[str]: return ["password"]
    def send(self, cfg: dict[str, Any], msg: NotifyMessage) -> int:
        try:
            host = str(cfg.get("smtp_host", ""))
            port = int(cfg.get("smtp_port", 587))
            user = str(cfg.get("username", ""))
            pwd = str(cfg.get("password", ""))
            to = cfg.get("to")
            if isinstance(to, str):
                to = [to]
            mime = MIMEText(msg.body, "plain", "utf-8")
            mime["Subject"] = msg.title
            mime["From"] = user or "candix@localhost"
            mime["To"] = ", ".join(to)  # type: ignore
            with smtplib.SMTP(host, port, timeout=10) as s:
                if cfg.get("tls"):
                    s.starttls()
                if user and pwd:
                    s.login(user, pwd)
                s.send_message(mime)
            return 1
        except Exception:
            return 0


REGISTRY: dict[str, Channel] = {
    "webhook": WebhookChannel(),
    "dingtalk": DingTalkChannel(),
    "feishu": FeishuChannel(),
    "telegram": TelegramChannel(),
    "email": EmailChannel(),
}

def get_channel(kind: str) -> Channel | None:
    return REGISTRY.get(kind)

def valid_kind(kind: str) -> bool:
    return kind in REGISTRY

def kinds() -> list[str]:
    return sorted(REGISTRY.keys())

class NotifyDispatcher:
    def __init__(self, channels: list[dict[str, Any]] | None = None):
        self.channels = channels or []
        self._rate: dict[str, float] = {}

    def dispatch(self, msg: NotifyMessage) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for cfg in self.channels:
            kind = str(cfg.get("kind", "webhook"))
            ch = get_channel(kind)
            if not ch:
                results.append({"kind": kind, "ok": False, "error": "unknown channel"})
                continue
            # rate limit
            key = f"{kind}:{cfg.get('url', cfg.get('webhook', ''))}"
            now = time.time()
            if now - self._rate.get(key, 0) < 60 / max(1, ch.default_rate_per_min()):
                results.append({"kind": kind, "ok": False, "error": "rate limited"})
                continue
            try:
                ch.validate(cfg)
                n = ch.send(cfg, msg)
                self._rate[key] = now
                results.append({"kind": kind, "ok": n > 0, "delivered": n})
            except Exception as e:
                results.append({"kind": kind, "ok": False, "error": str(e)})
        return results
