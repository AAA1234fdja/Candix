"""Generic signed webhook."""

from __future__ import annotations

import time
from typing import Any

from candix import VERSION
from candix.integrations.base import Integration, Notification, register


@register("webhook")
class WebhookIntegration(Integration):
    """POSTs the notification as JSON, optionally signing the raw body."""

    def build_payload(self, notification: Notification) -> dict[str, Any]:
        return {
            "source": "candix",
            "version": VERSION,
            "sent_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "event": "scan.completed",
            "notification": notification.to_dict(),
        }

    def request_headers(self) -> dict[str, str]:
        headers = super().request_headers()
        if self.secret:
            body = b""  # signature computed by the caller through sign()
            headers["X-Candix-Signature-Alg"] = "hmac-sha256"
        headers["X-Candix-Version"] = VERSION
        return headers

    def sign(self, notification: Notification) -> str:
        import json

        return self.signature(json.dumps(self.build_payload(notification), default=str).encode("utf-8"))


@register("slack")
class SlackIntegration(Integration):
    """Slack incoming webhook or chat.postMessage payload."""

    def build_payload(self, notification: Notification) -> dict[str, Any]:
        color = {
            "critical": "#b91c1c",
            "high": "#dc2626",
            "medium": "#d97706",
            "low": "#0284c7",
            "info": "#475569",
        }.get(notification.severity, "#475569")
        fields = [
            {"type": "mrkdwn", "text": f"*{severity.title()}*: {count}"}
            for severity, count in (notification.summary.get("counts") or {}).items()
            if severity != "total" and count
        ]
        blocks: list[dict[str, Any]] = [
            {"type": "header", "text": {"type": "plain_text", "text": notification.title[:150]}},
            {"type": "section", "text": {"type": "mrkdwn", "text": notification.body[:2800] or " "}},
        ]
        if fields:
            blocks.append({"type": "section", "fields": fields[:10]})
        if notification.link:
            blocks.append(
                {
                    "type": "actions",
                    "elements": [
                        {
                            "type": "button",
                            "text": {"type": "plain_text", "text": "Open report"},
                            "url": notification.link,
                        }
                    ],
                }
            )
        return {
            "text": notification.title,
            "attachments": [
                {
                    "color": color,
                    "fields": [
                        {"title": item["text"].split("*")[1], "value": str(item["text"].split(": ")[-1]), "short": True}
                        for item in fields
                    ],
                    "footer": f"candix/{VERSION}",
                }
            ],
            "blocks": blocks,
        }


@register("teams")
class TeamsIntegration(Integration):
    """Microsoft Teams incoming webhook using an adaptive card."""

    def build_payload(self, notification: Notification) -> dict[str, Any]:
        counts = notification.summary.get("counts") or {}
        facts = [
            {"title": "Scan", "value": str(notification.summary.get("scan_id", ""))},
            {"title": "Critical", "value": str(counts.get("critical", 0))},
            {"title": "High", "value": str(counts.get("high", 0))},
            {"title": "Medium", "value": str(counts.get("medium", 0))},
            {"title": "Low", "value": str(counts.get("low", 0))},
        ]
        elements: list[dict[str, Any]] = [
            {"type": "TextBlock", "text": notification.title, "weight": "Bolder", "wrap": True},
            {"type": "FactSet", "facts": facts},
            {"type": "TextBlock", "text": notification.body[:2000], "wrap": True},
        ]
        if notification.link:
            elements.append({"type": "Action.OpenUrl", "title": "Open report", "url": notification.link})
        return {
            "type": "message",
            "attachments": [
                {
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "content": {
                        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                        "type": "AdaptiveCard",
                        "version": "1.4",
                        "body": elements,
                    },
                }
            ],
        }


@register("pagerduty")
class PagerDutyIntegration(Integration):
    """PagerDuty Events API v2 trigger for critical findings only."""

    def build_payload(self, notification: Notification) -> dict[str, Any]:
        counts = notification.summary.get("counts") or {}
        return {
            "routing_key": self.token,
            "event_action": "trigger",
            "dedup_key": str(notification.summary.get("scan_id", "")) or "candix",
            "payload": {
                "summary": notification.title[:1024],
                "source": "candix",
                "severity": notification.severity if notification.severity in {"critical", "error", "warning", "info"} else "error",
                "custom_details": {
                    "counts": counts,
                    "risk_score": notification.summary.get("risk_score", 0),
                    "report": notification.link,
                    "body": notification.body[:4000],
                },
            },
        }


@register("discord")
class DiscordIntegration(Integration):
    """Discord channel webhook."""

    def build_payload(self, notification: Notification) -> dict[str, Any]:
        color = {
            "critical": 0xB91C1C,
            "high": 0xDC2626,
            "medium": 0xD97706,
            "low": 0x0284C7,
            "info": 0x475569,
        }.get(notification.severity, 0x475569)
        return {
            "username": "candix",
            "embeds": [
                {
                    "title": notification.title[:256],
                    "description": notification.body[:4000],
                    "color": color,
                    "footer": {"text": f"candix/{VERSION}"},
                    "url": notification.link or None,
                }
            ],
        }


@register("mattermost")
class MattermostIntegration(Integration):
    """Mattermost incoming webhook (Slack-compatible attachments)."""

    def build_payload(self, notification: Notification) -> dict[str, Any]:
        counts = notification.summary.get("counts") or {}
        return {
            "text": notification.title,
            "attachments": [
                {
                    "title": notification.title[:200],
                    "text": notification.body[:3000],
                    "color": {"critical": "#b91c1c", "high": "#dc2626", "medium": "#d97706"}.get(notification.severity, "#0284c7"),
                    "fields": [
                        {"short": True, "title": "scan", "value": str(notification.summary.get("scan_id", ""))},
                        {"short": True, "title": "total", "value": str(counts.get("total", 0))},
                    ],
                }
            ],
        }
