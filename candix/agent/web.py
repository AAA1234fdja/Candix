"""Shared request plumbing for the agent's web-facing tools."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any, Iterable
from urllib.parse import urlsplit, urlunsplit

from candix.analysis.html import HTMLDocument
from candix.core.log import get_logger
from candix.net.url import URL, join_url

log = get_logger("candix.agent.web")

_INTERESTING_HEADERS = (
    "content-type",
    "server",
    "location",
    "set-cookie",
    "x-powered-by",
    "content-length",
    "allow",
    "access-control-allow-origin",
    "x-frame-options",
    "content-security-policy",
)


@dataclass
class Fetch:
    url: str
    method: str = "GET"
    status: int = 0
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    elapsed: float = 0.0
    error: str = ""

    @property
    def ok(self) -> bool:
        return not self.error and 0 < self.status < 400

    @property
    def content_type(self) -> str:
        return self.headers.get("content-type", "").split(";")[0].strip().lower()

    @property
    def length(self) -> int:
        return len(self.body)

    def json(self) -> Any:
        try:
            return json.loads(self.body)
        except (ValueError, TypeError):
            return None

    def doc(self, *, base_url: str = "") -> HTMLDocument:
        return HTMLDocument(self.body, base_url=base_url or self.url)

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "method": self.method,
            "status": self.status,
            "headers": self.headers,
            "length": self.length,
            "elapsed_ms": round(self.elapsed * 1000, 1),
            "error": self.error,
            "body": self.body[:4000],
        }

    def summary(self) -> str:
        if self.error:
            return f"{self.method} {self.url} -> error: {self.error[:80]}"
        return f"{self.method} {self.url} -> {self.status} ({self.length} bytes)"


def session_for(ctx: Any) -> Any:
    from candix.agent.toolset import _session

    return _session(ctx)


def fetch(
    ctx: Any,
    url: str,
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: str | None = None,
    json_body: Any = None,
    follow: bool = False,
    max_bytes: int = 60000,
    timeout: float | None = None,
) -> Fetch:
    """One guarded request. Returns a :class:`Fetch` instead of raising."""

    record = Fetch(url=url, method=method.upper())
    try:
        ctx.guard.enforce(url, method=record.method)
    except Exception as error:
        record.error = f"scope: {error}"
        return record
    kwargs: dict[str, Any] = {
        "headers": dict(headers or {}),
        "allow_redirects": follow,
        "tag": "agent",
    }
    if timeout:
        kwargs["timeout"] = timeout
    if json_body is not None:
        kwargs["json_body"] = json_body
    elif body is not None:
        kwargs["data"] = body
    started = time.monotonic()
    try:
        response = session_for(ctx).request(record.method, url, **kwargs)
    except Exception as error:
        record.error = f"request failed: {error}"
        record.elapsed = time.monotonic() - started
        ctx.telemetry.increment("web.errors")
        return record
    record.elapsed = time.monotonic() - started
    record.status = int(getattr(response, "status", 0) or 0)
    record.url = str(getattr(response, "url", url) or url)
    record.headers = header_subset(response)
    text = getattr(response, "text", "") or ""
    record.body = text[:max_bytes]
    ctx.telemetry.increment("web.requests")
    assets = ctx.state.get("assets")
    if assets is not None:
        try:
            assets.add_endpoint(record.method, url, status=record.status)
        except Exception:
            pass
    return record


def fetch_many(
    ctx: Any,
    urls: Iterable[str],
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    limit: int = 40,
    stop_when: Any = None,
) -> list[Fetch]:
    results: list[Fetch] = []
    for url in list(urls)[:limit]:
        record = fetch(ctx, url, method=method, headers=headers)
        results.append(record)
        if stop_when is not None and stop_when(record):
            break
    return results


def header_subset(response: Any) -> dict[str, str]:
    headers = getattr(response, "headers", None)
    if headers is None:
        return {}
    output: dict[str, str] = {}
    for name in _INTERESTING_HEADERS:
        value = headers.get(name)
        if value:
            output[name] = str(value)[:300]
    return output


def join(base: str, path: str) -> str:
    try:
        return join_url(URL.parse(base), path).render()
    except Exception:
        return base.rstrip("/") + "/" + path.lstrip("/")


def origin_of(url: str) -> str:
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, "", "", ""))


def path_of(url: str) -> str:
    parts = urlsplit(url)
    return parts.path or "/"


def normalize_path(path: str) -> str:
    if not path.startswith("/"):
        path = "/" + path
    return path


def status_class(status: int) -> str:
    if status == 0:
        return "error"
    return f"{status // 100}xx"


def looks_like_soft_404(record: Fetch, reference: Fetch | None = None) -> bool:
    """Detect catch-all handlers that answer 200 to everything."""

    if record.status != 200 or reference is None:
        return False
    if reference.status != 200:
        return False
    difference = abs(record.length - reference.length)
    return difference <= max(12, reference.length // 50)


def is_json_response(record: Fetch) -> bool:
    if "json" in record.content_type:
        return True
    text = record.body.lstrip()[:1]
    return text in {"{", "["} and record.json() is not None


def extract_links(record: Fetch, *, limit: int = 60) -> list[str]:
    if "html" not in record.content_type and "<a" not in record.body.lower():
        return []
    try:
        document = record.doc()
    except Exception:
        return []
    links: list[str] = []
    try:
        for link in document.links():
            href = getattr(link, "href", link) if not isinstance(link, str) else link
            if href and href not in links:
                links.append(str(href))
    except Exception:
        pass
    try:
        for form in document.forms():
            action = getattr(form, "action", "")
            if action and action not in links:
                links.append(str(action))
    except Exception:
        pass
    return links[:limit]


def extract_title(record: Fetch) -> str:
    text = record.body
    start = text.lower().find("<title")
    if start < 0:
        return ""
    open_end = text.find(">", start)
    close = text.lower().find("</title>", open_end)
    if open_end < 0 or close < 0:
        return ""
    return " ".join(text[open_end + 1 : close].split())[:160]


def probe(
    ctx: Any,
    base: str,
    paths: Iterable[str],
    *,
    reference: Fetch | None = None,
    limit: int = 60,
) -> list[dict[str, Any]]:
    """Status matrix for candidate paths, skipping soft-404 noise."""

    rows: list[dict[str, Any]] = []
    reference = reference or fetch(ctx, base)
    for path in list(paths)[:limit]:
        url = join(base, normalize_path(path))
        record = fetch(ctx, url)
        if record.error:
            continue
        soft = looks_like_soft_404(record, reference)
        if soft:
            continue
        if record.status in {404, 410}:
            continue
        rows.append(
            {
                "path": normalize_path(path),
                "url": url,
                "status": record.status,
                "length": record.length,
                "content_type": record.content_type,
                "title": extract_title(record),
            }
        )
    return rows


def form_fields(record: Fetch) -> list[dict[str, Any]]:
    """Inputs from the first form on the page, ready to be filled."""

    try:
        document = record.doc()
        forms = list(document.forms())
    except Exception:
        return []
    if not forms:
        return []
    form = forms[0]
    fields: list[dict[str, Any]] = []
    for field in getattr(form, "inputs", []) or []:
        fields.append(
            {
                "name": getattr(field, "name", ""),
                "type": str(getattr(field, "type", "text")),
                "value": getattr(field, "value", ""),
                "required": bool(getattr(field, "required", False)),
            }
        )
    return [field for field in fields if field["name"]]


def csrf_token(record: Fetch) -> tuple[str, str]:
    """Find a CSRF token in a form or a meta tag."""

    for field in form_fields(record):
        name = str(field.get("name", "")).lower()
        if any(marker in name for marker in ("csrf", "token", "authenticity", "_token")):
            return field["name"], str(field.get("value", ""))
    lowered = record.body.lower()
    marker = 'name="csrf-token"'
    position = lowered.find(marker)
    if position < 0:
        return "", ""
    start = record.body.find('content="', position)
    if start < 0:
        return "", ""
    end = record.body.find('"', start + 9)
    return "X-CSRF-Token", record.body[start + 9 : end]
