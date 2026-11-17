"""Files the operator hands the agent, kept inside a token budget."""

from __future__ import annotations

import hashlib
import json
import mimetypes
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from candix.llm.tokens import estimate_text, truncate_text

TEXT_SUFFIXES = {
    ".txt": "text",
    ".md": "markdown",
    ".rst": "markdown",
    ".log": "log",
    ".json": "json",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".toml": "toml",
    ".ini": "config",
    ".conf": "config",
    ".csv": "csv",
    ".xml": "xml",
    ".html": "html",
    ".htm": "html",
    ".http": "http",
    ".har": "har",
    ".py": "code",
    ".js": "code",
    ".ts": "code",
    ".go": "code",
    ".sh": "code",
    ".sql": "sql",
    ".pem": "key",
    ".crt": "certificate",
}

SECRET_PATTERNS = (
    re.compile(r"(?i)-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{16,}"),
    re.compile(r"(?i)AKIA[0-9A-Z]{16}"),
    re.compile(r"ghp_[A-Za-z0-9]{30,}"),
)


@dataclass
class Attachment:
    name: str
    text: str
    kind: str = "text"
    size: int = 0
    sha256: str = ""
    truncated: bool = False
    source: str = ""

    @property
    def tokens(self) -> int:
        return estimate_text(self.text)

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "kind": self.kind, "size": self.size, "tokens": self.tokens, "truncated": self.truncated, "source": self.source}

    def cite(self) -> str:
        return f"[attach:{self.name}#{self.sha256[:8]}]"


def sniff_kind(name: str, text: str) -> str:
    suffix = Path(name).suffix.lower()
    if suffix in TEXT_SUFFIXES:
        return TEXT_SUFFIXES[suffix]
    mime, _ = mimetypes.guess_type(name)
    if mime and mime.startswith("text/"):
        return "text"
    stripped = (text or "").lstrip()
    if stripped.startswith("{") or stripped.startswith("["):
        return "json"
    if stripped.startswith("<?xml") or stripped.startswith("<"):
        return "xml"
    return "text"


def html_to_text(body: str) -> str:
    body = re.sub(r"(?is)<(script|style).*?</\1>", " ", body)
    body = re.sub(r"(?s)<[^>]+>", " ", body)
    body = re.sub(r"&nbsp;?", " ", body)
    body = re.sub(r"&amp;", "&", body)
    body = re.sub(r"&lt;", "<", body)
    body = re.sub(r"&gt;", ">", body)
    return re.sub(r"[ \t]+", " ", body).strip()


def redact(text: str) -> tuple[str, int]:
    count = 0
    for pattern in SECRET_PATTERNS:
        text, hits = pattern.subn("[redacted]", text)
        count += hits
    return text, count


def decode(data: bytes) -> tuple[str, bool]:
    for encoding in ("utf-8", "utf-16", "latin-1"):
        try:
            return data.decode(encoding), encoding != "utf-8"
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", "replace"), True


def from_text(text: str, *, name: str = "attachment.txt", max_tokens: int = 3000, kind: str = "") -> Attachment:
    raw = text or ""
    cleaned = html_to_text(raw) if (kind or sniff_kind(name, raw)) == "html" else raw
    cleaned, hits = redact(cleaned)
    truncated = False
    if estimate_text(cleaned) > max_tokens:
        cleaned = truncate_text(cleaned, max_tokens)
        truncated = True
    return Attachment(
        name=name,
        text=cleaned,
        kind=kind or sniff_kind(name, raw),
        size=len(raw.encode("utf-8")),
        sha256=hashlib.sha256(raw.encode("utf-8")).hexdigest(),
        truncated=truncated or hits > 0,
    )


def from_path(path: str | Path, *, max_tokens: int = 3000, max_bytes: int = 512_000) -> Attachment:
    source = Path(path)
    if not source.is_file():
        raise FileNotFoundError(str(source))
    data = source.read_bytes()
    clipped = data[:max_bytes]
    text, reencoded = decode(clipped)
    attachment = from_text(text, name=source.name, max_tokens=max_tokens)
    attachment.source = str(source)
    attachment.size = len(data)
    attachment.truncated = attachment.truncated or reencoded or len(data) > max_bytes
    attachment.sha256 = hashlib.sha256(data).hexdigest()
    return attachment


def chunks(attachment: Attachment, *, size: int = 800, overlap: int = 80) -> list[str]:
    text = attachment.text
    if len(text) <= size:
        return [text] if text else []
    step = max(1, size - overlap)
    return [text[index : index + size] for index in range(0, len(text), step) if text[index : index + size].strip()]


@dataclass
class AttachmentSet:
    items: list[Attachment] = field(default_factory=list)
    budget: int = 8000

    def add(self, attachment: Attachment) -> None:
        self.items.append(attachment)

    def add_path(self, path: str | Path, *, max_tokens: int = 3000) -> Attachment:
        attachment = from_path(path, max_tokens=max_tokens)
        self.add(attachment)
        return attachment

    @property
    def tokens(self) -> int:
        return sum(item.tokens for item in self.items)

    def fits(self) -> bool:
        return self.tokens <= self.budget

    def trim(self) -> list[str]:
        """Drop the largest attachments until the set fits; returns dropped names."""

        dropped: list[str] = []
        for attachment in sorted(self.items, key=lambda item: -item.tokens):
            if self.tokens <= self.budget:
                break
            self.items.remove(attachment)
            dropped.append(attachment.name)
        return dropped

    def prompt_block(self, *, per_attachment: int = 600, limit: int = 3) -> str:
        parts = []
        used = 0
        for attachment in self.items[:limit]:
            body = truncate_text(attachment.text, per_attachment)
            cost = estimate_text(body)
            if used + cost > self.budget:
                break
            parts.append(f"<attachment name=\"{attachment.name}\" kind=\"{attachment.kind}\">\n{body}\n</attachment>")
            used += cost
        return "\n\n".join(parts)

    def summary(self) -> str:
        if not self.items:
            return "no attachments"
        return f"{len(self.items)} attachment(s), {self.tokens} token(s), kinds: {', '.join(sorted({item.kind for item in self.items}))}"

    def to_dict(self) -> dict[str, Any]:
        return {"count": len(self.items), "tokens": self.tokens, "budget": self.budget, "items": [item.to_dict() for item in self.items]}


def from_har(path: str | Path, *, max_entries: int = 30) -> AttachmentSet:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    entries = ((payload.get("log") or {}).get("entries") or [])[:max_entries]
    lines = []
    for entry in entries:
        request = entry.get("request") or {}
        response = entry.get("response") or {}
        lines.append(f"{request.get('method', 'GET')} {request.get('url', '')} -> {response.get('status', '?')}")
    result = AttachmentSet(budget=6000)
    result.add(from_text("\n".join(lines), name=Path(path).name, kind="har"))
    return result


def from_request_log(text: str, *, name: str = "requests.log") -> AttachmentSet:
    result = AttachmentSet(budget=4000)
    result.add(from_text(text, name=name, kind="log", max_tokens=2000))
    return result


def describe(attachments: Iterable[Attachment]) -> str:
    lines = ["| file | kind | tokens | truncated |", "| --- | --- | --- | --- |"]
    for item in attachments:
        lines.append(f"| {item.name} | {item.kind} | {item.tokens} | {'yes' if item.truncated else 'no'} |")
    return "\n".join(lines) + "\n"


def sensitive(attachment: Attachment) -> bool:
    return attachment.kind in {"key", "certificate"} or "[redacted]" in attachment.text
