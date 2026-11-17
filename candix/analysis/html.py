"""A tolerant HTML parser for crawl-time extraction.

``html.parser`` is forgiving enough for real-world markup and, unlike a full
DOM implementation, cannot execute scripts or fetch subresources. Candix only
needs links, forms, inline scripts, comments and a few metadata fields.
"""

from __future__ import annotations

import html as html_module
import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Any, Iterable

from candix.net.url import URL, join_url

_FORM_METHODS = {"get", "post"}
_SKIP_SCHEMES = {"javascript", "mailto", "tel", "data", "sms", "about", "blob"}


@dataclass
class FormField:
    name: str
    field_type: str = "text"
    value: str = ""
    required: bool = False
    options: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "type": self.field_type,
            "value": self.value,
            "required": self.required,
            "options": list(self.options),
        }


@dataclass
class Form:
    action: str
    method: str = "GET"
    fields: list[FormField] = field(default_factory=list)
    enctype: str = ""
    form_id: str = ""
    has_csrf_token: bool = False
    password_field: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "method": self.method,
            "fields": [item.to_dict() for item in self.fields],
            "enctype": self.enctype,
            "id": self.form_id,
            "has_csrf_token": self.has_csrf_token,
            "password_field": self.password_field,
        }


@dataclass
class Script:
    src: str = ""
    inline: str = ""
    script_type: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"src": self.src, "inline": self.inline, "type": self.script_type}


class _Collector(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.forms: list[Form] = []
        self.scripts: list[Script] = []
        self.comments: list[str] = []
        self.meta: dict[str, str] = {}
        self.title = ""
        self.base_href = ""
        self._stack: list[str] = []
        self._form: Form | None = None
        self._select: FormField | None = None
        self._script: Script | None = None
        self._in_title = False
        self._text: list[str] = []
        self.inputs: list[dict[str, str]] = []

    # -- tags ---------------------------------------------------------
    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = {name.lower(): (value or "") for name, value in attrs}
        self._stack.append(tag)
        if tag in {"a", "area"}:
            href = attributes.get("href", "")
            if href:
                self.links.append(href)
        elif tag in {"link", "iframe", "frame", "embed", "object", "source", "video", "audio", "img"}:
            for key in ("href", "src", "data"):
                value = attributes.get(key)
                if value:
                    self.links.append(value)
        elif tag == "script":
            self._script = Script(src=attributes.get("src", ""), script_type=attributes.get("type", ""))
            if not attributes.get("src"):
                self._script.inline = ""
        elif tag == "form":
            action = attributes.get("action", "")
            method = (attributes.get("method") or "GET").lower()
            if method not in _FORM_METHODS:
                method = "get"
            self._form = Form(
                action=action,
                method=method.upper(),
                enctype=attributes.get("enctype", ""),
                form_id=attributes.get("id", ""),
            )
        elif tag == "input" and self._form is not None:
            name = attributes.get("name", "")
            if name:
                field_type = (attributes.get("type") or "text").lower()
                self._form.fields.append(
                    FormField(
                        name=name,
                        field_type=field_type,
                        value=attributes.get("value", ""),
                        required="required" in attributes,
                    )
                )
                if field_type == "password":
                    self._form.password_field = True
                self.inputs.append({"name": name, "type": field_type})
        elif tag == "select" and self._form is not None:
            name = attributes.get("name", "")
            if name:
                self._select = FormField(name=name, field_type="select")
                self._form.fields.append(self._select)
        elif tag == "option" and self._select is not None:
            value = attributes.get("value", "")
            if value:
                self._select.options.append(value)
        elif tag == "textarea" and self._form is not None:
            name = attributes.get("name", "")
            if name:
                self._form.fields.append(FormField(name=name, field_type="textarea"))
        elif tag == "button" and self._form is not None:
            name = attributes.get("name", "")
            if name:
                self._form.fields.append(
                    FormField(name=name, field_type="submit", value=attributes.get("value", ""))
                )
        elif tag == "meta":
            name = attributes.get("name") or attributes.get("property") or attributes.get("http-equiv")
            content = attributes.get("content")
            if name and content:
                self.meta[name.lower()] = content
        elif tag == "base":
            if not self.base_href:
                self.base_href = attributes.get("href", "")
        elif tag == "title":
            self._in_title = True

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._form is not None:
            self._finalise_form()
        elif tag == "select":
            self._select = None
        elif tag == "script" and self._script is not None:
            self.scripts.append(self._script)
            self._script = None
        elif tag == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title += data
            return
        if self._script is not None:
            self._script.inline += data
            return
        self._text.append(data)

    def handle_comment(self, data: str) -> None:
        if data.strip():
            self.comments.append(data.strip())

    def _finalise_form(self) -> None:
        assert self._form is not None
        if not self._form.action:
            self._form.action = ""
        names = {field.name.lower() for field in self._form.fields}
        self._form.has_csrf_token = bool(
            {name for name in names if "csrf" in name or "xsrf" in name or "_token" in name}
        )
        self.forms.append(self._form)
        self._form = None

    def close(self) -> None:
        super().close()
        if self._form is not None:
            self._finalise_form()
        if self._script is not None:
            self.scripts.append(self._script)
            self._script = None


class HTMLDocument:
    """Parsed HTML document with resolved URL helpers."""

    def __init__(self, text: str, base_url: str = "") -> None:
        self.raw = text or ""
        self.base_url = base_url
        collector = _Collector()
        try:
            collector.feed(self.raw)
            collector.close()
        except Exception:  # pragma: no cover - html.parser is already tolerant
            pass
        self._collector = collector
        self.title = collector.title.strip()
        self.meta = collector.meta
        self.comments = collector.comments
        self.scripts = collector.scripts
        self.forms = collector.forms
        self.links = collector.links
        self.text_content = _collapse_whitespace(" ".join(collector._text))
        base = collector.base_href or base_url
        self.base_href = base
        self.resolved_base = _safe_join(base_url, base) if base else base_url

    # ------------------------------------------------------------------
    def url_links(self) -> list[str]:
        result: list[str] = []
        for raw in self.links:
            candidate = raw.strip()
            if not candidate or candidate.startswith("#"):
                continue
            scheme = candidate.split(":", 1)[0].lower() if ":" in candidate else ""
            if scheme in _SKIP_SCHEMES:
                continue
            resolved = _safe_join(self.resolved_base or self.base_url, candidate)
            if resolved:
                result.append(resolved)
        return result

    def form_endpoints(self) -> list[Form]:
        for form in self.forms:
            if not form.action:
                form.action = self.base_url
            else:
                form.action = _safe_join(self.resolved_base or self.base_url, form.action) or self.base_url
        return self.forms

    def inline_scripts(self) -> list[str]:
        return [script.inline for script in self.scripts if script.inline.strip()]

    def script_sources(self) -> list[str]:
        result: list[str] = []
        for script in self.scripts:
            if script.src:
                resolved = _safe_join(self.resolved_base or self.base_url, script.src)
                if resolved:
                    result.append(resolved)
        return result

    def hidden_inputs(self) -> dict[str, str]:
        result: dict[str, str] = {}
        for form in self.forms:
            for field in form.fields:
                if field.field_type == "hidden" and field.name:
                    result[field.name] = field.value
        return result

    def has_password_form(self) -> bool:
        return any(form.password_field for form in self.forms)

    def resources(self) -> dict[str, list[str]]:
        grouped: dict[str, list[str]] = {"scripts": [], "styles": [], "images": [], "frames": []}
        for script in self.scripts:
            if script.src:
                resolved = _safe_join(self.resolved_base, script.src)
                if resolved:
                    grouped["scripts"].append(resolved)
        for raw in self.raw.lower().split("<link")[1:]:
            if "stylesheet" in raw and "href=" in raw:
                match = re.search(r'href=["\']([^"\']+)', raw)
                if match:
                    grouped["styles"].append(match.group(1))
        for raw in re.findall(r'<img[^>]+src=["\']([^"\']+)', self.raw, re.IGNORECASE):
            grouped["images"].append(raw)
        for raw in re.findall(r'<iframe[^>]+src=["\']([^"\']+)', self.raw, re.IGNORECASE):
            grouped["frames"].append(raw)
        return grouped

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "base": self.resolved_base,
            "links": len(self.links),
            "forms": [form.to_dict() for form in self.forms],
            "scripts": [script.to_dict() for script in self.scripts],
            "comments": self.comments[:20],
            "meta": self.meta,
        }


def _safe_join(base: str, reference: str) -> str:
    try:
        if not base:
            return reference
        return join_url(base, reference).render()
    except ValueError:
        return ""


def _collapse_whitespace(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def parse_html(text: str, base_url: str = "") -> HTMLDocument:
    return HTMLDocument(text, base_url)


def extract_links(text: str, base_url: str = "") -> list[str]:
    return HTMLDocument(text, base_url).url_links()


def parse_forms(text: str, base_url: str = "") -> list[dict[str, Any]]:
    document = HTMLDocument(text, base_url)
    return [form.to_dict() for form in document.form_endpoints()]


def visible_text(text: str) -> str:
    return HTMLDocument(text).text_content


def strip_tags(text: str) -> str:
    return re.sub(r"<[^>]+>", "", text or "")


def escape_html(value: str) -> str:
    return html_module.escape(value, quote=True)


def unescape_html(value: str) -> str:
    return html_module.unescape(value)


def find_meta_generator(text: str) -> str:
    match = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', text, re.IGNORECASE)
    if not match:
        match = re.search(r'content=["\']([^"\']+)["\'][^>]+name=["\']generator["\']', text, re.IGNORECASE)
    return match.group(1) if match else ""


def extract_comments(text: str) -> list[str]:
    return re.findall(r"<!--(.*?)-->", text or "", re.DOTALL)


def extract_urls_from_script(script: str) -> list[str]:
    patterns = (
        r"""["']((?:https?:)?//[^"'<> ]+)["']""",
        r"""["'](/[A-Za-z0-9_\-./]+(?:\?[^"'<> ]*)?)["']""",
        r"""url\s*:\s*["']([^"']+)["']""",
        r"""fetch\(\s*["']([^"']+)["']""",
        r"""axios\.\w+\(\s*["']([^"']+)["']""",
        r"""["'](/api/[^"']+)["']""",
    )
    found: list[str] = []
    for pattern in patterns:
        for match in re.findall(pattern, script):
            candidate = match.strip()
            if candidate and not candidate.startswith(("data:", "blob:")):
                found.append(candidate)
    return list(dict.fromkeys(found))


def is_html(response_text: str, content_type: str = "") -> bool:
    if "html" in (content_type or "").lower():
        return True
    head = (response_text or "")[:400].lower()
    return any(token in head for token in ("<!doctype html", "<html", "<head", "<body", "<div", "<form"))


def extract_ids(text: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for match in re.findall(r'<input[^>]+>', text or "", re.IGNORECASE):
        name = re.search(r'name=["\']([^"\']+)', match)
        value = re.search(r'value=["\']([^"\']*)', match)
        if name:
            result[name.group(1)] = value.group(1) if value else ""
    return result
