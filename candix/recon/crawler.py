"""Breadth-first crawler that builds the endpoint inventory.

The crawler is conservative by design: it respects scope, robots.txt, depth and
page limits, and it never submits a form. Its job is to enumerate GET
endpoints, forms (as POST/GET templates), JSON parameters and JavaScript-
referenced API routes so detectors have something meaningful to attack.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Iterable, Iterator

from candix.analysis.html import HTMLDocument, is_html
from candix.analysis.sinks import analyze_script
from candix.core.context import ScanContext
from candix.core.endpoint import Body, Endpoint, Param, params_from_json
from candix.core.log import Progress
from candix.net.http import Response
from candix.net.url import URL, is_static_asset, join_url
from candix.recon.robots import parse_robots
from candix.recon.sitemap import parse_sitemap

_COMMON_PARAMS = (
    "id", "q", "query", "search", "page", "file", "path", "url", "next", "redirect",
    "return", "callback", "cmd", "command", "exec", "host", "target", "lang", "view",
    "template", "name", "user", "username", "email", "token", "debug", "format",
    "type", "action", "dir", "folder", "download", "image", "src", "dest", "output",
)

_INTERESTING_EXTENSIONS = (
    ".php", ".asp", ".aspx", ".jsp", ".do", ".action", ".json", ".xml", ".cgi", ".pl",
)


@dataclass
class CrawlResult:
    pages_fetched: int = 0
    endpoints_added: int = 0
    forms_found: int = 0
    scripts_analyzed: int = 0
    js_endpoints: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    visited: list[str] = field(default_factory=list)

    def summary(self) -> dict[str, object]:
        return {
            "pages_fetched": self.pages_fetched,
            "endpoints_added": self.endpoints_added,
            "forms_found": self.forms_found,
            "scripts_analyzed": self.scripts_analyzed,
            "js_endpoints": len(self.js_endpoints),
            "errors": len(self.errors),
        }


class Crawler:
    def __init__(
        self,
        ctx: ScanContext,
        *,
        max_pages: int | None = None,
        max_depth: int | None = None,
        respect_robots: bool | None = None,
    ) -> None:
        self.ctx = ctx
        self.max_pages = max_pages or int(ctx.config.get("recon.max_crawl_pages", 200))
        self.max_depth = max_depth if max_depth is not None else int(ctx.config.get("scan.max_depth", 3))
        self.respect_robots = (
            respect_robots if respect_robots is not None else bool(ctx.config.get("scan.respect_robots", True))
        )
        self.result = CrawlResult()
        self._visited: set[str] = set()
        self._queued: set[str] = set()
        self._disallowed: list[str] = []
        self._scope_cache: dict[str, bool] = {}

    # ------------------------------------------------------------------
    def crawl(self, seeds: Iterable[str] | None = None) -> CrawlResult:
        seeds = list(seeds or [target.url for target in self.ctx.targets])
        queue: list[tuple[str, int]] = []
        for seed in seeds:
            normalized = _normalize(seed)
            if normalized and self._in_scope(normalized):
                queue.append((normalized, 0))
                self._queued.add(normalized)
        for target in self.ctx.targets:
            self._load_robots(target.base_url)
            self._load_sitemap(target.base_url)
            self._add_endpoint(target.url, source="target")
        progress = Progress(self.ctx.logger, max(1, self.max_pages), label="crawl")
        while queue and self.result.pages_fetched < self.max_pages:
            try:
                self.ctx.budget.check()
            except Exception:
                self.ctx.warn("crawl stopped by budget")
                break
            url, depth = queue.pop(0)
            if url in self._visited:
                continue
            if depth > self.max_depth:
                continue
            if self.respect_robots and self._is_disallowed(url):
                continue
            self._visited.add(url)
            response = self._fetch(url)
            if response is None:
                continue
            self.result.pages_fetched += 1
            self.result.visited.append(url)
            progress.advance()
            content_type = response.content_type
            if "json" in content_type:
                self._handle_json(url, response)
                continue
            if not is_html(response.text, content_type):
                continue
            document = HTMLDocument(response.text, response.url or url)
            self._handle_document(document, response.url or url, depth, queue)
        self.result.endpoints_added = len(self.ctx.endpoints)
        return self.result

    # ------------------------------------------------------------------
    def _fetch(self, url: str) -> Response | None:
        try:
            response = self.ctx.http.get(url, tag="crawl")
        except Exception as exc:
            self.result.errors.append(f"{url}: {exc}")
            return None
        if response.error:
            self.result.errors.append(f"{url}: {response.error}")
            return None
        if response.status >= 400:
            return None
        return response

    def _handle_document(self, document: HTMLDocument, base: str, depth: int, queue: list[tuple[str, int]]) -> None:
        parsed = URL.parse(base)
        self._add_endpoint(base, source="crawl", params=_params_from_url(parsed))
        forms = document.form_endpoints()
        self.result.forms_found += len(forms)
        for form in forms:
            action = form.action or base
            if not self._in_scope(action):
                continue
            form_location = "query" if form.method.lower() == "get" else "body"
            params = [
                Param(name=item.name, value=item.value, location=form_location, kind=_field_kind(item.field_type))
                for item in form.fields
                if item.name and item.field_type not in {"submit", "button", "reset", "image"}
            ]
            body = Body(
                content_type="application/x-www-form-urlencoded",
                form={item.name: item.value for item in form.fields if item.name},
            )
            endpoint = Endpoint(
                url=action,
                method=form.method.upper(),
                params=params,
                body=body,
                source="form",
                tags={"form", "auth" if form.password_field else "input"},
                forms=[form.to_dict()],
                depth=depth,
            )
            if endpoint.method == "GET":
                query = URL.parse(action)
                for item in params:
                    query = query.add_param(item.name, item.value)
                endpoint.url = query.render()
                endpoint.body = None
            self.ctx.add_endpoint(endpoint)
        for link in document.url_links():
            self._enqueue(link, depth + 1, queue)
        if self.ctx.config.get("scan.crawl_js", True):
            self._handle_scripts(document, base)
        self._guess_parameters(base)

    def _handle_scripts(self, document: HTMLDocument, base: str) -> None:
        sources = document.script_sources()[:10]
        for source in sources:
            if not self._in_scope(source):
                continue
            try:
                response = self.ctx.http.get(source, tag="crawl-js")
            except Exception:
                continue
            if response.error or response.status >= 400 or response.size > 2_000_000:
                continue
            analysis = analyze_script(response.text)
            self.result.scripts_analyzed += 1
            for endpoint in analysis.endpoints:
                resolved = _resolve(base, endpoint)
                if resolved and self._in_scope(resolved):
                    self.result.js_endpoints.append(resolved)
                    self._add_endpoint(resolved, source="javascript")
                    self.ctx.add_endpoint(
                        Endpoint(url=resolved, method="GET", source="javascript", tags={"js"})
                    )

    def _handle_json(self, url: str, response: Response) -> None:
        """Record JSON endpoints without inventing request parameters.

        Response keys describe the schema, not the accepted input. Fuzzing them
        produces false positives, so only the URL itself is registered; request
        parameters come from links, forms and the query string.
        """

        payload = response.try_json()
        if payload is None:
            return
        if not self._in_scope(url):
            return
        self.ctx.add_endpoint(
            Endpoint(
                url=url,
                method="GET",
                params=_params_from_url(URL.parse(url)),
                source="json",
                tags={"api", "json"},
            )
        )

    def _guess_parameters(self, base: str) -> None:
        """Add a few high-value parameter names to parameterless endpoints.

        This is deliberately narrow: blindly appending 30 parameters to every
        URL produces noise and load. Only endpoints that look interactive
        (HTML pages, not static assets) receive guesses.
        """

        parsed = URL.parse(base)
        if parsed.query:
            return
        if is_static_asset(base) or any(parsed.path.endswith(ext) for ext in _INTERESTING_EXTENSIONS):
            return
        guesses = self.ctx.config.get("recon.param_guesses")
        if guesses is False:
            return
        for name in _COMMON_PARAMS[:12]:
            endpoint = Endpoint(
                url=parsed.add_param(name, "1").render(),
                method="GET",
                params=[Param(name=name, value="1", location="query")],
                source="guess",
                tags={"guessed"},
            )
            self.ctx.add_endpoint(endpoint)

    # ------------------------------------------------------------------
    def _enqueue(self, url: str, depth: int, queue: list[tuple[str, int]]) -> None:
        normalized = _normalize(url)
        if not normalized or normalized in self._queued or normalized in self._visited:
            return
        if not self._in_scope(normalized):
            return
        if is_static_asset(normalized) and not normalized.endswith((".json", ".xml")):
            return
        if _looks_like_logout(normalized):
            return
        self._queued.add(normalized)
        queue.append((normalized, depth))

    def _add_endpoint(self, url: str, *, source: str, params: list[Param] | None = None) -> None:
        if not self._in_scope(url):
            return
        parsed = URL.parse(url)
        endpoint_params = params if params is not None else _params_from_url(parsed)
        endpoint = Endpoint(
            url=parsed.render(),
            method="GET",
            params=endpoint_params,
            source=source,
            tags={source},
        )
        self.ctx.add_endpoint(endpoint)

    def _in_scope(self, url: str) -> bool:
        if url in self._scope_cache:
            return self._scope_cache[url]
        scope = self.ctx.scope
        allowed = True
        if scope is not None:
            try:
                allowed = scope.matches(url)
            except Exception:
                allowed = False
        self._scope_cache[url] = allowed
        return allowed

    def _load_robots(self, base_url: str) -> None:
        url = base_url.rstrip("/") + "/robots.txt"
        if not self._in_scope(url):
            return
        try:
            response = self.ctx.http.get(url, tag="robots")
        except Exception:
            return
        if response.error or response.status != 200:
            return
        rules = parse_robots(response.text)
        self._disallowed.extend(rules.disallow)
        for path in rules.disallow[:50]:
            if path and len(path) > 1:
                self._enqueue(base_url.rstrip("/") + path, 1, [])

    def _load_sitemap(self, base_url: str) -> None:
        url = base_url.rstrip("/") + "/sitemap.xml"
        if not self._in_scope(url):
            return
        try:
            response = self.ctx.http.get(url, tag="sitemap")
        except Exception:
            return
        if response.error or response.status != 200:
            return
        for loc in parse_sitemap(response.text)[:200]:
            if self._in_scope(loc):
                self.ctx.add_endpoint(Endpoint(url=loc, method="GET", source="sitemap", tags={"sitemap"}))

    def _is_disallowed(self, url: str) -> bool:
        if not self._disallowed:
            return False
        path = URL.parse(url).path
        return any(path == rule or path.startswith(rule.rstrip("/") + "/") for rule in self._disallowed if rule)


def _params_from_url(parsed: URL) -> list[Param]:
    return [Param(name=name, value=value, location="query") for name, value in parsed.query.get_all()]


def _field_kind(field_type: str) -> str:
    if field_type in {"number", "range"}:
        return "int"
    if field_type == "checkbox":
        return "bool"
    if field_type == "file":
        return "file"
    return "string"


def _normalize(url: str) -> str:
    try:
        parsed = URL.parse(url)
    except ValueError:
        return ""
    if parsed.scheme not in {"http", "https"}:
        return ""
    parsed.fragment = ""
    return parsed.render()


def _resolve(base: str, reference: str) -> str:
    try:
        return join_url(base, reference).render()
    except ValueError:
        return ""


def _looks_like_logout(url: str) -> bool:
    lowered = url.lower()
    return any(token in lowered for token in ("logout", "signout", "sign-out", "delete", "destroy", "unsubscribe"))
