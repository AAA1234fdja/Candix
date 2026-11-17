"""Path and file discovery.

A wordlist sweep is still the most reliable way to find forgotten admin
consoles, backups and debug endpoints. Candix compares every candidate against a
random-path baseline to suppress soft-404 pages, classifies what it finds and
feeds interesting URLs back into the endpoint inventory.
"""

from __future__ import annotations

import random
import string
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any, Iterable

from candix.analysis.diff import similarity
from candix.analysis.html import HTMLDocument
from candix.catalog.wordlists import directory_wordlist, file_wordlist
from candix.core.context import ScanContext
from candix.core.endpoint import Endpoint, Param
from candix.core.log import Progress
from candix.net.http import Response
from candix.net.url import URL, join_url


@dataclass
class DiscoveredPath:
    url: str
    status: int
    length: int
    content_type: str
    title: str = ""
    reasons: list[str] = field(default_factory=list)
    redirect_to: str = ""
    body_snippet: str = ""
    severity: str = "info"

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "status": self.status,
            "length": self.length,
            "content_type": self.content_type,
            "title": self.title,
            "reasons": list(self.reasons),
            "redirect_to": self.redirect_to,
            "severity": self.severity,
        }


class PathDiscovery:
    def __init__(
        self,
        ctx: ScanContext,
        *,
        wordlist: Iterable[str] | None = None,
        include_files: bool = True,
        concurrency: int = 6,
    ) -> None:
        self.ctx = ctx
        self.wordlist = list(wordlist) if wordlist is not None else directory_wordlist(include_extensions=True)
        if include_files:
            self.wordlist.extend(file_wordlist())
        self.wordlist = list(dict.fromkeys(self.wordlist))[:1200]
        self.concurrency = max(1, concurrency)
        self.results: list[DiscoveredPath] = []
        self._lock = threading.Lock()
        self._soft_404: dict[str, Response] = {}

    def run(self) -> list[DiscoveredPath]:
        for target in self.ctx.targets:
            try:
                self._baseline_404(target.base_url)
            except Exception:
                continue
            progress = Progress(self.ctx.logger, len(self.wordlist), label=f"discover:{target.host}", every=2.0)
            with ThreadPoolExecutor(max_workers=self.concurrency, thread_name_prefix="discovery") as executor:
                futures = {
                    executor.submit(self._check, target.base_url, path): path for path in self.wordlist
                }
                for future in as_completed(futures):
                    try:
                        result = future.result()
                    except Exception:
                        result = None
                    if result is not None:
                        with self._lock:
                            self.results.append(result)
                            self._register(result)
                    progress.advance()
        return self.results

    # ------------------------------------------------------------------
    def _baseline_404(self, base_url: str) -> None:
        random_path = "/" + "".join(random.choices(string.ascii_lowercase + string.digits, k=18))
        url = join_url(base_url, random_path).render()
        response = self.ctx.http.get(url, tag="discovery-404")
        self._soft_404[base_url] = response

    def _check(self, base_url: str, path: str) -> DiscoveredPath | None:
        try:
            self.ctx.budget.check()
        except Exception:
            return None
        url = join_url(base_url, path).render()
        if self.ctx.scope is not None and not self.ctx.scope.matches(url):
            return None
        try:
            response = self.ctx.http.get(url, tag="discovery")
        except Exception:
            return None
        if response.error:
            return None
        if response.status in {404, 410}:
            return None
        soft = self._soft_404.get(base_url)
        if soft is not None and self._is_soft_404(soft, response):
            return None
        reasons = _classify(url, response)
        if not reasons and response.status not in {200, 201, 204, 301, 302, 307, 308, 401, 403}:
            return None
        title = ""
        content_type = response.content_type
        if "html" in content_type:
            document = HTMLDocument(response.text, url)
            title = document.title[:120]
        severity = _severity_for(reasons, response)
        return DiscoveredPath(
            url=url,
            status=response.status,
            length=response.size,
            content_type=content_type,
            title=title,
            reasons=trim_reasons(reasons),
            redirect_to=response.header("Location"),
            body_snippet=_snippet(response.text) if "text" in content_type or "html" in content_type else "",
            severity=severity,
        )

    def _is_soft_404(self, soft: Response, response: Response) -> bool:
        if response.status != soft.status:
            return False
        if response.status not in {200, 301, 302}:
            return False
        if abs(response.size - soft.size) > max(48, int(soft.size * 0.1)):
            return False
        return similarity(soft.text, response.text) > 0.93

    def _register(self, discovered: DiscoveredPath) -> None:
        try:
            parsed = URL.parse(discovered.url)
        except ValueError:
            return
        tags = {"discovered"}
        for reason in discovered.reasons:
            tags.add(reason.split(":")[0])
        endpoint = Endpoint(
            url=discovered.url,
            method="GET",
            params=[Param(name=name, value="1", location="query") for name in _params_for(discovered.url)],
            source="discovery",
            tags=tags,
        )
        self.ctx.add_endpoint(endpoint)


def _classify(url: str, response: Response) -> list[str]:
    reasons: list[str] = []
    lowered = url.lower()
    body = response.text[:5000].lower()
    if response.status == 403:
        reasons.append("access:403 (resource exists but is protected)")
    if response.status == 401:
        reasons.append("access:401 (authentication required)")
    if response.status in {301, 302, 307, 308} and response.header("Location"):
        reasons.append(f"redirect:{response.header('Location')[:80]}")
    if "index of /" in body or "<title>index of" in body:
        reasons.append("directory-listing")
    if any(token in lowered for token in ("/.git", "/.svn", "/.hg")):
        reasons.append("vcs-metadata")
    if lowered.endswith((".env", ".env.local", ".env.production")) or "/.env" in lowered:
        reasons.append("environment-file")
    if lowered.endswith((".bak", ".old", ".orig", "~", ".swp")):
        reasons.append("backup-file")
    if lowered.endswith((".zip", ".tar", ".tar.gz", ".tgz", ".sql", ".dump", ".rar", ".7z")):
        reasons.append("archive-or-dump")
    if any(token in lowered for token in ("phpinfo", "server-status", "server-info", "actuator", "heapdump", "threaddump")):
        reasons.append("debug-endpoint")
    if any(token in lowered for token in ("swagger", "openapi", "api-docs", "graphiql", "graphql")):
        reasons.append("api-documentation")
    if any(token in lowered for token in ("/admin", "administrator", "cpanel", "/manage", "/console")):
        reasons.append("admin-interface")
    if "root:x:0:0" in body or "[extensions]" in body:
        reasons.append("sensitive-file-content")
    if "aws_access_key_id" in body or "db_password" in body or "app_key=" in body:
        reasons.append("credential-material")
    if response.status == 200 and "text/plain" in response.header("Content-Type", "").lower() and response.size < 4000:
        if any(token in body for token in ("version", "uptime", "accesses", "repositoryformatversion")):
            reasons.append("information-disclosure")
    return list(dict.fromkeys(reasons))


def trim_reasons(reasons: list[str]) -> list[str]:
    return [reason[:120] for reason in reasons[:8]]


def _severity_for(reasons: list[str], response: Response) -> str:
    if "credential-material" in reasons or "sensitive-file-content" in reasons:
        return "high"
    if "vcs-metadata" in reasons or "environment-file" in reasons or "archive-or-dump" in reasons:
        return "high"
    if "debug-endpoint" in reasons or "admin-interface" in reasons:
        return "medium"
    if "directory-listing" in reasons:
        return "low"
    if response.status in {401, 403}:
        return "info"
    return "info"


def _params_for(url: str) -> list[str]:
    lowered = url.lower()
    guesses: list[str] = []
    if any(token in lowered for token in ("product", "item", "order", "user", "profile")):
        guesses.append("id")
    if "search" in lowered or "query" in lowered:
        guesses.append("q")
    if any(token in lowered for token in ("file", "download", "doc")):
        guesses.extend(["file", "path"])
    if any(token in lowered for token in ("fetch", "proxy", "url", "image")):
        guesses.append("url")
    if "redirect" in lowered or "return" in lowered:
        guesses.append("next")
    if "ping" in lowered or "host" in lowered:
        guesses.append("host")
    if "render" in lowered or "template" in lowered:
        guesses.append("tpl")
    if "graphql" in lowered:
        guesses.append("query")
    return list(dict.fromkeys(guesses))


def _snippet(text: str) -> str:
    cleaned = " ".join(text.split())
    return cleaned[:200]
