"""Subdomain enumeration through DNS resolution.

Passive sources require internet access and provider APIs, which are often
unavailable from a restricted operator network, so the default is an active
dictionary sweep with strict concurrency limits. Results are cached per parent
domain for the duration of the process.
"""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Iterable

from candix.catalog.wordlists import subdomain_wordlist
from candix.net import dns

_CACHE: dict[str, list[str]] = {}
_LOCK = threading.Lock()


@dataclass
class SubdomainResult:
    host: str
    addresses: list[str] = field(default_factory=list)
    cname: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {"host": self.host, "addresses": self.addresses, "cname": self.cname}


def enumerate_subdomains(
    domain: str,
    *,
    limit: int = 100,
    wordlist: Iterable[str] | None = None,
    concurrency: int = 12,
) -> list[str]:
    domain = domain.strip().lower().strip(".")
    if not domain or "." not in domain:
        return []
    with _LOCK:
        if domain in _CACHE:
            return list(_CACHE[domain])
    candidates = list(wordlist or subdomain_wordlist())[: max(1, limit * 3)]
    found: list[str] = []

    def check(label: str) -> str | None:
        host = f"{label}.{domain}"
        addresses = dns.resolve(host)
        return host if addresses else None

    with ThreadPoolExecutor(max_workers=concurrency, thread_name_prefix="subdomain") as executor:
        futures = {executor.submit(check, label): label for label in candidates}
        for future in as_completed(futures):
            try:
                host = future.result()
            except Exception:
                host = None
            if host:
                found.append(host)
                if len(found) >= limit:
                    break
    found.sort()
    with _LOCK:
        _CACHE[domain] = list(found)
    return found


def detailed(hosts: Iterable[str]) -> list[SubdomainResult]:
    results: list[SubdomainResult] = []
    for host in hosts:
        results.append(
            SubdomainResult(
                host=host,
                addresses=dns.resolve(host),
                cname=dns.cname_chain(host),
            )
        )
    return results


def clear_cache() -> None:
    with _LOCK:
        _CACHE.clear()
