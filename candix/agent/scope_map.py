"""Target expansion: what exactly is in scope for this engagement."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

from candix.agent.graph import EdgeKind
from candix.core.log import get_logger
from candix.net import dns
from candix.net.url import URL

log = get_logger("candix.agent.scope")


@dataclass
class Host:
    host: str
    addresses: list[str] = field(default_factory=list)
    cnames: list[str] = field(default_factory=list)
    scheme: str = "https"
    port: int = 443
    base: str = ""
    resolved: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "addresses": list(self.addresses),
            "cnames": list(self.cnames),
            "base": self.base,
            "resolved": self.resolved,
        }


@dataclass
class ScopeMap:
    hosts: list[Host] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def add(self, url: str) -> Host | None:
        try:
            parsed = URL.parse(url)
        except Exception:
            self.skipped.append(url)
            return None
        host = parsed.host
        if any(existing.host == host for existing in self.hosts):
            return next(existing for existing in self.hosts if existing.host == host)
        item = Host(host=host, scheme=parsed.scheme, port=parsed.port, base=f"{parsed.scheme}://{parsed.netloc}")
        self.hosts.append(item)
        return item

    def resolve(self, *, timeout: float = 3.0) -> "ScopeMap":
        for host in self.hosts:
            try:
                addresses = dns.resolve(host.host)
            except Exception as error:
                self.notes.append(f"{host.host}: resolution failed ({error})")
                continue
            host.addresses = list(addresses)
            host.resolved = bool(addresses)
            if not addresses:
                self.notes.append(f"{host.host}: no A/AAAA records")
                continue
            try:
                host.cnames = [name for name in dns.cname_chain(host.host) if name != host.host]
            except Exception:
                host.cnames = []
        return self

    def bases(self) -> list[str]:
        return [host.base for host in self.hosts if host.base]

    def unique_hosts(self) -> list[str]:
        return [host.host for host in self.hosts]

    def to_dict(self) -> dict[str, Any]:
        return {
            "hosts": [host.to_dict() for host in self.hosts],
            "skipped": self.skipped,
            "notes": self.notes,
        }

    def summary(self) -> str:
        resolved = sum(1 for host in self.hosts if host.resolved)
        return f"{len(self.hosts)} host(s), {resolved} resolved, {len(self.skipped)} skipped"


def build_scope(targets: Iterable[str], *, resolve: bool = True) -> ScopeMap:
    scope = ScopeMap()
    for target in targets:
        value = str(target).strip()
        if not value:
            continue
        if "://" not in value:
            value = f"https://{value}"
        scope.add(value)
    if resolve and scope.hosts:
        scope.resolve()
    return scope


def seed_assets(scope: ScopeMap, assets: Any) -> int:
    """Mirror the scope into the asset graph and return the number of nodes added."""

    added = 0
    for host in scope.hosts:
        try:
            assets.add_host(host.host)
            added += 1
            for address in host.addresses:
                assets.add_service(host.host, host.port, scheme=host.scheme, address=address)
                added += 1
            if host.base:
                endpoint = assets.add_endpoint("GET", host.base + "/")
                assets.connect(f"host:{host.host}", endpoint.id, EdgeKind.EXPOSES)
                added += 1
        except Exception as error:
            log.debug(f"could not seed {host.host}: {error}")
    return added


def directives_for(scope: ScopeMap) -> list[str]:
    """Human-readable scope statement for a report appendix."""

    lines = []
    for host in scope.hosts:
        suffix = f" ({', '.join(host.addresses)})" if host.addresses else " (unresolved)"
        lines.append(f"in scope: {host.host}{suffix}")
    for item in scope.skipped:
        lines.append(f"skipped: {item}")
    return lines
