"""Rules of engagement and target scope enforcement.

Candix refuses to send a request unless the destination is covered by the
engagement file supplied with ``--authorization``. The file is a JSON document
that names the client, the operator, the validity window and the exact hosts,
CIDRs and URL prefixes that may be tested. Its canonical digest is embedded so
that accidental edits after signature are detected.
"""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Iterator
from urllib.parse import urlsplit

from candix.core.clock import isoformat, parse_time, utcnow
from candix.core.errors import AuthorizationError, ConfigError, ScopeViolation
from candix.core.ids import sha256
from candix.net.url import URL, host_matches, is_loopback

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
ACTIVE_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"})
DESTRUCTIVE_METHODS = frozenset({"PUT", "PATCH", "DELETE"})


def _canonical(payload: dict[str, Any]) -> str:
    clone = {key: value for key, value in payload.items() if key != "digest"}
    return json.dumps(clone, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


@dataclass
class Authorization:
    """Metadata proving that the engagement was authorized."""

    engagement: str
    client: str
    operator: str
    authorized_by: str
    statement: str
    issued_at: str = field(default_factory=isoformat)
    expires_at: str = ""
    contact: str = ""
    reference: str = ""
    digest: str = ""

    def validate(self) -> None:
        missing = [
            name
            for name in ("engagement", "client", "operator", "authorized_by", "statement")
            if not getattr(self, name)
        ]
        if missing:
            raise AuthorizationError(
                "authorization document is incomplete",
                missing_fields=", ".join(missing),
            )
        if "authorize" not in self.statement.lower():
            raise AuthorizationError(
                "the statement must explicitly state that testing is authorized"
            )
        if self.expires_at:
            try:
                expires = parse_time(self.expires_at)
            except ValueError as exc:
                raise AuthorizationError(f"invalid expiry timestamp: {self.expires_at!r}") from exc
            if expires <= utcnow():
                raise AuthorizationError(
                    "authorization expired",
                    expires_at=self.expires_at,
                )

    def to_dict(self) -> dict[str, Any]:
        return {
            "engagement": self.engagement,
            "client": self.client,
            "operator": self.operator,
            "authorized_by": self.authorized_by,
            "statement": self.statement,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "contact": self.contact,
            "reference": self.reference,
        }

    def seal(self) -> str:
        self.digest = sha256(_canonical(self.to_dict()))
        return self.digest

    def verify_digest(self) -> bool:
        if not self.digest:
            return True
        return sha256(_canonical(self.to_dict())) == self.digest


@dataclass
class ScopeEntry:
    """One include or exclude clause."""

    raw: str
    kind: str  # url | host | wildcard | cidr | ip
    host: str = ""
    port: int | None = None
    path_prefix: str = ""
    network: ipaddress._BaseNetwork | None = None
    scheme: str = ""

    @classmethod
    def parse(cls, raw: str) -> "ScopeEntry":
        text = raw.strip()
        if not text:
            raise ConfigError("empty scope entry")
        if "/" in text and not text.startswith(("http://", "https://")):
            try:
                network = ipaddress.ip_network(text, strict=False)
            except ValueError:
                pass
            else:
                return cls(raw=text, kind="cidr", network=network)
        if text.startswith(("http://", "https://")):
            parsed = URL.parse(text)
            path = parsed.path if parsed.path not in {"", "/"} else ""
            return cls(
                raw=text,
                kind="url",
                host=parsed.host,
                port=parsed.port or parsed.effective_port,
                path_prefix=path,
                scheme=parsed.scheme,
            )
        host_part, _, port_part = text.partition(":")
        if port_part.isdigit():
            port = int(port_part)
        else:
            port = None
            host_part = text
        try:
            ipaddress.ip_address(host_part)
        except ValueError:
            pass
        else:
            kind = "ip"
            return cls(raw=text, kind=kind, host=host_part, port=port)
        kind = "wildcard" if host_part.startswith("*.") else "host"
        return cls(raw=text, kind=kind, host=host_part.lower(), port=port)

    def matches(self, url: URL) -> bool:
        if self.kind == "cidr" and self.network is not None:
            if url.is_ip:
                try:
                    return ipaddress.ip_address(url.host) in self.network
                except ValueError:
                    return False
            return False
        if self.host and not host_matches(url.host, self.host):
            return False
        if self.port and url.effective_port != self.port:
            return False
        if self.scheme and url.scheme != self.scheme:
            return False
        if self.path_prefix and not (url.path == self.path_prefix or url.path.startswith(self.path_prefix.rstrip("/") + "/")):
            return False
        return True

    def to_dict(self) -> dict[str, Any]:
        return {
            "raw": self.raw,
            "kind": self.kind,
            "host": self.host,
            "port": self.port,
            "path_prefix": self.path_prefix,
            "scheme": self.scheme,
        }


@dataclass
class Scope:
    """Allow-list based scope with explicit exclusions."""

    include: list[ScopeEntry] = field(default_factory=list)
    exclude: list[ScopeEntry] = field(default_factory=list)
    ports: set[int] = field(default_factory=set)
    allowed_methods: set[str] = field(default_factory=lambda: set(ACTIVE_METHODS))
    max_rps: float = 5.0
    max_requests: int = 20000
    allow_intrusive: bool = True
    allow_exploit: bool = False
    allow_destructive: bool = False
    data_handling: str = "no persistent data extraction; proof artifacts only"

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> "Scope":
        include_raw = payload.get("include", payload.get("targets", []))
        exclude_raw = payload.get("exclude", [])
        if isinstance(include_raw, str):
            include_raw = [include_raw]
        if isinstance(exclude_raw, str):
            exclude_raw = [exclude_raw]
        if not include_raw:
            raise ConfigError("scope must contain at least one include entry")
        methods = {method.upper() for method in payload.get("allowed_methods", ACTIVE_METHODS)}
        unknown = methods - ACTIVE_METHODS
        if unknown:
            raise ConfigError(f"unsupported methods in scope: {', '.join(sorted(unknown))}")
        return cls(
            include=[ScopeEntry.parse(_entry_text(item)) for item in include_raw],
            exclude=[ScopeEntry.parse(_entry_text(item)) for item in exclude_raw],
            ports={int(port) for port in payload.get("ports", [])},
            allowed_methods=methods,
            max_rps=float(payload.get("max_rps", 5.0)),
            max_requests=int(payload.get("max_requests", 20000)),
            allow_intrusive=bool(payload.get("allow_intrusive", True)),
            allow_exploit=bool(payload.get("allow_exploit", False)),
            allow_destructive=bool(payload.get("allow_destructive", False)),
            data_handling=str(payload.get("data_handling", "proof artifacts only")),
        )

    # ------------------------------------------------------------------
    def matches(self, target: str | URL) -> bool:
        try:
            url = URL.parse(target) if isinstance(target, str) else target
        except ValueError:
            return False
        included = any(entry.matches(url) for entry in self.include)
        if not included:
            return False
        if any(entry.matches(url) for entry in self.exclude):
            return False
        if self.ports and url.effective_port not in self.ports:
            return False
        return True

    def assert_url(self, target: str | URL, method: str = "GET") -> URL:
        try:
            url = URL.parse(target) if isinstance(target, str) else target
        except ValueError as exc:
            raise ScopeViolation(f"cannot parse target: {target!r}") from exc
        if not self.matches(url):
            raise ScopeViolation(
                "target is outside the authorized scope",
                target=f"{url.scheme}://{url.netloc}{url.path}",
            )
        method = method.upper()
        if method not in self.allowed_methods:
            raise ScopeViolation("HTTP method is not permitted by the rules of engagement", method=method)
        if method in DESTRUCTIVE_METHODS and not self.allow_destructive:
            raise ScopeViolation("destructive HTTP methods are disabled", method=method)
        return url

    def check_method(self, method: str) -> None:
        method = method.upper()
        if method not in self.allowed_methods:
            raise ScopeViolation("HTTP method is not permitted by the rules of engagement", method=method)
        if method in DESTRUCTIVE_METHODS and not self.allow_destructive:
            raise ScopeViolation("destructive HTTP methods are disabled", method=method)

    def allows_intrusive(self) -> bool:
        return self.allow_intrusive

    def allows_exploit(self) -> bool:
        return self.allow_exploit

    @property
    def hosts(self) -> list[str]:
        return [entry.host for entry in self.include if entry.host]

    def is_loopback_only(self) -> bool:
        hosts = self.hosts
        return bool(hosts) and all(is_loopback(host) for host in hosts)

    def to_dict(self) -> dict[str, Any]:
        return {
            "include": [entry.to_dict() for entry in self.include],
            "exclude": [entry.to_dict() for entry in self.exclude],
            "ports": sorted(self.ports),
            "allowed_methods": sorted(self.allowed_methods),
            "max_rps": self.max_rps,
            "max_requests": self.max_requests,
            "allow_intrusive": self.allow_intrusive,
            "allow_exploit": self.allow_exploit,
            "allow_destructive": self.allow_destructive,
            "data_handling": self.data_handling,
        }

    def describe(self) -> str:
        includes = ", ".join(entry.raw for entry in self.include)
        excludes = ", ".join(entry.raw for entry in self.exclude) or "none"
        return f"include=[{includes}] exclude=[{excludes}] rps<={self.max_rps} requests<={self.max_requests}"


@dataclass
class Engagement:
    """Authorization plus scope, loaded together from one file."""

    authorization: Authorization
    scope: Scope
    path: str = ""
    raw_digest: str = ""

    @classmethod
    def load(cls, path: str | Path) -> "Engagement":
        file = Path(path)
        if not file.exists():
            raise AuthorizationError(f"authorization file not found: {file}")
        try:
            payload = json.loads(file.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise AuthorizationError(f"authorization file is not valid JSON: {exc}") from exc
        if not isinstance(payload, dict):
            raise AuthorizationError("authorization file must contain a JSON object")
        digest = payload.get("digest", "")
        if digest and sha256(_canonical(payload)) != digest:
            raise AuthorizationError("authorization file digest mismatch: the document was modified")
        authorization_payload = payload.get("authorization", payload.get("roe", {}))
        if not authorization_payload:
            raise AuthorizationError("authorization section is missing")
        authorization = Authorization(
            engagement=authorization_payload.get("engagement", ""),
            client=authorization_payload.get("client", ""),
            operator=authorization_payload.get("operator", ""),
            authorized_by=authorization_payload.get("authorized_by", ""),
            statement=authorization_payload.get("statement", ""),
            issued_at=authorization_payload.get("issued_at", isoformat()),
            expires_at=authorization_payload.get("expires_at", ""),
            contact=authorization_payload.get("contact", ""),
            reference=authorization_payload.get("reference", ""),
            digest=authorization_payload.get("digest", ""),
        )
        authorization.validate()
        if authorization.digest and not authorization.verify_digest():
            raise AuthorizationError("authorization metadata digest mismatch")
        scope_payload = payload.get("scope", {})
        scope = Scope.from_payload(scope_payload)
        if not scope.include:
            raise AuthorizationError("scope has no include entries")
        return cls(
            authorization=authorization,
            scope=scope,
            path=str(file),
            raw_digest=digest,
        )

    @classmethod
    def from_document(cls, payload: dict[str, Any], *, path: str = "", verify: bool = True) -> "Engagement":
        """Build an engagement from an already-constructed authorization document."""

        if not isinstance(payload, dict):
            raise AuthorizationError("authorization document must be a JSON object")
        digest = payload.get("digest", "")
        if verify and digest and sha256(_canonical(payload)) != digest:
            raise AuthorizationError("authorization document digest mismatch")
        authorization_payload = payload.get("authorization", payload.get("roe", {}))
        if not authorization_payload:
            raise AuthorizationError("authorization section is missing")
        authorization = Authorization(
            engagement=authorization_payload.get("engagement", ""),
            client=authorization_payload.get("client", ""),
            operator=authorization_payload.get("operator", ""),
            authorized_by=authorization_payload.get("authorized_by", ""),
            statement=authorization_payload.get("statement", ""),
            issued_at=authorization_payload.get("issued_at", isoformat()),
            expires_at=authorization_payload.get("expires_at", ""),
            contact=authorization_payload.get("contact", ""),
            reference=authorization_payload.get("reference", ""),
            digest=authorization_payload.get("digest", ""),
        )
        authorization.validate()
        scope = Scope.from_payload(payload.get("scope", {}))
        return cls(authorization=authorization, scope=scope, path=path, raw_digest=digest)

    def guard_url(self, target: str | URL, method: str = "GET") -> URL:
        return self.scope.assert_url(target, method)

    def summary(self) -> dict[str, Any]:
        return {
            "engagement": self.authorization.engagement,
            "client": self.authorization.client,
            "operator": self.authorization.operator,
            "authorized_by": self.authorization.authorized_by,
            "expires_at": self.authorization.expires_at,
            "scope": self.scope.to_dict(),
            "digest": self.raw_digest,
            "authorization_file": self.path,
        }


def build_authorization(
    *,
    engagement: str,
    client: str,
    operator: str,
    authorized_by: str,
    include: Iterable[str],
    exclude: Iterable[str] = (),
    expires_in_days: int = 30,
    allow_exploit: bool = True,
    allow_intrusive: bool = True,
    max_rps: float = 5.0,
    max_requests: int = 20000,
) -> dict[str, Any]:
    """Create a ready-to-sign engagement document (used by ``candix authorize``)."""

    from datetime import timedelta

    authorization = Authorization(
        engagement=engagement,
        client=client,
        operator=operator,
        authorized_by=authorized_by,
        statement=(
            f"{client} authorizes {operator} to perform security testing against the "
            "assets listed in this scope. Testing must remain non-destructive and "
            "must stop if unexpected availability impact is observed."
        ),
        issued_at=isoformat(),
        expires_at=isoformat(utcnow() + timedelta(days=max(1, expires_in_days))),
    )
    scope = Scope.from_payload(
        {
            "include": list(include),
            "exclude": list(exclude),
            "max_rps": max_rps,
            "max_requests": max_requests,
            "allow_intrusive": allow_intrusive,
            "allow_exploit": allow_exploit,
        }
    )
    authorization.seal()
    document = {
        "authorization": authorization.to_dict(),
        "scope": scope.to_dict(),
    }
    document["digest"] = sha256(_canonical(document))
    return document


def write_engagement(path: str | Path, document: dict[str, Any]) -> Path:
    file = Path(path)
    file.parent.mkdir(parents=True, exist_ok=True)
    file.write_text(json.dumps(document, indent=2), encoding="utf-8")
    try:
        file.chmod(0o600)
    except OSError:  # pragma: no cover - platform dependent
        pass
    return file


def load_scope_only(path: str | Path) -> Scope:
    """Load just the scope section - useful for dry-run validation."""

    file = Path(path)
    if not file.exists():
        raise AuthorizationError(f"authorization file not found: {file}")
    payload = json.loads(file.read_text(encoding="utf-8"))
    scope_payload = payload.get("scope", payload)
    return Scope.from_payload(scope_payload)


class ScopeValidator:
    """Pre-flight checks that catch common operator mistakes early."""

    def __init__(self, engagement: Engagement) -> None:
        self.engagement = engagement

    def check(self, targets: Iterable[str]) -> list[str]:
        warnings: list[str] = []
        scope = self.engagement.scope
        for target in targets:
            try:
                url = URL.parse(target)
            except ValueError:
                warnings.append(f"unparseable target skipped: {target}")
                continue
            if not scope.matches(url):
                warnings.append(f"target outside scope: {target}")
                continue
            if url.scheme == "http" and not is_loopback(url.host):
                warnings.append(f"plaintext HTTP target: {target}")
            if scope.ports and url.effective_port not in scope.ports:
                warnings.append(f"port not declared in scope: {target}")
        if scope.allow_destructive:
            warnings.append("destructive methods are enabled for this engagement")
        if scope.max_rps > 20:
            warnings.append("rate limit above 20 rps may impact availability")
        if not self.engagement.authorization.expires_at:
            warnings.append("authorization has no expiry date")
        return warnings

    def assert_targets(self, targets: Iterable[str]) -> None:
        for target in targets:
            self.engagement.guard_url(target)


def _entry_text(item: Any) -> str:
    if isinstance(item, dict):
        return str(item.get("raw") or item.get("host") or "")
    return str(item)


def iter_scope_hosts(scope: Scope) -> Iterator[str]:
    for entry in scope.include:
        if entry.host:
            yield entry.host
