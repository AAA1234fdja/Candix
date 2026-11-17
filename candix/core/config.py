"""Layered configuration.

Priority, lowest to highest:

1. built-in defaults
2. the selected profile (``safe``, ``standard``, ``aggressive``, ``lab``)
3. the TOML file passed with ``--config``
4. ``CANDIX_*`` environment variables
5. explicit CLI overrides (applied by the CLI layer)

Only known keys are accepted so a typo cannot silently disable a safety control.
"""

from __future__ import annotations

import copy
import json
import os
import sys
from dataclasses import dataclass, field

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:
    # Fallback for environments where tomllib is stubbed or missing (tests, 3.10 sandbox)
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ModuleNotFoundError:
        tomllib = None  # type: ignore[assignment]  # handled at load time with a friendly error
from pathlib import Path
from typing import Any, Iterable, Mapping

from candix.core.errors import ConfigError

DEFAULTS: dict[str, Any] = {
    "profile": "standard",
    "http": {
        "timeout": 10.0,
        "connect_timeout": 5.0,
        "max_redirects": 5,
        "verify_tls": True,
        "user_agent": "Candix/0.1 (+authorized-security-testing)",
        "max_body_bytes": 2_000_000,
        "retries": 1,
        "retry_statuses": [502, 503, 504],
        "proxy": "",
        "headers": {},
        "http2": False,
        "preserve_host": False,
        "accept_encoding": "gzip, deflate",
    },
    "scan": {
        "max_requests": 20000,
        "max_rps": 5.0,
        "burst": 5,
        "concurrency": 8,
        "max_depth": 3,
        "max_pages": 200,
        "max_endpoints": 2000,
        "deadline_seconds": 1800,
        "request_timeout_budget": 0,
        "respect_robots": True,
        "include_subdomains": False,
        "crawl_js": True,
        "follow_redirects": True,
        "retest_findings": True,
        "waf_evasion": False,
        "stop_on_critical": False,
    },
    "detect": {
        "categories": [],
        "exclude_categories": [],
        "min_severity": "info",
        "min_confidence": "possible",
        "intrusive": True,
        "time_based": True,
        "max_payloads_per_param": 12,
        "max_params_per_endpoint": 40,
        "blind_callback_host": "",
        "safe_mode": True,
    },
    "exploit": {
        "enabled": False,
        "max_proofs": 10,
        "allow_data_access": False,
        "allow_write": False,
        "allow_command_execution": False,
        "require_confirmation": True,
        "timeout": 15.0,
        "marker_ttl": 300,
    },
    "evidence": {
        "enabled": True,
        "dir": "evidence",
        "max_body_bytes": 8192,
        "redaction": "standard",
        "hash_chain": True,
    },
    "report": {
        "formats": ["html", "json", "markdown"],
        "dir": "report",
        "title": "Security assessment",
        "include_evidence": True,
        "include_remediation": True,
        "min_severity": "info",
        "executive_summary": True,
        "appendix": True,
        "redaction": "standard",
        "logo": "",
    },
    "recon": {
        "enabled": True,
        "wordlist": "",
        "extensions": [".php", ".asp", ".aspx", ".jsp", ".json", ".bak", ".old", ".zip"],
        "max_crawl_pages": 200,
        "user_agent": "",
        "passive_only": False,
        "dns_resolvers": [],
        "subdomain_sources": ["crt.sh", "dns"],
        "max_subdomains": 500,
    },
    "plugins": {
        "enabled": True,
        "dirs": [],
        "allowlist": [],
        "denylist": [],
        "strict": False,
    },
    "logging": {
        "level": "info",
        "file": "",
        "jsonl": False,
        "color": True,
        "quiet": False,
    },
    "safety": {
        "require_authorization": True,
        "allow_loopback": True,
        "allow_private_ranges": True,
        "block_cloud_metadata": True,
        "max_requests_per_host": 0,
        "kill_switch_file": "",
        "confirm_exploit": True,
    },
    "tui": {"enabled": False, "refresh_ms": 250},
    "engine": {"enabled": False, "parallel": True, "url": "http://127.0.0.1:8787", "timeout": 2.0, "use_subprocess": True, "auto_start": False},
    "integrations": {
        "sarif": True,
        "webhook": "",
        "defectdojo_url": "",
        "jira_url": "",
    },
}

PROFILES: dict[str, dict[str, Any]] = {
    "safe": {
        "http": {"timeout": 15.0, "retries": 0},
        "scan": {"max_rps": 2.0, "burst": 2, "concurrency": 4, "max_requests": 5000, "deadline_seconds": 900},
        "detect": {"intrusive": False, "time_based": False, "safe_mode": True, "max_payloads_per_param": 4},
        "exploit": {"enabled": False},
        "recon": {"max_crawl_pages": 50},
    },
    "standard": {
        "scan": {"max_rps": 5.0, "burst": 5, "concurrency": 8, "max_requests": 20000},
        "detect": {"intrusive": True, "time_based": True, "safe_mode": True},
        "exploit": {"enabled": False},
    },
    "aggressive": {
        "http": {"timeout": 8.0, "retries": 2},
        "scan": {"max_rps": 15.0, "burst": 15, "concurrency": 16, "max_requests": 100000, "waf_evasion": True},
        "detect": {"intrusive": True, "time_based": True, "max_payloads_per_param": 30, "safe_mode": True},
        "exploit": {"enabled": True, "allow_data_access": True},
    },
    "lab": {
        "http": {"verify_tls": False, "timeout": 5.0},
        "scan": {"max_rps": 25.0, "burst": 25, "concurrency": 12, "max_requests": 50000, "respect_robots": False},
        "detect": {"intrusive": True, "time_based": True, "max_payloads_per_param": 30, "safe_mode": False},
        "exploit": {
            "enabled": True,
            "allow_data_access": True,
            "allow_write": True,
            "allow_command_execution": True,
            "require_confirmation": False,
        },
        "safety": {"block_cloud_metadata": False},
        "logging": {"level": "debug"},
    },
}

_ALLOWED_KEYS: set[str] = {key for key in DEFAULTS}
_ALLOWED_SUBKEYS: dict[str, set[str]] = {
    key: set(value.keys()) for key, value in DEFAULTS.items() if isinstance(value, dict)
}


def _deep_merge(base: dict[str, Any], overlay: Mapping[str, Any], *, path: str = "") -> dict[str, Any]:
    result = copy.deepcopy(base)
    for key, value in overlay.items():
        dotted = f"{path}.{key}" if path else key
        if key not in result:
            raise ConfigError(f"unknown configuration key: {dotted}")
        if isinstance(result[key], dict) and isinstance(value, Mapping):
            result[key] = _deep_merge(result[key], value, path=dotted)
        else:
            result[key] = copy.deepcopy(value)
    return result


@dataclass
class Config:
    """Resolved configuration with dotted access."""

    data: dict[str, Any] = field(default_factory=lambda: copy.deepcopy(DEFAULTS))
    sources: list[str] = field(default_factory=list)
    path: str = ""

    # ------------------------------------------------------------------
    # constructors
    # ------------------------------------------------------------------
    @classmethod
    def defaults(cls) -> "Config":
        return cls()

    @classmethod
    def profile(cls, name: str) -> "Config":
        name = (name or "standard").lower()
        if name not in PROFILES:
            raise ConfigError(f"unknown profile: {name}", available=", ".join(sorted(PROFILES)))
        config = cls()
        config.data["profile"] = name
        config.data = _deep_merge(config.data, PROFILES[name])
        config.sources.append(f"profile:{name}")
        return config

    @classmethod
    def load(
        cls,
        path: str | Path | None = None,
        *,
        profile: str | None = None,
        overrides: Mapping[str, Any] | None = None,
        use_env: bool = True,
    ) -> "Config":
        base_profile = profile or "standard"
        config = cls.profile(base_profile)
        if path:
            file = Path(path)
            if not file.exists():
                raise ConfigError(f"configuration file not found: {file}")
            if tomllib is None:
                raise ConfigError(
                    f"configuration file {file} requires TOML support (Python 3.11+ tomllib or tomli package). "
                    f"Running on Python {sys.version_info.major}.{sys.version_info.minor}; upgrade to 3.11+ or install tomli."
                )
            try:
                payload = tomllib.loads(file.read_text(encoding="utf-8"))
            except Exception as exc:  # TOMLDecodeError or AttributeError when tomllib is None
                # Preserve original message if it's a decode error
                if tomllib is not None and hasattr(tomllib, "TOMLDecodeError") and isinstance(exc, tomllib.TOMLDecodeError):
                    raise ConfigError(f"invalid TOML in {file}: {exc}") from exc
                raise ConfigError(f"invalid TOML in {file}: {exc}") from exc
            config.data = _deep_merge(config.data, payload)
            config.path = str(file)
            config.sources.append(str(file))
            if "profile" in payload and payload["profile"] != base_profile:
                config.data["profile"] = payload["profile"]
                config.data = _deep_merge(config.data, PROFILES.get(payload["profile"], {}))
        if use_env:
            env = _env_overrides()
            if env:
                config.data = _deep_merge(config.data, env)
                config.sources.append("environment")
        if overrides:
            config.data = _deep_merge(config.data, _expand_overrides(overrides))
            config.sources.append("cli")
        config.validate()
        return config

    # ------------------------------------------------------------------
    # access
    # ------------------------------------------------------------------
    def get(self, dotted: str, default: Any = None) -> Any:
        node: Any = self.data
        for part in dotted.split("."):
            if not isinstance(node, Mapping) or part not in node:
                return default
            node = node[part]
        return node

    def section(self, name: str) -> dict[str, Any]:
        value = self.data.get(name, {})
        if not isinstance(value, dict):
            raise ConfigError(f"configuration section {name!r} is not a table")
        return dict(value)

    def set(self, dotted: str, value: Any) -> None:
        parts = dotted.split(".")
        node = self.data
        for part in parts[:-1]:
            if part not in node or not isinstance(node[part], dict):
                raise ConfigError(f"unknown configuration section: {part}")
            node = node[part]
        if parts[-1] not in node:
            raise ConfigError(f"unknown configuration key: {dotted}")
        node[parts[-1]] = value

    def with_overrides(self, overrides: Mapping[str, Any]) -> "Config":
        clone = Config(data=_deep_merge(self.data, _expand_overrides(overrides)), sources=list(self.sources))
        clone.validate()
        return clone

    def to_dict(self) -> dict[str, Any]:
        return copy.deepcopy(self.data)

    # ------------------------------------------------------------------
    # validation
    # ------------------------------------------------------------------
    def validate(self) -> None:
        profile = self.data.get("profile", "standard")
        if profile not in PROFILES:
            raise ConfigError(f"unknown profile: {profile}")
        numeric_bounds = {
            "http.timeout": (0.5, 120.0),
            "http.connect_timeout": (0.5, 60.0),
            "http.max_redirects": (0, 20),
            "http.max_body_bytes": (4096, 50_000_000),
            "http.retries": (0, 5),
            "scan.max_requests": (1, 5_000_000),
            "scan.max_rps": (0.1, 200.0),
            "scan.burst": (1, 500),
            "scan.concurrency": (1, 128),
            "scan.max_depth": (0, 20),
            "scan.max_pages": (1, 100_000),
            "scan.max_endpoints": (1, 100_000),
            "scan.deadline_seconds": (0, 86_400),
            "detect.max_payloads_per_param": (1, 500),
            "detect.max_params_per_endpoint": (1, 1000),
            "exploit.max_proofs": (0, 1000),
            "exploit.timeout": (1.0, 120.0),
            "evidence.max_body_bytes": (256, 1_000_000),
            "recon.max_crawl_pages": (1, 100_000),
            "recon.max_subdomains": (1, 100_000),
        }
        for key, (low, high) in numeric_bounds.items():
            value = self.get(key)
            if not isinstance(value, (int, float)):
                raise ConfigError(f"{key} must be numeric")
            if value < low or value > high:
                raise ConfigError(f"{key} must be between {low} and {high}, got {value}")
        for key in ("detect.min_severity", "report.min_severity"):
            from candix.core.severity import Severity

            try:
                Severity.parse(str(self.get(key)))
            except Exception as exc:
                raise ConfigError(f"{key} is not a valid severity: {self.get(key)!r}") from exc
        from candix.core.severity import Confidence

        try:
            Confidence.parse(str(self.get("detect.min_confidence")))
        except ValueError as exc:
            raise ConfigError(f"detect.min_confidence is invalid: {exc}") from exc
        if not isinstance(self.get("report.formats"), list) or not self.get("report.formats"):
            raise ConfigError("report.formats must be a non-empty list")
        for fmt in self.get("report.formats"):
            if fmt not in {"html", "json", "markdown", "sarif", "csv", "junit"}:
                raise ConfigError(f"unsupported report format: {fmt}")
        if self.get("exploit.enabled") and not self.get("detect.intrusive"):
            raise ConfigError("exploitation requires active detection (detect.intrusive)")
        if self.get("scan.max_rps") > 20.0 and self.get("profile") == "safe":
            raise ConfigError("the safe profile cannot exceed 20 rps")
        if self.get("safety.require_authorization") is False:
            raise ConfigError(
                "authorization checks cannot be disabled through configuration; "
                "use the lab profile with loopback targets"
            )
        proxy = self.get("http.proxy", "")
        if proxy and not str(proxy).startswith(("http://", "https://", "socks5://")):
            raise ConfigError("http.proxy must be an http(s) or socks5 URL")

    # ------------------------------------------------------------------
    def describe(self) -> str:
        return (
            f"profile={self.get('profile')} rps={self.get('scan.max_rps')} "
            f"concurrency={self.get('scan.concurrency')} "
            f"exploit={'on' if self.get('exploit.enabled') else 'off'} "
            f"sources={','.join(self.sources) or 'defaults'}"
        )


def _expand_overrides(overrides: Mapping[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in overrides.items():
        if "." in key:
            parts = key.split(".")
            node = result
            for part in parts[:-1]:
                node = node.setdefault(part, {})
            node[parts[-1]] = value
        else:
            result[key] = value
    return result


def _env_overrides(environ: Mapping[str, str] | None = None) -> dict[str, Any]:
    environ = environ or os.environ
    result: dict[str, Any] = {}
    for name, value in environ.items():
        if not name.startswith("CANDIX_"):
            continue
        path = name[len("CANDIX_"):].lower().split("__")
        if len(path) < 2:
            continue
        node = result
        for part in path[:-1]:
            if part not in _ALLOWED_SUBKEYS.get(path[0], set()) and part != path[0]:
                node = None
                break
            node = node.setdefault(part, {})
        if node is None:
            continue
        node[path[-1]] = _coerce(value)
    return result


def _coerce(value: str) -> Any:
    lowered = value.strip().lower()
    if lowered in {"true", "yes", "on"}:
        return True
    if lowered in {"false", "no", "off"}:
        return False
    if lowered in {"null", "none"}:
        return None
    try:
        if "." in value:
            return float(value)
        return int(value)
    except ValueError:
        pass
    if value.startswith(("[", "{")):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return value
    return value


def merge_configs(*configs: Config) -> Config:
    merged = Config()
    for config in configs:
        merged.data = _deep_merge(merged.data, config.data)
    merged.validate()
    return merged


def config_for_lab() -> Config:
    return Config.profile("lab")


def resolve_dir(config: Config, key: str, base: Path | None = None) -> Path:
    raw = str(config.get(key, "") or "")
    path = Path(raw or key.split(".")[-1])
    if not path.is_absolute() and base is not None:
        path = base / path
    return path


def iter_sections() -> Iterable[str]:
    return (key for key, value in DEFAULTS.items() if isinstance(value, dict))
