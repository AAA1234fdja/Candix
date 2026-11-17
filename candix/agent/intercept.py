"""Decide whether a command, a target or a tool call may proceed.

The rules here are deterministic on purpose: no model scores risk, and the same
input always produces the same answer with the same reasons. The rules mirror the
Go gate in ``engine/intercept/`` and ``engine/guard/``; this module is an
independent Python implementation for this codebase.

When ``candix.engine_bridge`` is enabled (``engine.enabled=true`` or
``CANDIX_ENGINE_URL``), risk scoring can be delegated to the Go engine via
``EngineClient``/``InterceptProxy`` with a Python fallback — the two
implementations are kept in sync by ``engine/cmd/bridge`` tests.
"""

from __future__ import annotations

import ipaddress
import re
import shlex
from dataclasses import dataclass, field
from typing import Any, Iterable
from urllib.parse import urlsplit

RISK_MEDIUM = 30
RISK_HIGH = 70
RISK_MAX = 100

SHELL_BASE = 10
FILE_BASE = 30
FILE_SENSITIVE = 40
WEB_BASE = 10
WEB_MUTATING = 30
UNKNOWN_BASE = 30


def level_of(score: int) -> str:
    if score >= RISK_HIGH:
        return "high"
    if score >= RISK_MEDIUM:
        return "medium"
    return "low"


@dataclass
class RiskReport:
    score: int
    level: str = ""
    reasons: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.score = max(0, min(RISK_MAX, int(self.score)))
        if not self.level:
            self.level = level_of(self.score)

    @property
    def dangerous(self) -> bool:
        return self.score >= RISK_HIGH

    def to_dict(self) -> dict[str, Any]:
        return {"score": self.score, "level": self.level, "reasons": list(self.reasons)}

    def describe(self) -> str:
        if not self.reasons:
            return f"risk {self.score} ({self.level}), no signal matched"
        return f"risk {self.score} ({self.level}): " + "; ".join(self.reasons)


@dataclass(frozen=True)
class Signal:
    reason: str
    points: int
    pattern: re.Pattern[str]


def _signal(reason: str, points: int, pattern: str) -> Signal:
    return Signal(reason, points, re.compile(pattern, re.IGNORECASE))


SHELL_SIGNALS: tuple[Signal, ...] = (
    _signal(
        "destructive command (recursive rm, dd, mkfs, shred, truncate, DROP/DELETE, shutdown)",
        60,
        r"\brm\s+([^;&|]*\s)?(-[a-z]*r[a-z]*|--recursive)(\s|$)|\bdd\s+[^;&|]*\b(if|of)=|\bmkfs\b|"
        r"\bshred\b|\btruncate\b|\bdrop\s+table\b|\bdelete\s+from\b|\bshutdown\b",
    ),
    _signal("privilege change (sudo, su, chmod 777, setcap)", 40, r"(^|[\s;&|(])(sudo|su)(\s|$)|\bchmod\s+(-\w+\s+)*0?777\b|\bsetcap\b"),
    _signal("reads secrets (/etc/shadow, .ssh, .aws/credentials, .git-credentials)", 40, r"/etc/shadow|\.ssh/|\.aws/credentials|\.git-credentials"),
    _signal(
        "possible exfiltration (curl upload, scp, remote rsync, nc, socat)",
        40,
        r"\bcurl\b[^;&|]*\s(-d|--data[\w-]*|-F|--form|-T|--upload-file)(\s|=|$)|\bscp\b|\brsync\b[^;&|]*\s\S+:|\bnc\b|\bncat\b|\bsocat\b",
    ),
    _signal("reverse shell pattern (/dev/tcp, nc -e)", 60, r"/dev/tcp/|\b(nc|ncat)\b[^;&|]*\s-e(\s|$)"),
    _signal("network scanner (nmap, nuclei, sqlmap, ffuf, hydra, masscan, dalfox)", 30, r"\b(nmap|nuclei|sqlmap|ffuf|hydra|masscan|dalfox)\b"),
)

TEE = re.compile(r"(^|[|;&]\s*)tee\b", re.IGNORECASE)
SENSITIVE_PATH = re.compile(
    r"(^|/)(\.ssh|\.aws|\.gnupg)/|^/etc/|^/root/|^/boot/|/\.git-credentials$|/\.(bashrc|bash_profile|profile|zshrc)$|/authorized_keys$|(^|/)\.env$"
)


def writes_file(command: str) -> bool:
    """Redirection to a file, or tee. ``2>&1`` and ``/dev/null`` are not writes."""

    if TEE.search(command):
        return True
    for index, char in enumerate(command):
        if char != ">":
            continue
        rest = command[index + 1 :].lstrip(">").lstrip(" \t")
        if not rest or rest.startswith("&") or rest.startswith("/dev/null"):
            continue
        return True
    return False


def score_command(command: str) -> RiskReport:
    score = SHELL_BASE
    reasons: list[str] = []
    for signal in SHELL_SIGNALS:
        if signal.pattern.search(command):
            score += signal.points
            reasons.append(signal.reason)
    if writes_file(command):
        score += 15
        reasons.append("writes files (redirection or tee)")
    return RiskReport(score, reasons=reasons)


def score_file_write(path: str) -> RiskReport:
    score = FILE_BASE
    reasons = ["writes or edits a file"]
    if SENSITIVE_PATH.search(path or ""):
        score += FILE_SENSITIVE
        reasons.append("sensitive path (system, credential or shell startup file)")
    return RiskReport(score, reasons=reasons)


def score_web(method: str) -> RiskReport:
    verb = (method or "GET").upper()
    if verb in {"POST", "PUT", "PATCH", "DELETE"}:
        return RiskReport(WEB_BASE + WEB_MUTATING, reasons=[f"mutating HTTP method {verb}"])
    return RiskReport(WEB_BASE)


INTENT_TOOL_MAP = {
    "shell": "command",
    "http.request": "web",
    "http.batch": "web",
    "http.replay": "web",
    "web.probe": "web",
    "exploit.run": "command",
    "fuzz.run": "command",
}


def score_tool(tool: str, arguments: dict[str, Any] | None = None) -> RiskReport:
    payload = arguments or {}
    if tool in {"command", "shell"}:
        return score_command(str(payload.get("command", "")))
    if tool in {"write", "edit"}:
        return score_file_write(str(payload.get("path", payload.get("file_path", ""))))
    if tool in {"http.request", "http.batch", "http.replay", "web.probe", "WebFetch", "web_search"}:
        return score_web(str(payload.get("method", "GET")))
    if tool == "exploit.run":
        return score_command(f"{payload.get('max_attempts', 1)} exploit {payload.get('min_severity', '')}")
    return RiskReport(UNKNOWN_BASE, reasons=[f"unrecognized tool {tool}: no specific rules"])


def score_intent(intent: Any) -> RiskReport:
    """Risk of one agent intent, expressed on the 0..100 scale with reasons."""

    tool = str(getattr(intent, "tool", "") or "")
    arguments = dict(getattr(intent, "arguments", {}) or {})
    report = score_tool(tool, arguments)
    phase = str(getattr(getattr(intent, "phase", ""), "value", getattr(intent, "phase", "")) or "")
    score = report.score
    reasons = list(report.reasons)
    if phase == "exploit":
        score += 20
        reasons.append("exploit phase")
    elif phase == "detect":
        score += 5
    chain = arguments.get("urls") or arguments.get("targets")
    if isinstance(chain, (list, tuple)) and len(chain) > 10:
        score += 10
        reasons.append(f"batch of {len(chain)} targets")
    return RiskReport(score, reasons=reasons)


# ---------------------------------------------------------------------------
# argv prefixes


ARGV_ARITY: dict[str, int] = {
    "cat": 1,
    "cd": 1,
    "ls": 1,
    "rm": 1,
    "grep": 1,
    "head": 1,
    "tail": 1,
    "echo": 1,
    "pwd": 1,
    "find": 1,
    "curl": 1,
    "wget": 1,
    "nmap": 1,
    "dig": 1,
    "whois": 1,
    "git": 2,
    "npm": 2,
    "docker": 2,
    "kubectl": 2,
    "terraform": 2,
    "npm run": 3,
    "docker compose": 3,
    "kubectl rollout": 3,
    "git config": 3,
    "gcloud": 3,
    "gh": 3,
    "aws": 3,
}

CHAIN_PATTERN = re.compile(r"(\|\||&&|[|;]|\$\(|`)")


def program_name(token: str) -> str:
    """Basename, lower case, no version suffix, every ``mkfs.*`` reduced to mkfs."""

    name = (token or "").split("/")[-1].lower()
    if name.startswith("mkfs."):
        return "mkfs"
    end = len(name)
    while end > 0 and (name[end - 1] == "." or name[end - 1].isdigit()):
        end -= 1
    return name[:end] if 0 < end < len(name) else name


def split_command(command: str) -> list[str]:
    try:
        return shlex.split(command, posix=True)
    except ValueError:
        return (command or "").split()


def argv_prefix(command: str) -> str:
    """The human prefix of a command: program plus its subcommands."""

    tokens = split_command(command)
    if not tokens:
        return ""
    program = program_name(tokens[0])
    joined = program
    arity = ARGV_ARITY.get(program, 1)
    for token in tokens[1:]:
        if token.startswith("-"):
            break
        candidate = f"{joined} {token.lower()}"
        if candidate in ARGV_ARITY:
            joined = candidate
            arity = ARGV_ARITY[candidate]
            continue
        if len(joined.split()) < arity:
            joined = candidate
            continue
        break
    return joined


def prefix_matches(command: str, allowed: Iterable[str]) -> tuple[bool, str]:
    prefix = argv_prefix(command)
    for entry in allowed:
        rule = " ".join(program_name(part) if index == 0 else part.lower() for index, part in enumerate(str(entry).split()))
        if prefix == rule or prefix.startswith(rule + " "):
            return True, rule
    return False, ""


# ---------------------------------------------------------------------------
# always-allow denylist


ALWAYS_ALLOW_DENY: frozenset[str] = frozenset(
    set(
        """
        sh bash zsh dash ksh fish csh tcsh ash mksh rbash pwsh powershell python pypy ipython perl ruby irb
        node deno bun php lua luajit tclsh wish expect awk gawk mawk nawk sed jshell osascript
        env command builtin exec eval source nohup timeout nice ionice stdbuf setsid chroot unshare nsenter
        systemd-run su sudo doas pkexec runuser setpriv watch busybox toybox xargs parallel
        make gmake find ssh scp sftp rsync socat ncat nc netcat flock strace ltrace gdb
        npm npx pnpm yarn bunx corepack pip pipx uv uvx poetry conda composer gem bundle rake cargo go
        mvn gradle dotnet apt apt-get dpkg dnf yum rpm pacman apk brew snap flatpak
        docker docker-compose podman nerdctl kubectl helm ansible ansible-playbook terraform pulumi vagrant
        rm dd mkfs mkswap wipefs fdisk sfdisk parted shred truncate chmod chown kill pkill killall
        systemctl service iptables ip6tables nft ufw mount umount swapoff shutdown reboot poweroff halt
        crontab insmod rmmod modprobe
        """.split()
    )
)


@dataclass
class Decision:
    allowed: bool
    reason: str = ""
    rule: str = ""
    risk: RiskReport | None = None
    prefix: str = ""

    def __post_init__(self) -> None:
        if self.risk is not None:
            self.risk = self.risk if isinstance(self.risk, RiskReport) else RiskReport(int(self.risk))

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "reason": self.reason,
            "rule": self.rule,
            "prefix": self.prefix,
            "risk": self.risk.to_dict() if self.risk else {},
        }

    def describe(self) -> str:
        head = "allow" if self.allowed else "block"
        extra = f" [{self.rule}]" if self.rule else ""
        return f"{head}{extra}: {self.reason}"


class AlwaysAllowDeny:
    """An argv allow rule never covers an interpreter, a launcher or a package manager."""

    def __init__(self, *, deny: Iterable[str] = ALWAYS_ALLOW_DENY, max_risk: int = RISK_HIGH) -> None:
        self.deny = frozenset(deny)
        self.max_risk = max_risk

    def check(self, command: str, *, allowed_prefixes: Iterable[str] = ()) -> Decision:
        text = (command or "").strip()
        if not text:
            return Decision(False, "empty command", "empty", RiskReport(0))
        report = score_command(text)
        prefix = argv_prefix(text)
        program = program_name(split_command(text)[0]) if split_command(text) else prefix
        if program in self.deny:
            return Decision(False, f"{program} runs arbitrary code or does unbounded damage", "denylist", report, prefix)
        if CHAIN_PATTERN.search(text):
            head = split_command(text)[0] if split_command(text) else program
            if program_name(head) in self.deny:
                return Decision(False, "chained command starts with a denied program", "denylist", report, prefix)
        rules = list(allowed_prefixes)
        if rules:
            ok, rule = prefix_matches(text, rules)
            if not ok:
                return Decision(False, f"prefix '{prefix}' is not in the allowlist", "allowlist", report, prefix)
            if report.score >= self.max_risk:
                return Decision(False, f"risk {report.score} at or above {self.max_risk}", "risk", report, prefix)
            return Decision(True, f"matched allow rule '{rule}' (risk {report.score})", "allowlist", report, prefix)
        if report.score >= self.max_risk:
            return Decision(False, f"risk {report.score} at or above {self.max_risk}: {report.reasons[0]}", "risk", report, prefix)
        return Decision(True, f"no rule matched; risk {report.score}", "default", report, prefix)


# ---------------------------------------------------------------------------
# target normalisation and gating

DEFAULT_PORTS = {"http": 80, "https": 443, "ws": 80, "wss": 443, "ftp": 21, "ssh": 22}
METADATA_HOSTS = frozenset({"metadata.google.internal", "metadata", "instance-data"})
METADATA_IPS = frozenset({ipaddress.ip_address("169.254.169.254"), ipaddress.ip_address("fd00:ec2::254")})


@dataclass(frozen=True)
class Target:
    kind: str
    host: str
    port: int = 0

    @property
    def key(self) -> str:
        return f"{self.host}:{self.port}" if self.port else self.host

    def to_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "host": self.host, "port": self.port}


def _normalise_ipv4(token: str) -> str:
    """Decimal, hex, octal and short IPv4 forms become dotted quads."""

    parts = token.split(".")
    if len(parts) == 4 and all(part.isdigit() and len(part) > 1 and part.startswith("0") for part in parts):
        return ".".join(str(int(part, 8)) if part.isdigit() else part for part in parts)
    try:
        if token.startswith("0x") or token[:2].lower() == "0x":
            return str(ipaddress.ip_address(int(token, 16)))
        if token.isdigit() and len(token) <= 10 and int(token) > 0xFFFFFF:
            return str(ipaddress.ip_address(int(token)))
    except (ValueError, ipaddress.AddressValueError):
        return token
    return token


def normalise_target(value: str) -> Target | None:
    text = (value or "").strip()
    if not text:
        return None
    if "/" in text and not text.startswith(("http://", "https://", "ws://", "wss://")):
        try:
            network = ipaddress.ip_network(text, strict=False)
            return Target("cidr", str(network))
        except ValueError:
            pass
    scheme = ""
    port = 0
    if "://" in text:
        parsed = urlsplit(text)
        scheme = parsed.scheme.lower()
        host = parsed.hostname or ""
        port = parsed.port or DEFAULT_PORTS.get(scheme, 0)
    else:
        host = text
        if host.startswith("[") and "]" in host:
            host, _, rest = host[1:].partition("]")
            if rest.startswith(":") and rest[1:].isdigit():
                port = int(rest[1:])
        elif host.count(":") == 1:
            name, _, tail = host.partition(":")
            if tail.isdigit():
                host = name
                port = int(tail)
    host = host.strip().rstrip(".").lower()
    if not host:
        return None
    host = _normalise_ipv4(host)
    try:
        address = ipaddress.ip_address(host)
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
            address = address.ipv4_mapped
        return Target("ip", str(address), port)
    except ValueError:
        pass
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        pass
    return Target("domain", host, port)


@dataclass
class TargetGate:
    """Allow only the hosts the engagement named, and never the metadata plane."""

    allow: tuple[str, ...] = ()
    allow_private: bool = False
    allow_ports: tuple[int, ...] = ()
    block_metadata: bool = True

    def _explicit(self, host: str) -> bool:
        return bool(self.allow) and self._allowed_host(host, 0)

    def _allowed_host(self, host: str, port: int) -> bool:
        for entry in self.allow:
            rule = normalise_target(entry)
            if rule is None:
                continue
            if rule.kind == "cidr":
                try:
                    if ipaddress.ip_address(host) in ipaddress.ip_network(rule.host, strict=False):
                        return True
                except ValueError:
                    continue
            elif rule.kind == "domain":
                if host == rule.host or host.endswith("." + rule.host):
                    return True
            elif rule.host == host:
                return True
        return False

    def check(self, value: str) -> Decision:
        target = normalise_target(value)
        if target is None:
            return Decision(False, "unparseable target", "target", RiskReport(RISK_HIGH))
        if self.allow and not self._allowed_host(target.host, target.port):
            return Decision(False, f"{target.key} is outside the declared scope", "scope", RiskReport(RISK_HIGH))
        if self.allow_ports and target.port and target.port not in self.allow_ports:
            return Decision(False, f"port {target.port} is not allowed", "port", RiskReport(60))
        if target.kind == "ip":
            address = ipaddress.ip_address(target.host)
            if self.block_metadata and (address in METADATA_IPS):
                return Decision(False, "cloud metadata address", "metadata", RiskReport(RISK_HIGH))
            explicitly_allowed = self._explicit(target.host)
            if not (self.allow_private or explicitly_allowed) and (
                address.is_private or address.is_loopback or address.is_link_local or address.is_reserved
            ):
                return Decision(False, f"{target.host} is a private or reserved address", "private", RiskReport(60))
            if address.is_multicast:
                return Decision(False, "multicast target", "multicast", RiskReport(60))
        if target.kind == "domain" and target.host in METADATA_HOSTS:
            return Decision(False, "cloud metadata hostname", "metadata", RiskReport(RISK_HIGH))
        return Decision(True, f"{target.key} is in scope", "scope", RiskReport(10), prefix=target.key)


@dataclass
class AuditEntry:
    subject: str
    allowed: bool
    reason: str
    rule: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"subject": self.subject, "allowed": self.allowed, "reason": self.reason, "rule": self.rule}


_URL_PATTERN = re.compile(r"(?:https?|wss?)://[^\s'\"`<>|;]+", re.IGNORECASE)
_IPV4_PATTERN = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}(?::\d{1,5})?\b")


def command_targets(command: str) -> list[str]:
    """The targets a command names, so the target gate sees the real subject.

    A command does not carry its target in a separate argument: it carries it in
    the argv, in a URL, an IP, a ``host:port``. Extracting them here is what stops
    ``curl https://metadata.google.internal`` from passing on risk alone.
    """

    candidates: list[str] = []
    for match in _URL_PATTERN.findall(command or ""):
        candidates.append(match.rstrip(".,)"))
    for match in _IPV4_PATTERN.findall(command or ""):
        candidates.append(match)
    return list(dict.fromkeys(candidates))


class CommandGate:
    """One entry point for command execution decisions, with an audit trail."""

    def __init__(
        self,
        *,
        allowed_prefixes: Iterable[str] = (),
        max_risk: int = RISK_HIGH,
        targets: Iterable[str] = (),
        allow_private: bool = False,
        allow_ports: Iterable[int] = (),
        block_metadata: bool = True,
    ) -> None:
        self.rules = AlwaysAllowDeny(max_risk=max_risk)
        self.allowed_prefixes = tuple(allowed_prefixes)
        self.target_gate = TargetGate(
            allow=tuple(targets),
            allow_private=allow_private,
            allow_ports=tuple(allow_ports),
            block_metadata=block_metadata,
        )
        self.audit: list[AuditEntry] = []

    def check(self, command: str, *, targets: Iterable[str] = ()) -> Decision:
        decision = self.rules.check(command, allowed_prefixes=self.allowed_prefixes)
        self.audit.append(AuditEntry(command[:160], decision.allowed, decision.reason, decision.rule))
        if not decision.allowed:
            return decision
        declared = [str(item) for item in targets] or command_targets(command)
        for candidate in declared:
            target_decision = self.target_gate.check(candidate)
            if not target_decision.allowed:
                blocked = Decision(False, target_decision.reason, "target", decision.risk, decision.prefix)
                self.audit[-1] = AuditEntry(command[:160], False, blocked.reason, "target")
                return blocked
        return decision

    def summary(self) -> dict[str, Any]:
        blocked = [item for item in self.audit if not item.allowed]
        return {"checked": len(self.audit), "blocked": len(blocked), "entries": [item.to_dict() for item in self.audit[-20:]]}


def explain(command: str) -> str:
    report = score_command(command)
    lines = [f"{command[:80]} → {report.describe()}", f"prefix: {argv_prefix(command) or 'n/a'}"]
    decision = AlwaysAllowDeny().check(command)
    lines.append(decision.describe())
    return "\n".join(lines)

# ---------------------------------------------------------------------------
# Go engine bridge (optional delegation)
# ---------------------------------------------------------------------------

def score_via_engine(tool: str, arguments: dict[str, Any] | None = None) -> tuple[bool, Any]:
    """Try to score via Go engine bridge, falling back to Python.

    Returns (used_go: bool, report: RiskReport|BridgeResult).
    When the bridge is disabled or unavailable, returns (False, python_report).
    """
    try:
        from candix.engine_bridge.config import BridgeConfig
        from candix.engine_bridge.client import EngineClient

        cfg = BridgeConfig()
        # Allow env override
        import os
        if os.environ.get("CANDIX_ENGINE_URL"):
            cfg.url = os.environ["CANDIX_ENGINE_URL"]
            cfg.enabled = True
        if os.environ.get("CANDIX_ENGINE_ENABLED", "").lower() in {"1","true","yes","on"}:
            cfg.enabled = True
        if not cfg.enabled and not cfg.use_subprocess:
            raise RuntimeError("bridge disabled")
        client = EngineClient(cfg)
        # Use Go subprocess path (no HTTP needed)
        result = client.score_risk(tool, arguments or {})
        if result.ok and result.source.startswith("go"):
            # Adapt Go report to Python RiskReport shape
            return True, result
    except Exception:
        pass
    # fallback
    return False, score_tool(tool, arguments)

