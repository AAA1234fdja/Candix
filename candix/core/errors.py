"""Exception hierarchy used across the harness.

Every error carries a stable ``code`` so that the CLI can translate failures
into exit codes and the report can explain why a module was skipped instead of
silently swallowing the problem.
"""

from __future__ import annotations

from typing import Any


class CandixError(Exception):
    """Base class for all harness errors."""

    code = "candix.error"
    exit_code = 1

    def __init__(self, message: str, **context: Any) -> None:
        super().__init__(message)
        self.message = message
        self.context = context

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "message": self.message,
            "context": self.context,
        }

    def __str__(self) -> str:  # pragma: no cover - trivial
        if not self.context:
            return self.message
        pairs = ", ".join(f"{key}={value!r}" for key, value in sorted(self.context.items()))
        return f"{self.message} ({pairs})"


class ConfigError(CandixError):
    code = "candix.config"
    exit_code = 2


class AuthorizationError(CandixError):
    code = "candix.authorization"
    exit_code = 3


class ScopeViolation(CandixError):
    code = "candix.scope"
    exit_code = 3


class TargetUnreachable(CandixError):
    code = "candix.network.unreachable"
    exit_code = 4


class ProtocolError(CandixError):
    code = "candix.network.protocol"
    exit_code = 4


class RateLimited(CandixError):
    code = "candix.network.rate_limited"
    exit_code = 4


class BudgetExceeded(CandixError):
    code = "candix.budget"
    exit_code = 5


class ParseError(CandixError):
    code = "candix.parse"
    exit_code = 6


class PluginError(CandixError):
    code = "candix.plugin"
    exit_code = 7


class ReportError(CandixError):
    code = "candix.report"
    exit_code = 8


class VerificationError(CandixError):
    code = "candix.verification"
    exit_code = 9


class UnsupportedTarget(CandixError):
    code = "candix.target.unsupported"
    exit_code = 10


class LabError(CandixError):
    code = "candix.lab"
    exit_code = 11
