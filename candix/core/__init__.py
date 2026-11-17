"""Core primitives shared by every Candix subsystem."""

from __future__ import annotations

from candix.core.errors import (
    AuthorizationError,
    BudgetExceeded,
    CandixError,
    ConfigError,
    ParseError,
    PluginError,
    ProtocolError,
    RateLimited,
    ReportError,
    ScopeViolation,
    TargetUnreachable,
    UnsupportedTarget,
    VerificationError,
)

__all__ = [
    "AuthorizationError",
    "BudgetExceeded",
    "CandixError",
    "ConfigError",
    "ParseError",
    "PluginError",
    "ProtocolError",
    "RateLimited",
    "ReportError",
    "ScopeViolation",
    "TargetUnreachable",
    "UnsupportedTarget",
    "VerificationError",
]
