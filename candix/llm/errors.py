"""Errors raised by the model layer.

Every provider maps its transport and protocol failures onto this small tree so
the agent loop can make one decision instead of one per provider: retry, shrink
the context, fall back to another model, or stop.
"""

from __future__ import annotations

from candix.core.errors import CandixError


class LLMError(CandixError):
    """Base class for model-facing failures."""

    retryable = False

    def __init__(self, message: str, *, provider: str = "", model: str = "", status: int = 0) -> None:
        super().__init__(message)
        self.provider = provider
        self.model = model
        self.status = status


class ConfigurationError(LLMError):
    """The provider is missing credentials, a base URL or a required setting."""


class TransportError(LLMError):
    """The request never reached a usable response (DNS, TLS, timeouts, 5xx)."""

    retryable = True


class RateLimitError(LLMError):
    """The provider asked us to slow down."""

    retryable = True

    def __init__(self, message: str, *, retry_after: float | None = None, **kwargs: object) -> None:
        super().__init__(message, **kwargs)  # type: ignore[arg-type]
        self.retry_after = retry_after


class AuthenticationError(LLMError):
    """Credentials were rejected; retrying cannot help."""


class ContextLengthError(LLMError):
    """The prompt did not fit; the caller must truncate or summarise."""


class ContentFilterError(LLMError):
    """The provider refused the content.

    Security tooling trips this regularly, so the agent treats it as a routing
    signal (different model or narrower prompt) rather than a fatal error.
    """


class ToolCallError(LLMError):
    """The model produced a tool call that cannot be executed."""


class BudgetExhausted(LLMError):
    """A token, cost or request budget is spent."""


class ParseError(LLMError):
    """The provider returned a body that is not valid JSON for its schema."""
