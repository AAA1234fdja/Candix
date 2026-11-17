"""Candix - authorization-gated red team harness.

The package is intentionally dependency-free: every network primitive, parser,
detector and report renderer is implemented against the Python standard
library so that the harness can run from an air-gapped operator workstation.
"""

from __future__ import annotations

__all__ = [
    "AUTHORIZATION_NOTICE",
    "VERSION",
    "build_context",
]

VERSION = "0.1.0"

AUTHORIZATION_NOTICE = (
    "Candix performs active security testing. Use it only against systems for "
    "which you hold written authorization. Every run requires a rules of "
    "engagement file and an explicit scope."
)


def build_context(*args, **kwargs):
    """Lazily import :class:`candix.core.context.ScanContext`.

    Importing the context eagerly would pull the whole detector graph into
    processes that only need the version metadata (for example packaging
    tools), so the import is deferred.
    """

    from candix.core.context import ScanContext

    return ScanContext(*args, **kwargs)
