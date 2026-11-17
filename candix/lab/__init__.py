"""Deliberately vulnerable lab application.

The lab exists so the harness can be demonstrated and regression-tested without
touching a real customer. It binds to loopback by default, contains no
destructive primitives, and each vulnerability is isolated to a documented
route. Never deploy it on a routable interface.
"""

from __future__ import annotations

from candix.lab.app import LabServer, build_server

__all__ = ["LabServer", "build_server"]
