"""Vulnerability detectors.

Each module in this package defines one detector class decorated with
``@register_detector``. Importing the package does not import every detector;
:data:`candix.detectors.base.DETECTORS` is lazy and loads modules on demand.
"""

from __future__ import annotations

from candix.detectors.base import BaseDetector, DetectorMeta, DETECTORS, register_detector

__all__ = ["BaseDetector", "DetectorMeta", "DETECTORS", "register_detector"]
