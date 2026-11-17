"""Mutation fuzzer: feeds mutated values into every discovered parameter."""

from __future__ import annotations

from candix.fuzz.runner import run_fuzz
from candix.fuzz.model import FuzzCase, FuzzResult, FuzzSignal

__all__ = ["FuzzCase", "FuzzResult", "FuzzSignal", "run_fuzz"]
