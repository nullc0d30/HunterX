# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Safe validation tool adapter registry.

Registers the built-in safe validation adapters on an
:class:`~hunterx.tools.sdk.engine.ExecutionEngine`. This is the single place
that knows the safe-validation tool set, so callers (the validation engine,
tests, the platform) never construct individual adapters.
"""

from __future__ import annotations

from collections.abc import Mapping

from hunterx.tools.safe_validation.adapters import (
    ValidationToolAdapter,
    validation_adapters,
)
from hunterx.tools.sdk.engine import ExecutionEngine

#: Canonical order and set of the built-in safe-validation tools.
VALIDATION_TOOL_IDS: tuple[str, ...] = (
    "passive-probe",
    "version-probe",
    "error-behavior-probe",
)


class ValidationAdapterFactory:
    """Instantiate the safe validation tool adapters."""

    def build(self) -> dict[str, ValidationToolAdapter]:
        """Return a fresh set of validation adapters keyed by tool id."""
        return validation_adapters()

    def create(self, tool_id: str) -> ValidationToolAdapter:
        """Return a single adapter instance for ``tool_id``."""
        adapters = self.build()
        if tool_id not in adapters:
            raise KeyError(f"unknown validation tool '{tool_id}'")
        return adapters[tool_id]


def register_validation_adapters(engine: ExecutionEngine) -> Mapping[str, ValidationToolAdapter]:
    """Register every safe validation adapter on ``engine`` and return them."""
    adapters = validation_adapters()
    for tool_id, adapter in adapters.items():
        engine.register_adapter(tool_id, adapter)
    return adapters


__all__ = [
    "VALIDATION_TOOL_IDS",
    "ValidationAdapterFactory",
    "register_validation_adapters",
]
