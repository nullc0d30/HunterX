# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Parameter discovery tool adapter registry.

Builds and registers the parameter discovery adapters (arjun, paramspider,
kiterunner) on an :class:`~hunterx.tools.sdk.engine.ExecutionEngine`.
"""

from __future__ import annotations

from collections.abc import Mapping

from hunterx.tools.parameter.adapters import ArjunAdapter, KiterunnerAdapter, ParamspiderAdapter
from hunterx.tools.parameter.base import ParameterToolAdapter
from hunterx.tools.sdk.engine import ExecutionEngine

#: Canonical order and set of the integrated parameter discovery tools.
PARAMETER_TOOL_IDS: tuple[str, ...] = ("arjun", "paramspider", "kiterunner")


class ParameterAdapterFactory:
    """Instantiate the parameter discovery tool adapters."""

    def build(self) -> dict[str, ParameterToolAdapter]:
        """Return a fresh set of parameter adapters keyed by tool id."""
        return {
            "arjun": ArjunAdapter(),
            "paramspider": ParamspiderAdapter(),
            "kiterunner": KiterunnerAdapter(),
        }

    def create(self, tool_id: str) -> ParameterToolAdapter:
        """Return a single adapter instance for ``tool_id``."""
        adapters = self.build()
        if tool_id not in adapters:
            raise KeyError(f"unknown parameter tool '{tool_id}'")
        return adapters[tool_id]


def parameter_adapters() -> dict[str, ParameterToolAdapter]:
    """Return a fresh mapping of parameter tool id to adapter instance."""
    return ParameterAdapterFactory().build()


def register_parameter_adapters(engine: ExecutionEngine) -> Mapping[str, ParameterToolAdapter]:
    """Register every parameter adapter on ``engine`` and return the mapping."""
    adapters = parameter_adapters()
    for tool_id, adapter in adapters.items():
        engine.register_adapter(tool_id, adapter)
    return adapters
