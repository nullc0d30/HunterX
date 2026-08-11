# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Cloud intelligence tool registry.

Defines the canonical ``cloud-analysis`` tool id, the adapter factory and the
``register_cloud_adapters`` entry point used by the platform assembler to wire
the adapter into the Tool Integration SDK execution engine.
"""

from __future__ import annotations

from collections.abc import Mapping

from hunterx.tools.cloud.analyzer import CloudAnalyzerAdapter
from hunterx.tools.cloud.base import CloudToolAdapter
from hunterx.tools.sdk.engine import ExecutionEngine

#: Canonical cloud intelligence tool ids.
CLOUD_TOOL_IDS: tuple[str, ...] = ("cloud-analysis",)


class CloudAdapterFactory:
    """Build cloud tool adapters for the execution engine."""

    def build(self) -> dict[str, CloudToolAdapter]:
        """Return a fresh adapter mapping for every registered cloud tool."""
        return {tool_id: adapter() for tool_id, adapter in _ADAPTERS.items()}

    def create(self, tool_id: str) -> CloudToolAdapter:
        """Create the adapter for ``tool_id`` (raises ``KeyError`` when unknown)."""
        if tool_id not in _ADAPTERS:
            raise KeyError(f"unknown cloud tool: {tool_id}")
        return _ADAPTERS[tool_id]()


_ADAPTERS: dict[str, type[CloudToolAdapter]] = {
    "cloud-analysis": CloudAnalyzerAdapter,
}


def cloud_adapters() -> dict[str, CloudToolAdapter]:
    """Return a fresh mapping of every cloud tool adapter."""
    return {tool_id: adapter() for tool_id, adapter in _ADAPTERS.items()}


def register_cloud_adapters(engine: ExecutionEngine) -> Mapping[str, CloudToolAdapter]:
    """Register every cloud adapter into ``engine`` and return the mapping."""
    adapters = cloud_adapters()
    for tool_id, adapter in adapters.items():
        engine.register_adapter(tool_id, adapter)
    return adapters
