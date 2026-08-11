# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Topology tool adapter registry.

Builds and registers the topology route-mapping adapters on an
:class:`~hunterx.tools.sdk.engine.ExecutionEngine`. This is the single place
that knows the topology tool set; callers never construct individual adapters.
"""

from __future__ import annotations

from collections.abc import Mapping

from hunterx.tools.sdk.engine import ExecutionEngine
from hunterx.tools.topology.base import TopologyToolAdapter
from hunterx.tools.topology.traceroute import TracerouteAdapter

#: Canonical set of the integrated topology tools.
TOPOLOGY_TOOL_IDS: tuple[str, ...] = ("traceroute",)


class TopologyAdapterFactory:
    """Instantiate the topology tool adapters."""

    def build(self) -> dict[str, TopologyToolAdapter]:
        """Return a fresh set of topology adapters keyed by tool id."""
        return {"traceroute": TracerouteAdapter()}

    def create(self, tool_id: str) -> TopologyToolAdapter:
        """Return a single adapter instance for ``tool_id``."""
        adapters = self.build()
        if tool_id not in adapters:
            raise KeyError(f"unknown topology tool '{tool_id}'")
        return adapters[tool_id]


def topology_adapters() -> dict[str, TopologyToolAdapter]:
    """Return a fresh mapping of topology tool id to adapter instance."""
    return TopologyAdapterFactory().build()


def register_topology_adapters(engine: ExecutionEngine) -> Mapping[str, TopologyToolAdapter]:
    """Register every topology adapter on ``engine`` and return the mapping."""
    adapters = topology_adapters()
    for tool_id, adapter in adapters.items():
        engine.register_adapter(tool_id, adapter)
    return adapters
