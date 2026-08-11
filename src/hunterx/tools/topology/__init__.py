# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Network mapping & attack-surface topology tool adapters.

SDK tool adapters for route-mapping: traceroute (primary, plain-text contract
covering hop-by-hop routes). All external invocations flow through the shared
:class:`~hunterx.tools.recon.runner.BinaryRunner` seam; adapters serialize
canonical route records under the pipeline payload's ``routes`` key.
"""

from hunterx.tools.topology.base import TopologyToolAdapter
from hunterx.tools.topology.models import RouteRecord, routes_from_payload, routes_to_payload
from hunterx.tools.topology.registry import (
    TOPOLOGY_TOOL_IDS,
    TopologyAdapterFactory,
    register_topology_adapters,
    topology_adapters,
)
from hunterx.tools.topology.tip import TopologyToolSpec, register_topology_tools, topology_tool_specs
from hunterx.tools.topology.traceroute import TracerouteAdapter

__all__ = [
    "RouteRecord",
    "TOPOLOGY_TOOL_IDS",
    "TopologyAdapterFactory",
    "TopologyToolAdapter",
    "TopologyToolSpec",
    "TracerouteAdapter",
    "register_topology_adapters",
    "register_topology_tools",
    "routes_from_payload",
    "routes_to_payload",
    "topology_adapters",
    "topology_tool_specs",
]
