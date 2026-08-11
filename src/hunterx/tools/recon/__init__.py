# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Reconnaissance tool integrations.

SDK adapters for the six recon tools HunterX integrates (subfinder, amass,
assetfinder, findomain, bbot, theHarvester). Every adapter runs through the
Tool Integration SDK pipeline and produces canonical
:class:`~hunterx.domain.recon.models.DiscoveryRecord` observations.
"""

from __future__ import annotations

from hunterx.tools.recon.registry import (
    RECON_TOOL_IDS,
    ReconAdapterFactory,
    recon_adapters,
    register_recon_adapters,
)
from hunterx.tools.recon.tip import ReconToolSpec, recon_tool_specs, register_recon_tools

__all__ = [
    "RECON_TOOL_IDS",
    "ReconAdapterFactory",
    "ReconToolSpec",
    "recon_adapters",
    "recon_tool_specs",
    "register_recon_adapters",
    "register_recon_tools",
]
