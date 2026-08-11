# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Recon tool adapter registry.

Builds and registers the six recon adapters on an
:class:`~hunterx.tools.sdk.engine.ExecutionEngine`. This is the single place
that knows the recon tool set, so callers (tests, the recon service, the
platform) never construct individual adapters.
"""

from __future__ import annotations

from collections.abc import Mapping

from hunterx.tools.recon.amass import AmassAdapter
from hunterx.tools.recon.assetfinder import AssetfinderAdapter
from hunterx.tools.recon.base import ReconToolAdapter
from hunterx.tools.recon.bbot import BbotAdapter
from hunterx.tools.recon.findomain import FindomainAdapter
from hunterx.tools.recon.subfinder import SubfinderAdapter
from hunterx.tools.recon.theharvester import TheHarvesterAdapter
from hunterx.tools.sdk.engine import ExecutionEngine

#: Canonical order and set of the integrated recon tools.
RECON_TOOL_IDS: tuple[str, ...] = (
    "subfinder",
    "amass",
    "assetfinder",
    "findomain",
    "bbot",
    "theharvester",
)


class ReconAdapterFactory:
    """Instantiate the six recon tool adapters."""

    def build(self) -> dict[str, ReconToolAdapter]:
        """Return a fresh set of recon adapters keyed by tool id."""
        adapters: dict[str, ReconToolAdapter] = {
            "subfinder": SubfinderAdapter(),
            "amass": AmassAdapter(),
            "assetfinder": AssetfinderAdapter(),
            "findomain": FindomainAdapter(),
            "bbot": BbotAdapter(),
            "theharvester": TheHarvesterAdapter(),
        }
        return adapters

    def create(self, tool_id: str) -> ReconToolAdapter:
        """Return a single adapter instance for ``tool_id``."""
        adapters = self.build()
        if tool_id not in adapters:
            raise KeyError(f"unknown recon tool '{tool_id}'")
        return adapters[tool_id]


def recon_adapters() -> dict[str, ReconToolAdapter]:
    """Return a fresh mapping of recon tool id to adapter instance."""
    return ReconAdapterFactory().build()


def register_recon_adapters(engine: ExecutionEngine) -> Mapping[str, ReconToolAdapter]:
    """Register every recon adapter on ``engine`` and return the mapping."""
    adapters = recon_adapters()
    for tool_id, adapter in adapters.items():
        engine.register_adapter(tool_id, adapter)
    return adapters
