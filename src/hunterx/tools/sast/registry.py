# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""SAST tool adapter registry.

Builds and registers the SAST adapters (semgrep) on an
:class:`~hunterx.tools.sdk.engine.ExecutionEngine`.
"""

from __future__ import annotations

from collections.abc import Mapping

from hunterx.tools.sast.semgrep import SemgrepAdapter
from hunterx.tools.sdk.engine import ExecutionEngine
from hunterx.tools.vuln.scanbase import VulnerabilityScanAdapter

#: Canonical order and set of the integrated SAST tools.
SAST_TOOL_IDS: tuple[str, ...] = ("semgrep",)


class SastAdapterFactory:
    """Instantiate the SAST tool adapters."""

    def build(self) -> dict[str, VulnerabilityScanAdapter]:
        """Return a fresh set of SAST adapters keyed by tool id."""
        return {"semgrep": SemgrepAdapter()}

    def create(self, tool_id: str) -> VulnerabilityScanAdapter:
        """Return a single adapter instance for ``tool_id``."""
        adapters = self.build()
        if tool_id not in adapters:
            raise KeyError(f"unknown SAST tool '{tool_id}'")
        return adapters[tool_id]


def sast_adapters() -> dict[str, VulnerabilityScanAdapter]:
    """Return a fresh mapping of SAST tool id to adapter instance."""
    return SastAdapterFactory().build()


def register_sast_adapters(engine: ExecutionEngine) -> Mapping[str, VulnerabilityScanAdapter]:
    """Register every SAST adapter on ``engine`` and return the mapping."""
    adapters = sast_adapters()
    for tool_id, adapter in adapters.items():
        engine.register_adapter(tool_id, adapter)
    return adapters
