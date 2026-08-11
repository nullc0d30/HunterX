# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Live Host & Service Discovery tool adapter registry.

Builds and registers the live discovery tool adapters (nmap binary, naabu
binary, masscan binary and the in-process TCP-connect probe) on an
:class:`~hunterx.tools.sdk.engine.ExecutionEngine`. This is the single place
that knows the live discovery tool set, so callers (tests, the live host
service, the platform) never construct individual adapters.
"""

from __future__ import annotations

from collections.abc import Mapping

from hunterx.tools.livehost.base import LiveToolAdapter
from hunterx.tools.livehost.masscan import MasscanAdapter
from hunterx.tools.livehost.naabu import NaabuAdapter
from hunterx.tools.livehost.nmap import NmapAdapter
from hunterx.tools.livehost.rustscan import RustScanAdapter
from hunterx.tools.livehost.tcp_connect import TcpConnectAdapter
from hunterx.tools.sdk.engine import ExecutionEngine

#: Canonical order and set of the integrated live discovery tools.
LIVE_TOOL_IDS: tuple[str, ...] = (
    "nmap",
    "naabu",
    "masscan",
    "rustscan",
    "tcp-connect",
)


class LiveAdapterFactory:
    """Instantiate the live discovery tool adapters."""

    def build(self) -> dict[str, LiveToolAdapter]:
        """Return a fresh set of live discovery adapters keyed by tool id."""
        return {
            "nmap": NmapAdapter(),
            "naabu": NaabuAdapter(),
            "masscan": MasscanAdapter(),
            "rustscan": RustScanAdapter(),
            "tcp-connect": TcpConnectAdapter(),
        }

    def create(self, tool_id: str) -> LiveToolAdapter:
        """Return a single adapter instance for ``tool_id``."""
        adapters = self.build()
        if tool_id not in adapters:
            raise KeyError(f"unknown live discovery tool '{tool_id}'")
        return adapters[tool_id]


def live_adapters() -> dict[str, LiveToolAdapter]:
    """Return a fresh mapping of live discovery tool id to adapter instance."""
    return LiveAdapterFactory().build()


def register_live_adapters(engine: ExecutionEngine) -> Mapping[str, LiveToolAdapter]:
    """Register every live discovery adapter on ``engine`` and return the mapping."""
    adapters = live_adapters()
    for tool_id, adapter in adapters.items():
        engine.register_adapter(tool_id, adapter)
    return adapters
