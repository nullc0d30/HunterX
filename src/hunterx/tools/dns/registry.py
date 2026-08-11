# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""DNS tool adapter registry.

Builds and registers the DNS tool adapters (dnsx binary + dnspython-based
active resolver) on an :class:`~hunterx.tools.sdk.engine.ExecutionEngine`.
This is the single place that knows the DNS tool set, so callers (tests, the
DNS service, the platform) never construct individual adapters.
"""

from __future__ import annotations

from collections.abc import Mapping

from hunterx.tools.dns.base import DnsToolAdapter
from hunterx.tools.dns.dnspython import DnspythonAdapter
from hunterx.tools.dns.dnsx import DnsxAdapter
from hunterx.tools.dns.massdns import MassdnsAdapter
from hunterx.tools.dns.shuffledns import ShufflednsAdapter
from hunterx.tools.sdk.engine import ExecutionEngine

#: Canonical order and set of the integrated DNS tools.
DNS_TOOL_IDS: tuple[str, ...] = (
    "dnsx",
    "dnspython",
    "massdns",
    "shuffledns",
)


class DnsAdapterFactory:
    """Instantiate the DNS tool adapters."""

    def build(self) -> dict[str, DnsToolAdapter]:
        """Return a fresh set of DNS adapters keyed by tool id."""
        return {
            "dnsx": DnsxAdapter(),
            "dnspython": DnspythonAdapter(),
            "massdns": MassdnsAdapter(),
            "shuffledns": ShufflednsAdapter(),
        }

    def create(self, tool_id: str) -> DnsToolAdapter:
        """Return a single adapter instance for ``tool_id``."""
        adapters = self.build()
        if tool_id not in adapters:
            raise KeyError(f"unknown DNS tool '{tool_id}'")
        return adapters[tool_id]


def dns_adapters() -> dict[str, DnsToolAdapter]:
    """Return a fresh mapping of DNS tool id to adapter instance."""
    return DnsAdapterFactory().build()


def register_dns_adapters(engine: ExecutionEngine) -> Mapping[str, DnsToolAdapter]:
    """Register every DNS adapter on ``engine`` and return the mapping."""
    adapters = dns_adapters()
    for tool_id, adapter in adapters.items():
        engine.register_adapter(tool_id, adapter)
    return adapters
