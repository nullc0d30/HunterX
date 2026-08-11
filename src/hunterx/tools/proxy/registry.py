# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Proxy tool adapter registry.

Builds and registers the proxy/interception adapters (zap, mitmproxy) on an
:class:`~hunterx.tools.sdk.engine.ExecutionEngine`.
"""

from __future__ import annotations

from collections.abc import Mapping

from hunterx.tools.proxy.adapters import MitmproxyAdapter, ProxyToolAdapter, ZapAdapter
from hunterx.tools.sdk.engine import ExecutionEngine

#: Canonical order and set of the integrated proxy tools.
PROXY_TOOL_IDS: tuple[str, ...] = ("zap", "mitmproxy")


class ProxyAdapterFactory:
    """Instantiate the proxy tool adapters."""

    def build(self) -> dict[str, ProxyToolAdapter]:
        """Return a fresh set of proxy adapters keyed by tool id."""
        return {
            "zap": ZapAdapter(),
            "mitmproxy": MitmproxyAdapter(),
        }

    def create(self, tool_id: str) -> ProxyToolAdapter:
        """Return a single adapter instance for ``tool_id``."""
        adapters = self.build()
        if tool_id not in adapters:
            raise KeyError(f"unknown proxy tool '{tool_id}'")
        return adapters[tool_id]


def proxy_adapters() -> dict[str, ProxyToolAdapter]:
    """Return a fresh mapping of proxy tool id to adapter instance."""
    return ProxyAdapterFactory().build()


def register_proxy_adapters(engine: ExecutionEngine) -> Mapping[str, ProxyToolAdapter]:
    """Register every proxy adapter on ``engine`` and return the mapping."""
    adapters = proxy_adapters()
    for tool_id, adapter in adapters.items():
        engine.register_adapter(tool_id, adapter)
    return adapters
