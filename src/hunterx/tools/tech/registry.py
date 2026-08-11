# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Technology fingerprinting tool adapter registry.

Builds and registers the fingerprinting tool adapters (httpx binary, whatweb
binary and the in-process signature detector) on an
:class:`~hunterx.tools.sdk.engine.ExecutionEngine`. This is the single place
that knows the fingerprinting tool set, so callers (tests, the fingerprinting
service, the platform) never construct individual adapters.
"""

from __future__ import annotations

from collections.abc import Mapping

from hunterx.domain.ports.messaging import CachePort
from hunterx.tools.sdk.engine import ExecutionEngine
from hunterx.tools.tech.base import TechToolAdapter
from hunterx.tools.tech.httpx import HttpxAdapter
from hunterx.tools.tech.signature import SignatureAdapter
from hunterx.tools.tech.whatweb import WhatWebAdapter

#: Canonical order and set of the integrated fingerprinting tools.
TECH_TOOL_IDS: tuple[str, ...] = (
    "httpx",
    "whatweb",
    "signature",
)


class TechAdapterFactory:
    """Instantiate the technology fingerprinting tool adapters."""

    def build(self, *, cache: CachePort | None = None) -> dict[str, TechToolAdapter]:
        """Return a fresh set of fingerprinting adapters keyed by tool id."""
        return {
            "httpx": HttpxAdapter(),
            "whatweb": WhatWebAdapter(),
            "signature": SignatureAdapter(cache=cache),
        }

    def create(self, tool_id: str) -> TechToolAdapter:
        """Return a single adapter instance for ``tool_id``."""
        adapters = self.build()
        if tool_id not in adapters:
            raise KeyError(f"unknown fingerprinting tool '{tool_id}'")
        return adapters[tool_id]


def tech_adapters(*, cache: CachePort | None = None) -> dict[str, TechToolAdapter]:
    """Return a fresh mapping of fingerprinting tool id to adapter instance."""
    return TechAdapterFactory().build(cache=cache)


def register_tech_adapters(
    engine: ExecutionEngine,
    *,
    cache: CachePort | None = None,
) -> Mapping[str, TechToolAdapter]:
    """Register every fingerprinting adapter on ``engine`` and return the mapping."""
    adapters = tech_adapters(cache=cache)
    for tool_id, adapter in adapters.items():
        engine.register_adapter(tool_id, adapter)
    return adapters
