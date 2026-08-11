# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Content discovery tool adapter registry.

Builds and registers the content discovery adapters (ffuf) on an
:class:`~hunterx.tools.sdk.engine.ExecutionEngine`. This is the single place
that knows the content tool set, so callers (tests, the arsenal orchestrator,
the platform) never construct individual adapters.
"""

from __future__ import annotations

from collections.abc import Mapping

from hunterx.tools.content.base import ContentToolAdapter
from hunterx.tools.content.bruteforcers import (
    DirsearchAdapter,
    FeroxbusterAdapter,
    GobusterAdapter,
)
from hunterx.tools.content.ffuf import FfufAdapter
from hunterx.tools.sdk.engine import ExecutionEngine

#: Canonical order and set of the integrated content discovery tools.
CONTENT_TOOL_IDS: tuple[str, ...] = ("ffuf", "gobuster", "feroxbuster", "dirsearch")


class ContentAdapterFactory:
    """Instantiate the content discovery tool adapters."""

    def build(self) -> dict[str, ContentToolAdapter]:
        """Return a fresh set of content adapters keyed by tool id."""
        return {
            "ffuf": FfufAdapter(),
            "gobuster": GobusterAdapter(),
            "feroxbuster": FeroxbusterAdapter(),
            "dirsearch": DirsearchAdapter(),
        }

    def create(self, tool_id: str) -> ContentToolAdapter:
        """Return a single adapter instance for ``tool_id``."""
        adapters = self.build()
        if tool_id not in adapters:
            raise KeyError(f"unknown content tool '{tool_id}'")
        return adapters[tool_id]


def content_adapters() -> dict[str, ContentToolAdapter]:
    """Return a fresh mapping of content tool id to adapter instance."""
    return ContentAdapterFactory().build()


def register_content_adapters(engine: ExecutionEngine) -> Mapping[str, ContentToolAdapter]:
    """Register every content adapter on ``engine`` and return the mapping."""
    adapters = content_adapters()
    for tool_id, adapter in adapters.items():
        engine.register_adapter(tool_id, adapter)
    return adapters
