# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""JavaScript intelligence tool adapter registry.

Builds and registers the JavaScript intelligence adapters (the in-process
analyzer) on an :class:`~hunterx.tools.sdk.engine.ExecutionEngine`. This is the
single place that knows the JavaScript tool set, so callers (tests, the
JavaScript service, the platform) never construct individual adapters.
"""

from __future__ import annotations

from collections.abc import Mapping

from hunterx.tools.javascript.analyzer import JavaScriptAnalyzerAdapter
from hunterx.tools.javascript.external import (
    LinkFinderAdapter,
    SecretFinderAdapter,
    XnLinkFinderAdapter,
)
from hunterx.tools.sdk.adapter import ToolAdapter
from hunterx.tools.sdk.engine import ExecutionEngine

#: Canonical order and set of the integrated JavaScript intelligence tools.
JS_TOOL_IDS: tuple[str, ...] = (
    "javascript",
    "linkfinder",
    "secretfinder",
    "xnlinkfinder",
)


class JavaScriptAdapterFactory:
    """Instantiate the JavaScript intelligence tool adapters."""

    def build(self) -> dict[str, ToolAdapter]:
        """Return a fresh set of JavaScript adapters keyed by tool id."""
        return {
            "javascript": JavaScriptAnalyzerAdapter(),
            "linkfinder": LinkFinderAdapter(),
            "secretfinder": SecretFinderAdapter(),
            "xnlinkfinder": XnLinkFinderAdapter(),
        }

    def create(self, tool_id: str) -> ToolAdapter:
        """Return a single adapter instance for ``tool_id``."""
        adapters = self.build()
        if tool_id not in adapters:
            raise KeyError(f"unknown JavaScript tool '{tool_id}'")
        return adapters[tool_id]


def javascript_adapters() -> dict[str, ToolAdapter]:
    """Return a fresh mapping of JavaScript tool id to adapter instance."""
    return JavaScriptAdapterFactory().build()


def register_javascript_adapters(engine: ExecutionEngine) -> Mapping[str, ToolAdapter]:
    """Register every JavaScript adapter on ``engine`` and return the mapping."""
    adapters = javascript_adapters()
    for tool_id, adapter in adapters.items():
        engine.register_adapter(tool_id, adapter)
    return adapters
