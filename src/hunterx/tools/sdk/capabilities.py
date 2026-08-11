# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Capability registry.

Maps capability ids to the tools that provide them and records which
capabilities an execution requires. Used by the dependency resolver and the
execution pipeline to decide tool eligibility before running.
"""

from __future__ import annotations

import threading
from collections import defaultdict


class ExecutionCapabilityRegistry:
    """Thread-safe registry of capability → provider tool ids.

    Usage::

        registry = ExecutionCapabilityRegistry()
        registry.register("web.scan", "httpx")
        registry.providers_for("web.scan")   # ["httpx"]
    """

    def __init__(self) -> None:
        self._providers: dict[str, set[str]] = defaultdict(set)
        self._capabilities: dict[str, set[str]] = defaultdict(set)
        self._lock = threading.RLock()

    def register(self, tool_id: str, capabilities: list[str]) -> None:
        """Record that ``tool_id`` provides ``capabilities``."""
        with self._lock:
            for capability in capabilities:
                self._providers[capability].add(tool_id)
                self._capabilities[tool_id].add(capability)

    def providers_for(self, capability_id: str) -> list[str]:
        """Return the registered provider tool ids for ``capability_id``."""
        with self._lock:
            return sorted(self._providers.get(capability_id, ()))

    def capabilities_for(self, tool_id: str) -> list[str]:
        """Return the capabilities provided by ``tool_id``."""
        with self._lock:
            return sorted(self._capabilities.get(tool_id, ()))

    def can_provide(self, capability_id: str, tool_id: str) -> bool:
        """Return ``True`` when ``tool_id`` is a registered provider."""
        with self._lock:
            return tool_id in self._providers.get(capability_id, set())

    def capabilities(self) -> list[str]:
        """Return all known capability ids, sorted."""
        with self._lock:
            return sorted(self._providers)
