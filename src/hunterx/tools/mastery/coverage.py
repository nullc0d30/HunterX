# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Arsenal coverage engine.

Classifies how completely HunterX supports each tool and reports capability
coverage. Never awards FULLY_SUPPORTED for "the binary can execute"; full
support requires execution, parsing, normalization, capability knowledge,
evidence mapping, error handling, version handling, scope, safety and tests.
"""

from __future__ import annotations

import threading
from datetime import UTC, datetime

from hunterx.domain.tool_mastery import (
    ToolCoverageReport,
    ToolSupportLevel,
)
from hunterx.tools.mastery.registry import ToolMasteryRegistry


class ToolCoverageEngine:
    """Compute arsenal and capability coverage from a master-profile registry.

    Args:
        registry: the :class:`ToolMasteryRegistry` to analyze.

    """

    def __init__(self, registry: ToolMasteryRegistry) -> None:
        self._registry = registry
        self._lock = threading.RLock()
        self._canonical_capabilities: tuple[str, ...] = ()

    def set_capability_universe(self, capabilities: list[str]) -> None:
        """Declare the canonical capability set used to find gaps."""
        with self._lock:
            self._canonical_capabilities = tuple(dict.fromkeys(capabilities))

    def report(self) -> ToolCoverageReport:
        """Compute the current coverage report."""
        profiles = self._registry.list()

        by_level: dict[str, int] = {}
        tools_by_capability: dict[str, list[str]] = {}
        capability_coverage: dict[str, list[str]] = {}

        for profile in profiles:
            by_level[profile.support_level.value] = by_level.get(profile.support_level.value, 0) + 1
            capabilities = profile.capability_ids or profile.knowledge.capabilities
            tools_by_capability[profile.tool_id] = list(capabilities)
            for capability in capabilities:
                capability_coverage.setdefault(capability, []).append(profile.tool_id)

        covered = set(capability_coverage)
        with self._lock:
            universe = set(self._canonical_capabilities)
        gaps = tuple(sorted(universe - covered)) if universe else ()

        return ToolCoverageReport(
            total_tools=len(profiles),
            by_support_level=dict(sorted(by_level.items())),
            capability_coverage={k: tuple(sorted(v)) for k, v in sorted(capability_coverage.items())},
            capability_gaps=gaps,
            tools_by_capability={k: tuple(v) for k, v in sorted(tools_by_capability.items())},
            report_timestamp=datetime.now(UTC).isoformat(),
        )

    def supported_count(self) -> int:
        """Return how many tools are FULLY_SUPPORTED."""
        return len(self._registry.by_support_level(ToolSupportLevel.FULLY_SUPPORTED))

    def capability_gaps(self) -> tuple[str, ...]:
        """Return capabilities with no provider."""
        return self.report().capability_gaps

    def full_support_ids(self) -> tuple[str, ...]:
        """Return tool ids classified as FULLY_SUPPORTED."""
        return self._registry.by_support_level(ToolSupportLevel.FULLY_SUPPORTED)

    def _universe(self) -> tuple[str, ...]:
        with self._lock:
            return self._canonical_capabilities
