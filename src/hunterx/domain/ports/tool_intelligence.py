# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tool Intelligence port.

The Tool Intelligence API contract. Every HunterX subsystem that needs to
answer questions about tools (planner, AI engine, workflow engine, CLI, API)
SHALL depend on this port and receive a concrete implementation (the TIP
facade) through composition.
"""

from __future__ import annotations

import abc

from hunterx.domain.tool_intelligence import (
    ToolCompatibility,
    ToolHealthStats,
    ToolKnowledge,
    ToolMetadata,
    ToolPerformanceStats,
    ToolRecommendation,
    ToolSelectionCriteria,
    ToolSelectionResult,
    ToolTaxonomyNode,
)


class ToolIntelligencePort(abc.ABC):
    """Query surface for tool intelligence.

    The port is deliberately read-focused: subsystems ask questions and
    receive structured answers. Mutating operations (register, install,
    record health) happen through dedicated managers, not this port.
    """

    # -- registry ----------------------------------------------------------

    @abc.abstractmethod
    def get_tool(self, tool_id: str) -> ToolMetadata | None:
        """Return metadata for ``tool_id`` or ``None``."""

    @abc.abstractmethod
    def list_tools(self) -> list[ToolMetadata]:
        """Return metadata for every registered tool."""

    @abc.abstractmethod
    def get_knowledge(self, tool_id: str) -> ToolKnowledge | None:
        """Return the knowledge profile for ``tool_id`` or ``None``."""

    @abc.abstractmethod
    def search_tools(self, term: str) -> list[ToolMetadata]:
        """Return tools whose id/name/tags match ``term``."""

    # -- capabilities and taxonomy ----------------------------------------

    @abc.abstractmethod
    def tools_by_capability(self, capability_id: str) -> list[str]:
        """Return tool ids that provide ``capability_id``."""

    @abc.abstractmethod
    def capabilities(self) -> list[str]:
        """Return the known capability ids."""

    @abc.abstractmethod
    def taxonomy(self) -> ToolTaxonomyNode:
        """Return the root of the tool taxonomy tree."""

    # -- analysis ----------------------------------------------------------

    @abc.abstractmethod
    def resolve_dependencies(self, tool_id: str) -> list[str]:
        """Return tool ids that must run before ``tool_id`` (topological)."""

    @abc.abstractmethod
    def check_compatibility(
        self,
        tool_id: str,
        *,
        os_name: str = "",
        architecture: str = "",
        docker: bool = False,
        air_gapped: bool = False,
        cloud: bool = False,
    ) -> ToolCompatibility:
        """Return the compatibility assessment for ``tool_id``."""

    @abc.abstractmethod
    def health(self, tool_id: str) -> ToolHealthStats | None:
        """Return live health stats for ``tool_id`` or ``None``."""

    @abc.abstractmethod
    def performance(self, tool_id: str) -> ToolPerformanceStats | None:
        """Return historical performance stats for ``tool_id`` or ``None``."""

    # -- decision support --------------------------------------------------

    @abc.abstractmethod
    def select(self, criteria: ToolSelectionCriteria) -> list[ToolSelectionResult]:
        """Rank tools matching ``criteria``, best first."""

    @abc.abstractmethod
    def recommend(self, capability_id: str) -> list[ToolRecommendation]:
        """Return recommendations (best/alternative/fallback/...) for a capability."""
