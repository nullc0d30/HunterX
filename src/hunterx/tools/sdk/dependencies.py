# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Execution dependency resolver.

Resolves the tools that must be installed and healthy before ``tool_id`` can
run. Built on the TIP dependency engine (capability graph) and the SDK
installation manager, so a missing prerequisite blocks the execution pipeline
before anything is spawned.
"""

from __future__ import annotations

from hunterx.domain.exceptions import ToolDependencyError, ToolNotFoundError
from hunterx.domain.execution import FailureKind
from hunterx.tools.intelligence.dependency import DependencyEngine
from hunterx.tools.intelligence.registry import ToolIntelligenceRegistry
from hunterx.tools.sdk.installer import InstallationManager


class DependencyResolver:
    """Combine capability dependencies with installation state.

    Usage::

        resolver = DependencyResolver(registry, installer)
        missing = resolver.unmet(tool_id)          # list of tool ids to install
        resolver.assert_satisfied(tool_id)          # raises ToolDependencyError
    """

    def __init__(
        self,
        registry: ToolIntelligenceRegistry,
        installer: InstallationManager,
    ) -> None:
        self._engine = DependencyEngine(registry)
        self._installer = installer

    def prerequisites(self, tool_id: str) -> list[str]:
        """Return tool ids that must run before ``tool_id`` (transitive).

        Tools unknown to the intelligence registry are treated as having no
        dependency requirements (best-effort resolution).
        """
        try:
            return self._engine.resolve_dependencies(tool_id)
        except ToolNotFoundError:
            return []

    def unmet(self, tool_id: str) -> list[str]:
        """Return prerequisites that are not installed and functional."""
        unmet: list[str] = []
        for prerequisite in self.prerequisites(tool_id):
            if not self._installer.is_installed(prerequisite):
                unmet.append(prerequisite)
        return unmet

    def assert_satisfied(self, tool_id: str) -> None:
        """Raise :class:`ToolDependencyError` when prerequisites are missing.

        The failure kind is ``INSTALLATION_REQUIRED`` so the pipeline can
        classify the execution as installable rather than permanent.
        """
        missing = self.unmet(tool_id)
        if missing:
            raise ToolDependencyError(tool_id, missing=missing)

    def classify_failure(self, error: Exception) -> FailureKind:
        """Map a dependency failure to a retryable failure kind."""
        return FailureKind.INSTALLATION_REQUIRED if isinstance(error, ToolDependencyError) else FailureKind.UNKNOWN
