# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Mission preflight.

The readiness gate between mission planning and execution:

    Mission created
         ↓
    Required capabilities calculated (from the adaptive plan)
         ↓
    Tool readiness checked
         ↓
    Missing tools provisioned (when supported)
         ↓
    Tools verified
         ↓
    Mission execution unlocked (or explicitly blocked/degraded)

Capabilities are classified ``required`` / ``recommended`` / ``optional``.
A required capability with no available provider blocks the mission with an
explicit, machine-readable reason. Recommended/optional gaps degrade the
mission (reduced coverage) but never silently abort it.
"""

from __future__ import annotations

from typing import Any

from hunterx.tools.readiness.models import (
    CapabilityLevel,
    PreflightResult,
    PreflightStatus,
    ToolReadinessStatus,
)


class MissionCapabilityResolver:
    """Resolve mission capability requirements to importance levels.

    The planner determines the required capabilities; this resolver attaches
    the importance (required/recommended/optional) and the provider tool ids.
    """

    def __init__(
        self,
        capability_providers: dict[str, tuple[str, ...]] | None = None,
        capability_levels: dict[str, CapabilityLevel] | None = None,
    ) -> None:
        self._providers = dict(capability_providers or {})
        self._levels = dict(capability_levels or {})

    def levels_for(self, capabilities: list[str]) -> dict[str, CapabilityLevel]:
        """Return the importance level for each capability (required default)."""
        return {capability: self._levels.get(capability, CapabilityLevel.REQUIRED) for capability in capabilities}

    def providers_for(self, capability: str) -> tuple[str, ...]:
        """Return the registered provider tool ids for ``capability``."""
        return self._providers.get(capability, ())

    def candidate_tools(self, capabilities: list[str]) -> list[str]:
        """Return the deduplicated candidate tool ids for ``capabilities``."""
        candidates: list[str] = []
        for capability in capabilities:
            for tool_id in self.providers_for(capability):
                if tool_id not in candidates:
                    candidates.append(tool_id)
        return candidates


class MissionPreflight:
    """Compute mission preflight verdicts from capability requirements.

    Args:
        capability_providers: planner capability → provider tool ids.
        capability_levels: planner capability → importance level.

    """

    def __init__(
        self,
        capability_providers: dict[str, tuple[str, ...]] | None = None,
        capability_levels: dict[str, CapabilityLevel] | None = None,
    ) -> None:
        self._resolver = MissionCapabilityResolver(capability_providers, capability_levels)

    def levels_for(self, capabilities: list[str]) -> dict[str, CapabilityLevel]:
        """Return the importance level for each capability."""
        return self._resolver.levels_for(capabilities)

    def run(
        self,
        readiness: Any,
        capabilities: list[str],
        *,
        mission_id: str = "",
        auto_provision: bool = True,
        provisioner: Any | None = None,
    ) -> PreflightResult:
        """Compute the preflight verdict for ``capabilities``.

        ``readiness`` is a :class:`ToolReadinessService` used to probe tools
        and (optionally) provision missing providers.

        Returns:
            :class:`PreflightResult` — the mission may execute when
            ``result.may_execute`` is ``True``.

        """
        unique_capabilities = list(dict.fromkeys(capabilities))
        levels = self._resolver.levels_for(unique_capabilities)
        candidates = self._resolver.candidate_tools(unique_capabilities)

        verdicts = readiness.check(tool_ids=candidates, sync_engine=True)
        by_tool = {verdict.tool_id: verdict for verdict in verdicts.tools}
        available = {
            tool_id
            for tool_id, verdict in by_tool.items()
            if verdict.status is ToolReadinessStatus.AVAILABLE
        }

        provisioned: list[str] = []
        provision_failures: list[str] = []
        provision_attempted = False
        required_missing = [
            capability
            for capability in unique_capabilities
            if levels[capability] is CapabilityLevel.REQUIRED
            and not any(tool_id in available for tool_id in self._resolver.providers_for(capability))
        ]

        if required_missing and auto_provision and provisioner is not None:
            provision_attempted = True
            for capability in required_missing:
                for tool_id in self._resolver.providers_for(capability):
                    if tool_id in available:
                        continue
                    definition = readiness.definition(tool_id)
                    if definition is None:
                        continue
                    outcome = provisioner.install(definition, verify=True)
                    if outcome.success and outcome.skipped:
                        available.add(tool_id)
                        continue
                    if outcome.success:
                        provisioned.append(tool_id)
                        available.add(tool_id)
                    else:
                        provision_failures.append(tool_id)
                    if tool_id in available:
                        break

        required_missing = [
            capability
            for capability in unique_capabilities
            if levels[capability] is CapabilityLevel.REQUIRED
            and not any(tool_id in available for tool_id in self._resolver.providers_for(capability))
        ]
        optional_missing = [
            capability
            for capability in unique_capabilities
            if levels[capability] is not CapabilityLevel.REQUIRED
            and not any(tool_id in available for tool_id in self._resolver.providers_for(capability))
        ]

        missing_tools: list[str] = []
        for capability in required_missing:
            for tool_id in self._resolver.providers_for(capability):
                if tool_id not in available and tool_id not in missing_tools:
                    missing_tools.append(tool_id)

        if required_missing:
            return PreflightResult(
                status=PreflightStatus.BLOCKED,
                mission_id=mission_id,
                required_missing=tuple(required_missing),
                missing_tools=tuple(missing_tools),
                optional_missing=tuple(optional_missing),
                provision_attempted=provision_attempted,
                provisioned=tuple(provisioned),
                provision_failures=tuple(provision_failures),
                blocked_reason=_blocked_reason(required_missing, missing_tools),
            )
        return PreflightResult(
            status=PreflightStatus.DEGRADED if optional_missing else PreflightStatus.PASS,
            mission_id=mission_id,
            required_missing=(),
            missing_tools=tuple(missing_tools),
            optional_missing=tuple(optional_missing),
            provision_attempted=provision_attempted,
            provisioned=tuple(provisioned),
            provision_failures=tuple(provision_failures),
        )


def _blocked_reason(required_missing: list[str], missing_tools: list[str]) -> str:
    """Return a precise, machine-and-human-readable blocked reason."""
    caps = ", ".join(required_missing) or "none"
    tools = ", ".join(missing_tools) or "none"
    return (
        f"mission blocked: required capabilities without an available provider "
        f"({caps}); missing tools: {tools}"
    )


__all__ = ["MissionCapabilityResolver", "MissionPreflight"]
