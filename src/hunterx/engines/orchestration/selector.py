# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Mission tool selection.

Capability-driven tool selection for mission steps. The selector queries the
Tool Intelligence Platform (TIP) for candidates that provide a capability,
filters by the mission tool policy and the registered execution adapters, and
ranks by the TIP selection score. Fallback selection returns the next best
compatible provider when the primary tool is unavailable.
"""

from __future__ import annotations

from hunterx.domain.exceptions import ToolSelectionUnavailableError
from hunterx.domain.orchestration.enums import MissionType
from hunterx.domain.orchestration.models import ToolPolicy
from hunterx.domain.orchestration.selection import CapabilityNeed, ToolSelectionResult
from hunterx.domain.ports.tool_intelligence import ToolIntelligencePort
from hunterx.domain.tool_intelligence import ToolSelectionCriteria
from hunterx.tools.sdk.engine import ExecutionEngine

#: Mission profile names TIP understands, keyed by orchestration mission type.
_MISSION_PROFILE = {
    MissionType.BUG_BOUNTY: "bug-bounty",
    MissionType.WEB_PENTEST: "web-application-pentest",
    MissionType.API_PENTEST: "api-pentest",
    MissionType.EXTERNAL_ASSESSMENT: "external-pentest",
    MissionType.INTERNAL_ASSESSMENT: "internal-pentest",
    MissionType.RED_TEAM_RECON: "red-team",
    MissionType.CLOUD_ASSESSMENT: "cloud-assessment",
    MissionType.CONTINUOUS_ATTACK_SURFACE_MONITORING: "continuous-monitoring",
    MissionType.VULNERABILITY_ASSESSMENT: "vulnerability-assessment",
}


class MissionToolSelector:
    """Selects tools for mission steps from the TIP + execution registry.

    Usage::

        selector = MissionToolSelector(tip=tip, engine=execution_engine)
        result = selector.select(
            need=CapabilityNeed(capability="subdomain-discovery", target_type="domain"),
            mission_type=MissionType.EXTERNAL_ASSESSMENT,
            policy=mission.policies.tool,
        )
    """

    def __init__(
        self,
        tip: ToolIntelligencePort | None = None,
        engine: ExecutionEngine | None = None,
        *,
        require_installed: bool = True,
    ) -> None:
        self._tip = tip
        self._engine = engine
        self._require_installed = require_installed

    def select(
        self,
        need: CapabilityNeed,
        *,
        mission_type: MissionType = MissionType.VULNERABILITY_ASSESSMENT,
        policy: ToolPolicy | None = None,
        limit: int = 5,
    ) -> list[ToolSelectionResult]:
        """Return ranked candidate tools satisfying ``need``, best first.

        Raises:
            ToolSelectionUnavailableError: when no tool satisfies the need.

        """
        policy = policy or ToolPolicy()
        candidates = self._candidates(need, mission_type, policy, limit)
        if not candidates:
            raise ToolSelectionUnavailableError(
                f"no tool provides capability '{need.capability}' within the mission tool policy",
                capability=need.capability,
            )
        return candidates

    def select_primary(
        self,
        need: CapabilityNeed,
        *,
        mission_type: MissionType = MissionType.VULNERABILITY_ASSESSMENT,
        policy: ToolPolicy | None = None,
        limit: int = 5,
    ) -> ToolSelectionResult:
        """Return the single best tool for ``need``."""
        ranked = self.select(need, mission_type=mission_type, policy=policy, limit=limit)
        return ranked[0]

    def alternatives(
        self,
        need: CapabilityNeed,
        *,
        primary: str,
        mission_type: MissionType = MissionType.VULNERABILITY_ASSESSMENT,
        policy: ToolPolicy | None = None,
        limit: int = 5,
    ) -> list[ToolSelectionResult]:
        """Return fallback candidates excluding ``primary``, best first."""
        policy = policy or ToolPolicy()
        ranked = self._candidates(need, mission_type, policy, limit)
        return [candidate for candidate in ranked if candidate.tool_id != primary]

    # -- internals ----------------------------------------------------------

    def _candidates(
        self,
        need: CapabilityNeed,
        mission_type: MissionType,
        policy: ToolPolicy,
        limit: int,
    ) -> list[ToolSelectionResult]:
        profile = _MISSION_PROFILE.get(mission_type, mission_type.value)
        criteria = ToolSelectionCriteria(
            mission_profile=profile,
            target_type=need.target_type,
            required_capabilities=(need.capability,),
            require_installed=self._require_installed,
            preferences=policy.preferred_tools,
            limit=limit,
        )
        tool_ids = self._registry_candidates(need, criteria)
        results: list[ToolSelectionResult] = []
        for tool_id in tool_ids:
            if not policy.permits(tool_id):
                continue
            if self._engine is not None and self._engine.adapter_for(tool_id) is None:
                continue
            score = self._score(tool_id, need, criteria)
            results.append(
                ToolSelectionResult(
                    tool_id=tool_id,
                    score=score,
                    reasons=tuple(self._reasons(tool_id)),
                    capability=need.capability,
                )
            )
        results.sort(key=lambda item: item.score, reverse=True)
        return results[:limit]

    def _registry_candidates(self, need: CapabilityNeed, criteria: ToolSelectionCriteria) -> list[str]:
        """Return tool ids providing the need's capability, ordered by TIP."""
        if self._tip is not None:
            try:
                selected = self._tip.select(criteria)
                if selected:
                    return [result.tool_id for result in selected]
            except Exception:  # noqa: BLE001 - degrade to registry lookup; nosec B110
                pass
            return self._tip.tools_by_capability(need.capability)
        return [tool_id for tool_id in self._providers_from_registry(need.capability)]

    def _providers_from_registry(self, capability: str) -> list[str]:
        """Return providers from the execution capability registry when present."""
        registry = getattr(self._engine, "_capability_registry", None)
        if registry is not None:
            providers = registry.providers_for(capability)
            return list(providers)
        return []

    def _score(self, tool_id: str, need: CapabilityNeed, criteria: ToolSelectionCriteria) -> float:
        """Return a selection score for ``tool_id`` in ``[0, 1]``."""
        score = 0.5
        if self._tip is not None:
            try:
                selected = self._tip.select(criteria)
                for result in selected:
                    if result.tool_id == tool_id:
                        score = result.score
                        break
            except Exception:  # noqa: BLE001 - fall back to a neutral score; nosec B110
                pass
        if tool_id in criteria.preferences:
            score = min(1.0, score + 0.2)
        return max(0.0, min(1.0, score))

    def _reasons(self, tool_id: str) -> list[str]:
        """Return candidate selection reasons."""
        reasons = ["provides the required capability"]
        if self._engine is not None and self._engine.adapter_for(tool_id) is not None:
            reasons.append("registered execution adapter available")
        return reasons
