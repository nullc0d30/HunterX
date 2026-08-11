# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Mission-aware tool selection.

Tool selection must change according to mission type. Each mission type has a
different scope, safety ceiling, time budget, depth and proof requirement.
This selector enriches TIP criteria with a mission profile and produces
explainable selections: why a tool was chosen, what evidence it can produce,
what risk/cost it carries and why alternatives were rejected.
"""

from __future__ import annotations

from hunterx.domain.exceptions.operation import ToolSelectionError
from hunterx.domain.tool_intelligence import ToolSelection, ToolSelectionCriteria
from hunterx.domain.tool_mastery import ToolSelectionDecision
from hunterx.tools.intelligence.api import ToolIntelligenceAPI
from hunterx.tools.intelligence.selector import ToolSelector

#: Canonical mission types per the Sprint 025 contract.
MISSION_TYPES = (
    "bug-bounty",
    "pentest",
    "red-team",
    "web-assessment",
    "api-assessment",
    "network-assessment",
    "internal-assessment",
    "cloud-assessment",
    "vulnerability-research",
    "authorized-security-research",
)

#: Default authorization ceiling (TIP safety class) per mission type.
_MISSION_AUTHORIZATION = {
    "bug-bounty": "low-impact-active",
    "pentest": "active",
    "red-team": "high-impact",
    "web-assessment": "active",
    "api-assessment": "active",
    "network-assessment": "active",
    "internal-assessment": "high-impact",
    "cloud-assessment": "active",
    "vulnerability-research": "low-impact-active",
    "authorized-security-research": "active",
}


class MissionAwareToolSelector:
    """Select the best tool for a capability under a mission profile.

    Wraps the TIP :class:`ToolSelector` and enriches it with mission-aware
    authorization ceilings and explainable rationale. Never selects a tool
    above the mission authorization ceiling.
    """

    def __init__(
        self,
        tip: ToolIntelligenceAPI,
        selector: ToolSelector | None = None,
        mission_authorization: dict[str, str] | None = None,
    ) -> None:
        self._tip = tip
        self._selector = selector or tip.selector
        self._mission_authorization = mission_authorization or _MISSION_AUTHORIZATION

    def select(
        self,
        capability: str,
        *,
        mission_type: str = "bug-bounty",
        target_type: str = "",
        available_inputs: tuple[str, ...] = (),
        require_installed: bool = False,
        preferences: tuple[str, ...] = (),
        limit: int = 5,
        authorization_granted: bool = False,
    ) -> list[ToolSelectionDecision]:
        """Return explainable selections for ``capability`` under ``mission_type``.

        Raises:
            ToolSelectionError: if no tool passes the mission's safety ceiling.

        """
        criteria = ToolSelectionCriteria(
            mission_profile=mission_type,
            target_type=target_type,
            available_inputs=available_inputs,
            required_capabilities=(capability,),
            require_installed=require_installed,
            preferences=preferences,
            limit=limit,
        )
        authorization = _safety_class(self._mission_authorization.get(mission_type, "active"))
        selections = self._selector.select(
            criteria,
            authorization=authorization,
            mission_scope=mission_type,
            authorization_granted=authorization_granted,
        )
        return [self._explain(item, capability) for item in selections]

    def select_best(
        self,
        capability: str,
        *,
        mission_type: str = "bug-bounty",
        target_type: str = "",
        require_installed: bool = False,
        authorization_granted: bool = False,
    ) -> ToolSelectionDecision:
        """Return the single best explainable selection.

        Raises:
            ToolSelectionError: if no tool passes the mission's safety ceiling.

        """
        decisions = self.select(
            capability,
            mission_type=mission_type,
            target_type=target_type,
            require_installed=require_installed,
            authorization_granted=authorization_granted,
            limit=1,
        )
        if not decisions:
            raise ToolSelectionError(
                f"no tool provides '{capability}' under mission '{mission_type}'"
            )
        return decisions[0]

    def _explain(self, selection: ToolSelection, capability: str) -> ToolSelectionDecision:
        alternatives = tuple(selection.alternatives)
        rejected = ()
        if alternatives:
            rejected = tuple(
                f"{alternative} scored lower or lacks required capability"
                for alternative in alternatives
            )
        evidence = tuple(selection.expected_evidence)
        return ToolSelectionDecision(
            tool_id=selection.tool_id,
            reason="; ".join(selection.reasoning) or f"best match for {capability}",
            required_capability=capability,
            expected_information_gain=evidence,
            expected_evidence=evidence,
            expected_proof_capability=selection.expected_proof_capability,
            risk=selection.risk_level,
            cost=selection.estimated_cost,
            alternatives=alternatives,
            why_alternatives_rejected=rejected,
            score=selection.score,
        )


def _safety_class(label: str):
    """Convert a safety-class label to a TIP :class:`ToolSafetyClass`."""
    from hunterx.domain.tool_intelligence import ToolSafetyClass

    for member in ToolSafetyClass:
        if member.value == label:
            return member
    return ToolSafetyClass.ACTIVE
