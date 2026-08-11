# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tool fallback selection.

Selects a capability-equivalent fallback tool when the primary tool is
unavailable or failed. Fallbacks preserve the input contract (capability +
target type), the output contract (same capability semantics) and the mission
tool policy.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from hunterx.domain.orchestration.enums import MissionType
from hunterx.domain.orchestration.models import ToolPolicy
from hunterx.domain.orchestration.selection import CapabilityNeed
from hunterx.engines.orchestration.selector import MissionToolSelector


@dataclass(frozen=True, slots=True)
class FallbackDecision:
    """A tool fallback decision.

    Attributes:
        step_id: the step that needed a fallback.
        primary_tool: the tool that failed or was unavailable.
        fallback_tool: the tool substituted in (empty when unavailable).
        reason: fallback rationale.
        alternatives: ordered alternative candidates considered.

    """

    step_id: str = ""
    primary_tool: str = ""
    fallback_tool: str = ""
    reason: str = ""
    alternatives: tuple[str, ...] = field(default_factory=tuple)


class FallbackEngine:
    """Selects capability-equivalent fallback tools for a step.

    Usage::

        decision = fallback.select_fallback(
            step_id="s1",
            primary="subfinder",
            need=CapabilityNeed(capability="subdomain-discovery", target_type="domain"),
            mission_type=MissionType.EXTERNAL_ASSESSMENT,
            policy=mission.policies.tool,
        )
    """

    def __init__(self, selector: MissionToolSelector | None = None) -> None:
        self._selector = selector or MissionToolSelector()

    def select_fallback(
        self,
        *,
        step_id: str,
        primary: str,
        need: CapabilityNeed,
        mission_type: MissionType = MissionType.VULNERABILITY_ASSESSMENT,
        policy: ToolPolicy | None = None,
        limit: int = 5,
    ) -> FallbackDecision:
        """Return a fallback decision for a failed/unavailable primary tool.

        If the tool policy disables fallbacks or no alternative provider is
        available, ``fallback_tool`` is empty and the decision records the
        reason.
        """
        policy = policy or ToolPolicy()
        if not policy.fallback_enabled:
            return FallbackDecision(
                step_id=step_id,
                primary_tool=primary,
                reason="tool fallback is disabled by the mission tool policy",
            )
        try:
            alternatives = self._selector.alternatives(
                need,
                primary=primary,
                mission_type=mission_type,
                policy=policy,
                limit=limit,
            )
        except Exception:  # noqa: BLE001 - no candidates means no fallback
            alternatives = []
        if not alternatives:
            return FallbackDecision(
                step_id=step_id,
                primary_tool=primary,
                reason=f"no capability-equivalent fallback for '{primary}'",
            )
        best = alternatives[0]
        return FallbackDecision(
            step_id=step_id,
            primary_tool=primary,
            fallback_tool=best.tool_id,
            reason=f"fallback to '{best.tool_id}' for capability '{need.capability}'",
            alternatives=tuple(result.tool_id for result in alternatives),
        )
