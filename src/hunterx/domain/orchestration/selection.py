# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tool selection domain models.

The orchestration tool-selection vocabulary: capability needs, selection
results and selections. These bridge the Tool Intelligence Platform's raw
candidate ranking with the mission planner's step binding.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from hunterx.shared.ids import generate_id
from hunterx.shared.time import utcnow_iso


@dataclass(frozen=True, slots=True)
class CapabilityNeed:
    """A capability a step requires, with its context.

    Attributes:
        capability: canonical capability id (e.g. ``subdomain-discovery``).
        target_type: canonical target kind the capability acts upon.
        safety_class: safety class the tool must honour.
        mission_type: mission type the tool must support (empty = any).
        required: whether the capability is mandatory for the step.
        alternatives: acceptable alternative capabilities (fallback).

    """

    capability: str
    target_type: str = ""
    safety_class: str = "passive"
    mission_type: str = ""
    required: bool = True
    alternatives: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe representation."""
        return {
            "capability": self.capability,
            "target_type": self.target_type,
            "safety_class": self.safety_class,
            "mission_type": self.mission_type,
            "required": self.required,
            "alternatives": list(self.alternatives),
        }


@dataclass(frozen=True, slots=True)
class ToolSelectionResult:
    """A ranked candidate tool satisfying a capability need.

    Attributes:
        tool_id: candidate tool.
        score: selection score in ``[0, 1]``.
        reasons: reasons contributing to the score.
        capability: capability the tool satisfies.
        is_fallback: whether this tool is a fallback for the primary.
        fallback_of: the primary tool id this tool substitutes for.

    """

    tool_id: str
    score: float = 0.0
    reasons: tuple[str, ...] = ()
    capability: str = ""
    is_fallback: bool = False
    fallback_of: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe representation."""
        return {
            "tool_id": self.tool_id,
            "score": self.score,
            "reasons": list(self.reasons),
            "capability": self.capability,
            "is_fallback": self.is_fallback,
            "fallback_of": self.fallback_of,
        }


@dataclass(slots=True)
class ToolSelection:
    """A persisted tool-selection record for a step.

    Attributes:
        selection_id: stable record identifier.
        mission_id: owning mission.
        plan_id: owning plan.
        step_id: owning step.
        capability: capability the selection satisfies.
        tool_id: selected tool.
        alternative_tools: ordered alternatives (fallback chain).
        score: selection score.
        reasons: selection rationale.
        fallback_of: primary tool this selection substitutes for.
        created_at: UTC ISO-8601 timestamp.

    """

    selection_id: str = field(default_factory=generate_id)
    mission_id: str = ""
    plan_id: str = ""
    step_id: str = ""
    capability: str = ""
    tool_id: str = ""
    alternative_tools: tuple[str, ...] = ()
    score: float = 0.0
    reasons: tuple[str, ...] = ()
    fallback_of: str = ""
    created_at: str = field(default_factory=utcnow_iso)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe representation."""
        return {
            "selection_id": self.selection_id,
            "mission_id": self.mission_id,
            "plan_id": self.plan_id,
            "step_id": self.step_id,
            "capability": self.capability,
            "tool_id": self.tool_id,
            "alternative_tools": list(self.alternative_tools),
            "score": self.score,
            "reasons": list(self.reasons),
            "fallback_of": self.fallback_of,
            "created_at": self.created_at,
        }
