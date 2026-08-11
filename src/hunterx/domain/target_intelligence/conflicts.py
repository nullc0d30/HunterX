# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Intelligence Conflict Resolution.

Sprint 026. When Tool A says "vulnerable" and Tool B says "not vulnerable",
HunterX never auto-chooses one. The conflict is preserved and triggers
additional validation or higher-quality evidence collection. This module
detects conflicts from observations and manages their lifecycle (open →
escalated → resolved).
"""

from __future__ import annotations

from collections.abc import Sequence

from hunterx.domain.target_intelligence.enums import (
    ConflictState,
    CoverageCapability,
    ObservationType,
)
from hunterx.domain.target_intelligence.models import (
    IntelligenceConflict,
    Observation,
)
from hunterx.shared.ids import generate_id
from hunterx.shared.time import utcnow_iso


class IntelligenceConflictDetector:
    """Detect and preserve contradictions between tool results.

    A conflict requires at least two *different* tools disagreeing on the same
    (asset, capability). Same-tool disagreements are treated as noise.
    """

    def detect(
        self,
        observations: Sequence[Observation],
        *,
        target_id: str,
        mission_id: str = "",
    ) -> list[IntelligenceConflict]:
        """Return open conflicts from a batch of observations.

        For capability-carrying observations on the same asset, distinct values
        from distinct tools become a conflict. The conflict is preserved with
        the raw observations so validation can collect better evidence.
        """
        buckets: dict[tuple[str, str], list[Observation]] = {}
        for observation in observations:
            if not observation.asset_key:
                continue
            capability = observation.capability or _capability_for_type(observation.observation_type)
            if not capability:
                continue
            buckets.setdefault((observation.asset_key, capability), []).append(observation)

        conflicts: list[IntelligenceConflict] = []
        for (asset_key, capability), members in buckets.items():
            by_value: dict[str, set[str]] = {}
            for member in members:
                value = member.normalized_value or member.value
                if member.tool:
                    by_value.setdefault(value, set()).add(member.tool)
            distinct_values = [value for value, tools in by_value.items() if tools]
            if len(distinct_values) < 2:
                continue
            member_tools = sorted({member.tool for member in members if member.tool})
            conflicts.append(
                IntelligenceConflict(
                    conflict_id=generate_id(),
                    target_id=target_id,
                    mission_id=mission_id,
                    asset_key=asset_key,
                    capability=CoverageCapability(capability),
                    observations=tuple(member.to_dict() for member in members),
                    tools=tuple(member_tools),
                    state=ConflictState.OPEN,
                    detected_at=utcnow_iso(),
                )
            )
        return conflicts


class IntelligenceConflictManager:
    """Manage the lifecycle of preserved conflicts."""

    def __init__(self) -> None:
        self._conflicts: dict[str, IntelligenceConflict] = {}

    def record(self, conflict: IntelligenceConflict) -> IntelligenceConflict:
        """Register a conflict (deduplicated by key)."""
        self._conflicts[conflict.conflict_id] = conflict
        return conflict

    def escalate(self, conflict_id: str, *, reason: str) -> IntelligenceConflict:
        """Mark a conflict as escalated for higher-quality evidence collection."""
        conflict = self._conflicts.get(conflict_id)
        if conflict is None:
            raise KeyError(conflict_id)
        import dataclasses

        updated = dataclasses.replace(
            conflict,
            state=ConflictState.ESCALATED,
            resolution=reason,
            resolved_at=utcnow_iso(),
        )
        self._conflicts[conflict_id] = updated
        return updated

    def resolve(self, conflict_id: str, *, resolution: str) -> IntelligenceConflict:
        """Mark a conflict as resolved with an evidence-backed resolution."""
        conflict = self._conflicts.get(conflict_id)
        if conflict is None:
            raise KeyError(conflict_id)
        import dataclasses

        updated = dataclasses.replace(
            conflict,
            state=ConflictState.RESOLVED,
            resolution=resolution,
            resolved_at=utcnow_iso(),
        )
        self._conflicts[conflict_id] = updated
        return updated

    def open(self, target_id: str = "") -> list[IntelligenceConflict]:
        """Return open (or escalated) conflicts, optionally per target."""
        conflicts = [c for c in self._conflicts.values() if c.state in (ConflictState.OPEN, ConflictState.ESCALATED)]
        if target_id:
            conflicts = [c for c in conflicts if c.target_id == target_id]
        return conflicts

    def all(self, target_id: str = "") -> list[IntelligenceConflict]:
        """Return all recorded conflicts."""
        conflicts = list(self._conflicts.values())
        if target_id:
            conflicts = [c for c in conflicts if c.target_id == target_id]
        return conflicts


def _capability_for_type(observation_type: ObservationType) -> str:
    """Best-effort capability mapping for observations without a capability tag."""
    return {
        ObservationType.PORT: CoverageCapability.PORT_DISCOVERY.value,
        ObservationType.SERVICE: CoverageCapability.SERVICE_DETECTION.value,
        ObservationType.TECHNOLOGY: CoverageCapability.TECHNOLOGY_FINGERPRINT.value,
        ObservationType.VULNERABILITY: CoverageCapability.VULNERABILITY_SCANNING.value,
        ObservationType.PARAMETER: CoverageCapability.PARAMETER_DISCOVERY.value,
    }.get(observation_type, "")


__all__ = [
    "ConflictState",
    "IntelligenceConflict",
    "IntelligenceConflictDetector",
    "IntelligenceConflictManager",
]
