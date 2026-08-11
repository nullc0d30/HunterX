# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Intelligence Correlation Engine.

Sprint 026. Correlates observations across tools, time, assets, missions and
technologies. Correlation is provenance-preserving: it never merges away a
disagreement. The engine produces correlation chains (same fact, multiple
tools) and hands off genuine contradictions to the conflict detector.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from hunterx.domain.target_intelligence.enums import CoverageCapability, ObservationType
from hunterx.domain.target_intelligence.models import Observation
from hunterx.shared.ids import generate_id


@dataclass(frozen=True, slots=True)
class CorrelatedObservation:
    """A canonical fact corroborated by one or more observations.

    Attributes:
        chain_id: stable correlation chain identifier.
        target_id: owning target.
        mission_id: owning mission.
        asset_key: related asset key.
        observation_type: :class:`ObservationType`.
        value: the canonical correlated value.
        tools: tools that reported the fact.
        observations: contributing observation ids.
        first_seen / last_seen: state-time stamps.
        confidence: merged confidence in ``[0, 1]``.

    """

    chain_id: str
    target_id: str = ""
    mission_id: str = ""
    asset_key: str = ""
    observation_type: ObservationType = ObservationType.OTHER
    value: str = ""
    tools: tuple[str, ...] = ()
    observations: tuple[str, ...] = ()
    first_seen: str = ""
    last_seen: str = ""
    confidence: float = 1.0

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe mapping."""
        return {
            "chain_id": self.chain_id,
            "target_id": self.target_id,
            "mission_id": self.mission_id,
            "asset_key": self.asset_key,
            "observation_type": self.observation_type.value,
            "value": self.value,
            "tools": list(self.tools),
            "observations": list(self.observations),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "confidence": self.confidence,
        }


@dataclass(frozen=True, slots=True)
class CorrelationResult:
    """Result of correlating a batch of observations.

    Attributes:
        chains: corroborated canonical facts.
        conflicts: conflicting observations that must be validated.
        orphan_count: observations with no asset linkage (kept, not dropped).

    """

    chains: tuple[CorrelatedObservation, ...] = ()
    conflicts: tuple[Observation, ...] = ()
    orphan_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe mapping."""
        return {
            "chains": [chain.to_dict() for chain in self.chains],
            "conflicts": [obs.to_dict() for obs in self.conflicts],
            "orphan_count": self.orphan_count,
        }


class IntelligenceCorrelationEngine:
    """Correlate observations by (asset, type, normalized value)."""

    def correlate(self, observations: Sequence[Observation]) -> CorrelationResult:
        """Group observations into corroboration chains and detect conflicts.

        Conflicts are detected when two different tools report *different*
        values for the same (asset, observation type) with comparable
        confidence — those are never merged.
        """
        buckets: dict[tuple[str, str, str], list[Observation]] = {}
        for observation in observations:
            key = (
                observation.asset_key,
                observation.observation_type.value,
                observation.normalized_value or observation.value,
            )
            buckets.setdefault(key, []).append(observation)

        chains: list[CorrelatedObservation] = []
        conflicts: list[Observation] = []
        for key, members in buckets.items():
            asset_key, obs_type, value = key
            tools = sorted({obs.tool for obs in members if obs.tool})
            chain_id = generate_id()
            chains.append(
                CorrelatedObservation(
                    chain_id=chain_id,
                    target_id=members[0].target_id,
                    mission_id=members[0].mission_id,
                    asset_key=asset_key,
                    observation_type=members[0].observation_type,
                    value=value,
                    tools=tuple(tools),
                    observations=tuple(member.observation_id for member in members),
                    first_seen=min(member.first_seen for member in members),
                    last_seen=max(member.last_seen for member in members),
                    confidence=round(max(member.confidence for member in members), 4),
                )
            )

        # Detect conflicting values per (asset, type) across tools.
        value_by_asset_type: dict[tuple[str, str], dict[str, list[Observation]]] = {}
        for observation in observations:
            marker = (observation.asset_key, observation.observation_type.value)
            value_by_asset_type.setdefault(marker, {}).setdefault(
                observation.normalized_value or observation.value, []
            ).append(observation)
        for values_by_value in value_by_asset_type.values():
            if len(values_by_value) > 1:
                for bucket in values_by_value.values():
                    for observation in bucket:
                        conflicts.append(observation)

        orphan_count = sum(1 for obs in observations if not obs.asset_key)
        return CorrelationResult(
            chains=tuple(sorted(chains, key=lambda c: c.value)),
            conflicts=tuple(conflicts),
            orphan_count=orphan_count,
        )

    def by_capability(self, observations: Sequence[Observation], capability: CoverageCapability) -> list[Observation]:
        """Return observations relevant to a coverage capability."""
        return [obs for obs in observations if obs.capability == capability.value or obs.capability == ""]


__all__ = [
    "CorrelatedObservation",
    "CorrelationResult",
    "IntelligenceCorrelationEngine",
    "ObservationType",
]
