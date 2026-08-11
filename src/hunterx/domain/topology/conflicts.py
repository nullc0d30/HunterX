# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Topology conflict detection & resolution.

Preserves contradictions found while correlating relationships instead of
silently discarding them. The detector works on raw observations grouped by
endpoint pair; when observations disagree on the relationship type the pair is
flagged and the highest-confidence type is selected with an explainable reason.
"""

from __future__ import annotations

from collections.abc import Sequence

from hunterx.domain.topology.confidence import TopologyConfidenceEngine
from hunterx.domain.topology.enums import ConflictType, RelationshipType
from hunterx.domain.topology.keys import relationship_key
from hunterx.domain.topology.models import RelationshipObservation, TopologyConflict


class TopologyConflictResolver:
    """Detect and resolve relationship conflicts."""

    def __init__(self, confidence: TopologyConfidenceEngine | None = None) -> None:
        self._confidence = confidence or TopologyConfidenceEngine()

    def detect(
        self,
        observations: Sequence[RelationshipObservation],
        *,
        mission_id: str = "",
        correlation_id: str = "",
    ) -> list[TopologyConflict]:
        """Return conflicts found in ``observations``.

        Conflicts are grouped by the unordered endpoint pair; a pair is
        conflicted when it carries more than one distinct relationship type.
        """
        conflicts: list[TopologyConflict] = []
        pairs: dict[tuple[str, str], list[RelationshipObservation]] = {}
        for observation in observations:
            a, b = sorted((observation.source.key, observation.target.key))
            pairs.setdefault((a, b), []).append(observation)

        for (source_key, target_key) in sorted(pairs):
            group = pairs[(source_key, target_key)]
            by_type: dict[str, list[RelationshipObservation]] = {}
            for observation in group:
                by_type.setdefault(observation.rel_type.value, []).append(observation)
            if len(by_type) <= 1:
                continue

            selected_type, selected_group = self._select(by_type)
            conflict = TopologyConflict(
                key=relationship_key(selected_type, source_key, target_key),
                conflict_type=ConflictType.RELATIONSHIP_TYPE,
                observations=[
                    {
                        "rel_type": rel_type,
                        "source": source_key,
                        "target": target_key,
                        "count": len(obs_group),
                        "confidence": self._confidence.combine(
                            [float(o.confidence) for o in obs_group],
                            source_names=[str(o.source_name) for o in obs_group],
                        ),
                    }
                    for rel_type, obs_group in sorted(by_type.items())
                ],
                selected_value=selected_type,
                selected_source=selected_group[0].source_name,
                reason=(
                    f"endpoint pair {source_key} → {target_key} reported under multiple "
                    f"relationship types ({', '.join(sorted(by_type))}); selected "
                    f"{selected_type} by combined confidence"
                ),
                confidence=self._confidence.combine(
                    [float(o.confidence) for o in selected_group],
                    source_names=[str(o.source_name) for o in selected_group],
                ),
                mission_id=mission_id,
                correlation_id=correlation_id,
            )
            conflicts.append(conflict)
        return conflicts

    @staticmethod
    def _select(by_type: dict[str, list[RelationshipObservation]]) -> tuple[str, list[RelationshipObservation]]:
        """Return the ``(rel_type, observations)`` with the highest confidence sum."""
        return max(
            by_type.items(),
            key=lambda item: sum(float(o.confidence) for o in item[1]),
        )


def dedupe_conflicts(conflicts: Sequence[TopologyConflict]) -> list[TopologyConflict]:
    """Return conflicts with duplicate keys removed (last occurrence wins)."""
    unique: dict[str, TopologyConflict] = {}
    for conflict in conflicts:
        unique[conflict.key] = conflict
    return list(unique.values())


def _ensure_enum(rel_type: str) -> RelationshipType:
    try:
        return RelationshipType(rel_type)
    except ValueError:
        return RelationshipType.RELATED_TO
