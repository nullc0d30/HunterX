# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Source reliability model.

Classifies evidence sources (direct observation, validated replay, controlled
callback, tool signature, historical archive, external intelligence, AI
inference, analyst annotation) and maps each to an ordered reliability rank.
Direct validated evidence always outranks AI inference.
"""

from __future__ import annotations

from hunterx.domain.reporting.enums import ReliabilityRank, SourceReliabilityKind
from hunterx.domain.reporting.models import SourceReliabilityModel

#: Rank and weight per source-reliability kind.
_KIND_META: dict[SourceReliabilityKind, tuple[ReliabilityRank, float]] = {
    SourceReliabilityKind.DIRECT_OBSERVATION: (ReliabilityRank.DIRECT, 1.0),
    SourceReliabilityKind.VALIDATED_REPLAY: (ReliabilityRank.DIRECT, 1.0),
    SourceReliabilityKind.CONTROLLED_CALLBACK: (ReliabilityRank.HIGH, 0.95),
    SourceReliabilityKind.TOOL_SIGNATURE: (ReliabilityRank.MEDIUM, 0.7),
    SourceReliabilityKind.HISTORICAL_ARCHIVE: (ReliabilityRank.LOW, 0.4),
    SourceReliabilityKind.EXTERNAL_INTELLIGENCE: (ReliabilityRank.LOW, 0.3),
    SourceReliabilityKind.ANALYST_ANNOTATION: (ReliabilityRank.LOW, 0.35),
    SourceReliabilityKind.AI_INFERENCE: (ReliabilityRank.INFERRED, 0.1),
}

#: Ordered ranks used to compare sources.
_RANK_ORDER: tuple[ReliabilityRank, ...] = (
    ReliabilityRank.DIRECT,
    ReliabilityRank.HIGH,
    ReliabilityRank.MEDIUM,
    ReliabilityRank.LOW,
    ReliabilityRank.INFERRED,
    ReliabilityRank.UNKNOWN,
)


class SourceReliabilityModelBuilder:
    """Builds source-reliability classifications.

    ``reliability_for`` returns the canonical reliability for a source kind;
    ``stronger_than`` compares two reliability models so direct evidence can be
    prioritized over AI inference.
    """

    def reliability_for(
        self,
        source: str,
        kind: SourceReliabilityKind,
        *,
        notes: str = "",
    ) -> SourceReliabilityModel:
        """Return the reliability model for a source of ``kind``."""
        rank, weight = _KIND_META.get(kind, (ReliabilityRank.UNKNOWN, 0.0))
        return SourceReliabilityModel(
            source=source,
            kind=kind,
            rank=rank,
            notes=notes or f"classified as {kind.value}",
            effective_weight=weight,
        )

    def stronger_than(self, a: SourceReliabilityModel, b: SourceReliabilityModel) -> bool:
        """Return ``True`` when source ``a`` is stronger than source ``b``."""
        return _rank_index(a.rank) < _rank_index(b.rank)


def _rank_index(rank: ReliabilityRank) -> int:
    """Return the ordering index of a reliability rank."""
    try:
        return _RANK_ORDER.index(rank)
    except ValueError:
        return len(_RANK_ORDER) - 1


__all__ = ["SourceReliabilityModelBuilder"]
