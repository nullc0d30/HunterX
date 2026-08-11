# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Target Intelligence State assembly & scoring.

Sprint 026. Assembles the :class:`TargetIntelligenceState` snapshot from the
stores and computes the explainable multi-dimension intelligence score. The
score never collapses into a single opaque number: each dimension is reported
with its weight and the aggregate is a weighted combination recorded for
explainability.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from hunterx.domain.target_intelligence.coverage import CoverageEngine
from hunterx.domain.target_intelligence.enums import (
    CoverageCapability,
    CoverageState,
    IntelligenceDimension,
    IntelligencePhase,
    IntelligenceTargetStatus,
)
from hunterx.domain.target_intelligence.models import (
    IntelligenceAsset,
    IntelligenceScore,
    IntelligenceTarget,
    TargetHistoryEntry,
    TargetIntelligenceState,
)
from hunterx.shared.time import utcnow_iso

#: Phase progression rules: the state advances when the previous phase's
#: preconditions hold. Used by the mission-state transition helper.
_PHASE_PRECONDITIONS: dict[IntelligencePhase, str] = {
    IntelligencePhase.DISCOVERY: "initial",
    IntelligencePhase.ENUMERATION: "assets exist",
    IntelligencePhase.MAPPING: "services/technologies fingerprinted",
    IntelligencePhase.ANALYSIS: "coverage matrix populated",
    IntelligencePhase.HYPOTHESIS: "analysis complete",
    IntelligencePhase.VALIDATION: "hypotheses exist",
    IntelligencePhase.PROOF: "validation evidence exists",
    IntelligencePhase.REPORTING: "proofs validated",
}


class TargetIntelligenceStateAssembler:
    """Build :class:`TargetIntelligenceState` snapshots from the stores.

    The assembler is read-mostly: it gathers the target, its assets, the
    coverage matrix, gaps, hypotheses, conflicts and history from the stores
    and merges them into one immutable snapshot. High-volume stores are counted
    rather than embedded to keep the footprint bounded.
    """

    def __init__(
        self,
        *,
        coverage: CoverageEngine | None = None,
    ) -> None:
        self._coverage = coverage or CoverageEngine()

    def assemble(
        self,
        *,
        target: IntelligenceTarget,
        assets: Sequence[IntelligenceAsset],
        coverage: Any | None = None,
        gaps: Sequence[Any] = (),
        hypotheses: Sequence[Any] = (),
        negative_results: Sequence[Any] = (),
        conflicts: Sequence[Any] = (),
        history: Sequence[TargetHistoryEntry] = (),
        observation_count: int = 0,
        evidence_count: int = 0,
        score: IntelligenceScore | None = None,
        mission_id: str = "",
    ) -> TargetIntelligenceState:
        """Assemble an immutable state snapshot."""
        matrix = coverage if coverage is not None else self._coverage.matrix(target.target_id)
        return TargetIntelligenceState(
            target=target,
            assets=tuple(assets),
            coverage=matrix,
            gaps=tuple(gaps),
            hypotheses=tuple(hypotheses),
            observation_count=observation_count,
            evidence_count=evidence_count,
            negative_results=tuple(negative_results),
            conflicts=tuple(conflicts),
            history=tuple(history),
            score=score,
            updated_at=utcnow_iso(),
        )


class IntelligenceScoreEngine:
    """Compute the explainable multi-dimension intelligence score."""

    def __init__(self, *, coverage: CoverageEngine | None = None) -> None:
        self._coverage = coverage or CoverageEngine()

    def score(
        self,
        *,
        target: IntelligenceTarget,
        matrix: Any,
        weights: dict[str, float] | None = None,
        policy_id: str = "target-intelligence/ranking/1.0.0",
    ) -> IntelligenceScore:
        """Return an explainable :class:`IntelligenceScore` for the target."""
        dimensions, aggregate, normalized = self._coverage.score(matrix, weights=weights, policy_id=policy_id)
        return IntelligenceScore(
            target_id=target.target_id,
            dimensions=dimensions,
            aggregate=aggregate,
            weights=normalized,
            computed_at=utcnow_iso(),
            policy_id=policy_id,
        )


def recommend_phase(
    target: IntelligenceTarget,
    matrix: Any,
    *,
    open_hypotheses: int = 0,
    validated_count: int = 0,
    proved_count: int = 0,
) -> IntelligencePhase:
    """Recommend the next intelligence phase from the current state.

    The recommendation is derived from coverage, unknowns and hypothesis state —
    never from a hardcoded tool sequence. The highest phase whose preconditions
    hold is returned, so a fully-covered target advances to PROOF/REPORTING
    rather than stalling at DISCOVERY.
    """
    ratio = matrix.coverage_ratio()
    phase = target.phase
    candidates: list[tuple[IntelligencePhase, bool]] = [
        (IntelligencePhase.ENUMERATION, ratio > 0.15),
        (IntelligencePhase.MAPPING, ratio > 0.35),
        (IntelligencePhase.ANALYSIS, ratio > 0.5),
        (IntelligencePhase.HYPOTHESIS, open_hypotheses == 0 and ratio > 0.6),
        (IntelligencePhase.VALIDATION, open_hypotheses > 0),
        (IntelligencePhase.PROOF, validated_count > 0),
        (IntelligencePhase.REPORTING, proved_count > 0),
    ]
    justified = [candidate for candidate, holds in candidates if holds]
    if not justified:
        return phase
    highest = max(justified, key=lambda item: item.rank)
    if highest.rank >= phase.rank:
        return highest
    return phase


__all__ = [
    "CoverageCapability",
    "CoverageState",
    "IntelligenceDimension",
    "IntelligencePhase",
    "IntelligenceScore",
    "IntelligenceScoreEngine",
    "IntelligenceTargetStatus",
    "TargetIntelligenceState",
    "TargetIntelligenceStateAssembler",
    "recommend_phase",
]
