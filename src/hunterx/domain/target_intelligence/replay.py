# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Target Intelligence Replay.

Sprint 026. The entire intelligence pipeline must be replayable from stored
artifacts: artifact → parser → observation → correlation → hypothesis → action
recommendation — without rerunning external tools. This module defines the
replay contract and an in-memory replay runner that drives the pipeline stages
from stored observations.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field, replace
from typing import Any

from hunterx.domain.target_intelligence.actions import NextActionEngine
from hunterx.domain.target_intelligence.correlation import IntelligenceCorrelationEngine
from hunterx.domain.target_intelligence.coverage import CoverageEngine
from hunterx.domain.target_intelligence.enums import ObservationType
from hunterx.domain.target_intelligence.hypotheses import HypothesisEngine
from hunterx.domain.target_intelligence.models import (
    CoverageMatrix,
    Hypothesis,
    IntelligenceAction,
    IntelligenceAsset,
    IntelligenceDecision,
    IntelligenceTarget,
    Observation,
    TargetIntelligenceState,
)
from hunterx.domain.topology.enums import EntityKind
from hunterx.shared.time import utcnow_iso


@dataclass(frozen=True, slots=True)
class ReplayRun:
    """Result of replaying the intelligence pipeline from stored observations.

    Attributes:
        run_id: stable run identifier.
        target: the replayed target.
        observation_count: observations consumed.
        correlations: correlation chains produced.
        conflicts: observations flagged as conflicting.
        hypotheses: hypotheses regenerated.
        actions: recommended actions.
        decision: the produced decision.
        completed_at: UTC ISO-8601 completion stamp.
        status: ``replayed`` or ``failed``.

    """

    run_id: str
    target: IntelligenceTarget
    observation_count: int = 0
    correlations: tuple[Any, ...] = ()
    conflicts: tuple[Any, ...] = ()
    hypotheses: tuple[Hypothesis, ...] = ()
    actions: tuple[IntelligenceAction, ...] = ()
    decision: IntelligenceDecision | None = None
    completed_at: str = field(default_factory=utcnow_iso, kw_only=True)
    status: str = "replayed"

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe mapping."""
        return {
            "run_id": self.run_id,
            "target_id": self.target.target_id,
            "observation_count": self.observation_count,
            "correlations": [c.to_dict() for c in self.correlations],
            "conflicts": [c.to_dict() for c in self.conflicts],
            "hypotheses": [h.to_dict() for h in self.hypotheses],
            "actions": [a.to_dict() for a in self.actions],
            "decision": self.decision.to_dict() if self.decision is not None else None,
            "completed_at": self.completed_at,
            "status": self.status,
        }


class IntelligenceReplayRunner:
    """Replay the intelligence pipeline from stored observations.

    The runner never executes tools: it derives correlation, conflicts,
    hypotheses and action recommendations purely from stored artifacts so a
    mission can be re-audited or re-planned offline.
    """

    def __init__(
        self,
        *,
        correlator: IntelligenceCorrelationEngine | None = None,
        hypotheses: HypothesisEngine | None = None,
        next_action: NextActionEngine | None = None,
        coverage: CoverageEngine | None = None,
    ) -> None:
        self._correlator = correlator or IntelligenceCorrelationEngine()
        self._hypotheses = hypotheses or HypothesisEngine()
        self._next_action = next_action or NextActionEngine()
        self._coverage = coverage or CoverageEngine()

    def replay(
        self,
        target: IntelligenceTarget,
        observations: Sequence[Observation],
        *,
        mission_objective: str = "",
    ) -> ReplayRun:
        """Replay the pipeline for a target over stored observations."""
        correlation = self._correlator.correlate(observations)
        assets = _derive_assets(observations)
        for observation in observations:
            self._coverage.record(
                target_id=target.target_id,
                asset_key=observation.asset_key,
                capability=observation.capability or "vulnerability_scanning",
                state="tested",
                tool=observation.tool,
                confidence=observation.confidence,
            )
        matrix = self._coverage.matrix(target.target_id)
        state = TargetIntelligenceState(
            target=target,
            assets=assets,
            coverage=matrix,
            observation_count=len(observations),
            updated_at=utcnow_iso(),
        )
        hypotheses = self._hypotheses.generate(state)
        state = TargetIntelligenceState(
            target=target,
            assets=assets,
            coverage=matrix,
            hypotheses=tuple(hypotheses),
            observation_count=len(observations),
            updated_at=utcnow_iso(),
        )
        actions, decision = self._next_action.rank(state, mission_objective=mission_objective)
        from hunterx.shared.ids import generate_id

        return ReplayRun(
            run_id=generate_id(),
            target=target,
            observation_count=len(observations),
            correlations=correlation.chains,
            conflicts=correlation.conflicts,
            hypotheses=tuple(hypotheses),
            actions=tuple(actions),
            decision=decision,
            status="replayed",
        )


def _derive_assets(observations: Sequence[Observation]) -> tuple[IntelligenceAsset, ...]:
    """Derive assets from stored observations (purely derivational).

    The asset key prefix is the canonical entity kind; parameter observations
    enrich the endpoint asset they belong to so hypothesis rules see the
    parameter surface.
    """
    assets: dict[str, IntelligenceAsset] = {}
    for observation in observations:
        if not observation.asset_key or ":" not in observation.asset_key:
            continue
        prefix, name = observation.asset_key.split(":", 1)
        existing = assets.get(observation.asset_key)
        if existing is None:
            try:
                kind = EntityKind(prefix)
            except ValueError:
                kind = EntityKind.HOSTNAME
            existing = IntelligenceAsset(
                target_id=observation.target_id,
                mission_id=observation.mission_id,
                kind=kind,
                name=name,
                key=observation.asset_key,
                label=name,
                properties={"source": observation.source},
                source=observation.tool,
                observed_by=(observation.tool,) if observation.tool else (),
            )
            assets[observation.asset_key] = existing
        if observation.observation_type is ObservationType.PARAMETER:
            parameters = list(existing.properties.get("parameters") or ())
            if observation.value not in parameters:
                parameters.append(observation.value)
            existing = replace(
                existing,
                properties={**existing.properties, "parameters": parameters, "capability": observation.capability},
            )
            assets[observation.asset_key] = existing
    return tuple(assets.values())


__all__ = [
    "CoverageMatrix",
    "Hypothesis",
    "IntelligenceAction",
    "IntelligenceDecision",
    "IntelligenceReplayRunner",
    "ReplayRun",
    "TargetIntelligenceState",
]
