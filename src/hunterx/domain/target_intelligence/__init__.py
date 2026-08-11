# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Adaptive Target Intelligence (Sprint 026).

The Target Intelligence layer turns HunterX from a *tool runner* into a
*target intelligence system*: every target is represented as a continuously
evolving attack-surface graph backed by immutable observations, explicit
coverage, explicit uncertainty, hypotheses to validate, and an explainable
next-action engine that selects the smallest justified tool set.

Pure domain models and engines — no I/O, no tool execution. The application
layer (`hunterx.application.target_intelligence`) and the engine facade
(`hunterx.engines.target_intelligence`) wire these to the TIDB and the Sprint
025 selector.
"""

from __future__ import annotations

from hunterx.domain.target_intelligence.actions import (
    DEFAULT_RANKING_WEIGHTS,
    ActionStatus,
    ActionType,
    IntelligenceAction,
    IntelligenceDecision,
    NextActionEngine,
    RankingWeights,
    StopCondition,
)
from hunterx.domain.target_intelligence.conflicts import (
    ConflictState,
    IntelligenceConflict,
    IntelligenceConflictDetector,
    IntelligenceConflictManager,
)
from hunterx.domain.target_intelligence.correlation import (
    CorrelatedObservation,
    CorrelationResult,
    IntelligenceCorrelationEngine,
)
from hunterx.domain.target_intelligence.coverage import (
    CoverageCapability,
    CoverageEngine,
    CoverageEntry,
    CoverageMatrix,
    CoverageState,
)
from hunterx.domain.target_intelligence.enums import (
    ChangeKind,
    HypothesisStatus,
    HypothesisType,
    InformationGapCategory,
    IntelligenceDimension,
    IntelligencePhase,
    IntelligenceTargetKind,
    IntelligenceTargetStatus,
    ObservationType,
    UnknownCategory,
)
from hunterx.domain.target_intelligence.graph import AttackSurfaceGraph
from hunterx.domain.target_intelligence.history import (
    IntelligenceChange,
    TargetChangeDetector,
    TargetHistory,
    TargetHistoryEntry,
)
from hunterx.domain.target_intelligence.hypotheses import (
    Hypothesis,
    HypothesisEngine,
)
from hunterx.domain.target_intelligence.models import (
    IntelligenceAsset,
    IntelligenceEvidence,
    IntelligenceScore,
    IntelligenceTarget,
    NegativeResult,
    Observation,
    TargetIntelligenceState,
    observation_key,
)
from hunterx.domain.target_intelligence.replay import (
    IntelligenceReplayRunner,
    ReplayRun,
)
from hunterx.domain.target_intelligence.scope import (
    ScopeViolationError,
    TargetIntelligenceScopeEnforcer,
    TargetIsolationContext,
)
from hunterx.domain.target_intelligence.state import (
    IntelligenceScoreEngine,
    TargetIntelligenceStateAssembler,
    recommend_phase,
)
from hunterx.domain.target_intelligence.stores import (
    AssetIntelligenceStore,
    EvidenceStore,
    InMemoryAssetIntelligenceStore,
    InMemoryEvidenceStore,
    InMemoryObservationStore,
    ObservationStore,
)
from hunterx.domain.target_intelligence.unknowns import (
    InformationGap,
    UnknownsEngine,
)

__all__ = [
    "ActionStatus",
    "ActionType",
    "AssetIntelligenceStore",
    "AttackSurfaceGraph",
    "ChangeKind",
    "ConflictState",
    "CorrelatedObservation",
    "CorrelationResult",
    "CoverageCapability",
    "CoverageEngine",
    "CoverageEntry",
    "CoverageMatrix",
    "CoverageState",
    "DEFAULT_RANKING_WEIGHTS",
    "EvidenceStore",
    "Hypothesis",
    "HypothesisEngine",
    "HypothesisStatus",
    "HypothesisType",
    "InformationGap",
    "InformationGapCategory",
    "InMemoryAssetIntelligenceStore",
    "InMemoryEvidenceStore",
    "InMemoryObservationStore",
    "IntelligenceAction",
    "IntelligenceAsset",
    "IntelligenceChange",
    "IntelligenceConflict",
    "IntelligenceConflictDetector",
    "IntelligenceConflictManager",
    "IntelligenceCorrelationEngine",
    "IntelligenceDecision",
    "IntelligenceDimension",
    "IntelligenceEvidence",
    "IntelligencePhase",
    "IntelligenceReplayRunner",
    "IntelligenceScore",
    "IntelligenceScoreEngine",
    "IntelligenceTarget",
    "IntelligenceTargetKind",
    "IntelligenceTargetStatus",
    "NegativeResult",
    "NextActionEngine",
    "Observation",
    "ObservationStore",
    "ObservationType",
    "RankingWeights",
    "ReplayRun",
    "ScopeViolationError",
    "StopCondition",
    "TargetChangeDetector",
    "TargetHistory",
    "TargetHistoryEntry",
    "TargetIntelligenceScopeEnforcer",
    "TargetIntelligenceState",
    "TargetIntelligenceStateAssembler",
    "TargetIsolationContext",
    "UnknownCategory",
    "UnknownsEngine",
    "observation_key",
    "recommend_phase",
]
