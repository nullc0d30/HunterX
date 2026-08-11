# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Autonomous Mission Orchestration Engine (Sprint 032).

Turns HunterX from a *planner of command lists* into a stateful, adaptive,
evidence-driven mission orchestrator. It reuses the Sprint 027 planning
aggregate (:class:`AdaptiveMission` + ``AdaptiveExecutionGraph``) as the
executable mission and adds the reasoning/evidence layer that drives the
adaptive loop:

    OBSERVE → HYPOTHESIZE → TEST → OBSERVE → UPDATE HYPOTHESIS → TEST →
    VERIFY → PROVE

The orchestrator ranks every candidate action by expected information gain,
maintains baseline + differential testing, bounded negative evidence, mission
coverage, knowledge gaps, evidence-driven confidence, mission branches,
telemetry, a structured reasoning trace, mission policies and stop conditions,
impact analysis and finding cascades. AI suggestions are advisory only —
deterministic components enforce schema, state transitions, tool contracts,
scope, persistence and evidence provenance.

Pure domain models and engines — no I/O, no tool execution. The engine facade
(``hunterx.engines.mission_orchestration``) and the application layer
(``hunterx.application.mission_orchestration``) wire these to the platform.
"""

from __future__ import annotations

from hunterx.domain.mission_orchestration.baseline import (
    BaselineEngine,
    BaselineObservation,
    DifferentialSignal,
    DifferentialTestEngine,
    TestResponse,
)
from hunterx.domain.mission_orchestration.branch import BranchManager
from hunterx.domain.mission_orchestration.cascade import CascadeTrigger, FindingCascadeEngine
from hunterx.domain.mission_orchestration.confidence import (
    ConfidenceComponent,
    ConfidenceEngine,
    ConfidenceInput,
    ConfidenceResult,
)
from hunterx.domain.mission_orchestration.coverage import MissionCoverageEngine
from hunterx.domain.mission_orchestration.decision import (
    CandidateAction,
    DecisionInput,
    MissionDecisionEngine,
)
from hunterx.domain.mission_orchestration.enums import (
    BehaviorClass,
    FindingStage,
    HypothesisState,
    MissionEventType,
    MissionPhase,
    MissionRunStatus,
    NegativeEvidenceKind,
    NovelPipelineStage,
    ReasoningTraceKind,
    StopCondition,
    StrategyKind,
)
from hunterx.domain.mission_orchestration.gap import KnowledgeGap, KnowledgeGapEngine
from hunterx.domain.mission_orchestration.hypothesis import HypothesisLoopEngine
from hunterx.domain.mission_orchestration.impact import ImpactAnalysisEngine
from hunterx.domain.mission_orchestration.mission import (
    OrchestratedMission,
    new_orchestrated_mission,
)
from hunterx.domain.mission_orchestration.models import (
    CoverageCell,
    DifferentialResult,
    ImpactAnalysis,
    MissionBranch,
    MissionBudget,
    MissionContext,
    MissionDecision,
    MissionHypothesis,
    MissionObservation,
    MissionOutcome,
    MissionPolicy,
    MissionRun,
    MissionScope,
    NegativeEvidenceRecord,
    NovelBehaviorRecord,
    ReasoningTraceEntry,
    TelemetrySnapshot,
)
from hunterx.domain.mission_orchestration.negative import NegativeEvidenceEngine
from hunterx.domain.mission_orchestration.objective import resolve_objective
from hunterx.domain.mission_orchestration.orchestrator import MissionOrchestrator
from hunterx.domain.mission_orchestration.policy import MissionPolicyEngine, PolicyVerdict
from hunterx.domain.mission_orchestration.telemetry import MissionTelemetry
from hunterx.domain.mission_orchestration.trace import ReasoningTrace

__all__ = [
    "BaselineEngine",
    "BaselineObservation",
    "BehaviorClass",
    "BranchManager",
    "CandidateAction",
    "CascadeTrigger",
    "ConfidenceComponent",
    "ConfidenceEngine",
    "ConfidenceInput",
    "ConfidenceResult",
    "CoverageCell",
    "DecisionInput",
    "DifferentialResult",
    "DifferentialSignal",
    "DifferentialTestEngine",
    "FindingCascadeEngine",
    "FindingStage",
    "HypothesisLoopEngine",
    "HypothesisState",
    "ImpactAnalysis",
    "ImpactAnalysisEngine",
    "KnowledgeGap",
    "KnowledgeGapEngine",
    "MissionBranch",
    "MissionBudget",
    "MissionContext",
    "MissionCoverageEngine",
    "MissionDecision",
    "MissionDecisionEngine",
    "MissionEventType",
    "MissionHypothesis",
    "MissionObservation",
    "MissionOrchestrator",
    "MissionOutcome",
    "MissionPhase",
    "MissionPolicy",
    "MissionPolicyEngine",
    "MissionRun",
    "MissionRunStatus",
    "MissionScope",
    "MissionTelemetry",
    "NegativeEvidenceEngine",
    "NegativeEvidenceKind",
    "NegativeEvidenceRecord",
    "NovelBehaviorRecord",
    "NovelPipelineStage",
    "OrchestratedMission",
    "PolicyVerdict",
    "ReasoningTrace",
    "ReasoningTraceEntry",
    "ReasoningTraceKind",
    "StopCondition",
    "StrategyKind",
    "TelemetrySnapshot",
    "TestResponse",
    "new_orchestrated_mission",
    "resolve_objective",
]
