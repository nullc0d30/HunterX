# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Autonomous Mission Orchestration Engine.

Turns HunterX from a *planner of command lists* into a stateful, adaptive, evidence-driven mission orchestrator.
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
