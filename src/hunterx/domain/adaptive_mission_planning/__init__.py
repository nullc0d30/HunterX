# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Adaptive Mission & Attack-Path Planning."""

from __future__ import annotations

from hunterx.domain.adaptive_mission_planning.attack_path import AttackPathEngine
from hunterx.domain.adaptive_mission_planning.catalog import DeterministicPlanner
from hunterx.domain.adaptive_mission_planning.checkpoint import CheckpointEngine
from hunterx.domain.adaptive_mission_planning.decision import (
    ActionDecisionEngine,
    DecisionInput,
    DecisionResult,
)
from hunterx.domain.adaptive_mission_planning.enums import (
    ActionStatus,
    ActionType,
    AttackPathState,
    AttackPathStepKind,
    BranchKind,
    DecisionFactor,
    DependencyKind,
    EvidenceGapKind,
    FailureClass,
    FailureManagement,
    MissionMode,
    MissionObjective,
    MissionState,
    PathScoringDimension,
    PlanDeltaKind,
    ReplanTrigger,
    ToolFailureAction,
    ValidationLevel,
)
from hunterx.domain.adaptive_mission_planning.graph import (
    AdaptiveExecutionGraph,
    InvalidExecutionGraphError,
)
from hunterx.domain.adaptive_mission_planning.mission import (
    AdaptiveMission,
    DeterministicMissionPlanner,
)
from hunterx.domain.adaptive_mission_planning.models import (
    ActionNode,
    ActionProposal,
    AttackPath,
    AttackPathStep,
    ConditionalBranch,
    DecisionRecord,
    DynamicDependency,
    FailureRecord,
    Gap,
    MissionConstraints,
    MissionObjectiveSpec,
    PlanCheckpoint,
    PlanDelta,
    PlanDeltaChange,
    PlanVersion,
    PolicyDecision,
    ToolFallbackRecord,
    ToolSelection,
)
from hunterx.domain.adaptive_mission_planning.objective import (
    MODE_WEIGHTS,
    default_objective_catalog,
)
from hunterx.domain.adaptive_mission_planning.policy import PolicyEngine
from hunterx.domain.adaptive_mission_planning.replan import (
    ReplanningEngine,
    ReplanSignal,
)
from hunterx.domain.adaptive_mission_planning.resource import (
    ResourcePlanner,
    ResourceState,
    TimePlanner,
)
from hunterx.domain.adaptive_mission_planning.scoring import (
    DEFAULT_WEIGHTS,
    ScoringModel,
    ScoringResult,
)
from hunterx.domain.adaptive_mission_planning.state import (
    InvalidMissionStateTransitionError,
    allowed_targets,
    assert_transition,
    can_transition,
)
from hunterx.domain.adaptive_mission_planning.toolchain import (
    FailureClassifier,
    RecoveryEngine,
    ToolChainPlanner,
    ToolFallbackResolver,
    ToolSelectionEngine,
)

__all__ = [
    "ActionDecisionEngine",
    "ActionNode",
    "ActionProposal",
    "ActionStatus",
    "ActionType",
    "AdaptiveExecutionGraph",
    "AdaptiveMission",
    "AttackPath",
    "AttackPathEngine",
    "AttackPathState",
    "AttackPathStep",
    "AttackPathStepKind",
    "BranchKind",
    "CheckpointEngine",
    "ConditionalBranch",
    "DEFAULT_WEIGHTS",
    "DecisionFactor",
    "DecisionInput",
    "DecisionRecord",
    "DecisionResult",
    "DependencyKind",
    "DeterministicMissionPlanner",
    "DeterministicPlanner",
    "DynamicDependency",
    "EvidenceGapKind",
    "FailureClass",
    "FailureClassifier",
    "FailureManagement",
    "FailureRecord",
    "Gap",
    "InvalidExecutionGraphError",
    "InvalidMissionStateTransitionError",
    "MODE_WEIGHTS",
    "MissionConstraints",
    "MissionMode",
    "MissionObjective",
    "MissionObjectiveSpec",
    "MissionState",
    "PathScoringDimension",
    "PlanCheckpoint",
    "PlanDelta",
    "PlanDeltaChange",
    "PlanDeltaKind",
    "PlanVersion",
    "PolicyDecision",
    "PolicyEngine",
    "RecoveryEngine",
    "ReplanSignal",
    "ReplanTrigger",
    "ReplanningEngine",
    "ResourcePlanner",
    "ResourceState",
    "ScoringModel",
    "ScoringResult",
    "TimePlanner",
    "ToolChainPlanner",
    "ToolFailureAction",
    "ToolFallbackRecord",
    "ToolFallbackResolver",
    "ToolSelection",
    "ToolSelectionEngine",
    "ValidationLevel",
    "allowed_targets",
    "assert_transition",
    "can_transition",
    "default_objective_catalog",
]
