# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Offensive Tool Orchestration engine."""

from __future__ import annotations

from hunterx.engines.orchestration.checkpoints import (
    MissionCheckpoint,
    MissionCheckpointManager,
)
from hunterx.engines.orchestration.coverage import CoverageMetric, CoverageModel, CoverageReport
from hunterx.engines.orchestration.dedup import (
    ExecutionDeduplicator,
    ExecutionRecord,
    execution_hash,
)
from hunterx.engines.orchestration.engine import (
    MissionRun,
    OffensiveOrchestrationEngine,
)
from hunterx.engines.orchestration.events import MissionEventEmitter
from hunterx.engines.orchestration.executor import (
    MissionExecutor,
    MissionRunResult,
    StepOutcome,
)
from hunterx.engines.orchestration.fallback import FallbackDecision, FallbackEngine
from hunterx.engines.orchestration.graph import (
    GraphEdge,
    GraphNode,
    MissionDependencyGraph,
)
from hunterx.engines.orchestration.lifecycle import (
    MissionLifecycle,
    MissionLifecycleOperator,
    Transition,
)
from hunterx.engines.orchestration.memory import MissionMemoryStore, TargetMemory
from hunterx.engines.orchestration.planner import IntelligenceSummary, MissionPlanner
from hunterx.engines.orchestration.quality import (
    MissionQuality,
    MissionQualityScorer,
    QualityFactor,
)
from hunterx.engines.orchestration.ratelimit import RateLimiter
from hunterx.engines.orchestration.replan import (
    DiscoveredAsset,
    ReplanDecision,
    ReplanningEngine,
    ReplanRequest,
)
from hunterx.engines.orchestration.retry import (
    FailureClassifier,
    FailureReport,
    RetryEngine,
)
from hunterx.engines.orchestration.safety import (
    MissionSafetyEnforcer,
    SafetyDecision,
)
from hunterx.engines.orchestration.scope import (
    MissionScopeGuard,
    ScopeDecision,
)
from hunterx.engines.orchestration.selector import MissionToolSelector

__all__ = [
    "FailureClassifier",
    "FailureReport",
    "RetryEngine",
    "MissionLifecycle",
    "MissionLifecycleOperator",
    "Transition",
    "MissionScopeGuard",
    "ScopeDecision",
    "MissionSafetyEnforcer",
    "SafetyDecision",
    "MissionToolSelector",
    "MissionPlanner",
    "IntelligenceSummary",
    "MissionDependencyGraph",
    "GraphEdge",
    "GraphNode",
    "MissionExecutor",
    "StepOutcome",
    "MissionRunResult",
    "ExecutionDeduplicator",
    "ExecutionRecord",
    "execution_hash",
    "FallbackEngine",
    "FallbackDecision",
    "RateLimiter",
    "MissionCheckpoint",
    "MissionCheckpointManager",
    "MissionMemoryStore",
    "TargetMemory",
    "ReplanningEngine",
    "ReplanRequest",
    "ReplanDecision",
    "DiscoveredAsset",
    "CoverageModel",
    "CoverageReport",
    "CoverageMetric",
    "MissionQualityScorer",
    "MissionQuality",
    "QualityFactor",
    "MissionEventEmitter",
    "OffensiveOrchestrationEngine",
    "MissionRun",
]
