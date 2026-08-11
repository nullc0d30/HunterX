# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Offensive Tool Orchestration engine.

The mission-execution half of HunterX: lifecycle state machine, scope guard,
safety enforcer, capability-driven tool selection, adaptive planning,
dependency-graph execution through the Tool Integration SDK, retry/fallback/
dedup/rate-limit engines, checkpoints, mission memory, replanning, coverage,
quality scoring and the canonical mission event stream.

Responsibilities:
    - Mission lifecycle state machine with validated transitions.
    - Scope and safety enforcement before every task.
    - Capability-driven tool selection, retry, fallback, dedup and rate limits.
    - Dependency-graph execution through the Tool Integration SDK.
    - Checkpoints, mission memory, replanning, coverage and quality scoring.
    - Canonical ``mission.*`` event emission.

Extension points:
    - New mission phases via ``hunterx.engines.orchestration.planner``.
    - Alternative scope guards implementing the same decision contract.
    - Persistence adapters wired through the platform assembler.

Dependencies:
    - ``hunterx.domain.orchestration`` (models and enums).
    - ``hunterx.tools.sdk`` (execution engine) and ``hunterx.tools.intelligence`` (TIP).
    - ``hunterx.domain.events`` (typed mission events).
"""

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
