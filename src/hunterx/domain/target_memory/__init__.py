# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Target Memory & Campaign Intelligence (Sprint 030).

The historical intelligence layer of HunterX. It turns raw tool output and
discovery records into a persistent, queryable historical understanding of
every authorized target:

* memory observations with first/last seen tracking and classified state,
* reproducible target snapshots and deterministic snapshot diffs,
* change significance classification,
* observation freshness and prioritized revalidation planning,
* mission memory, failed/successful hypothesis memory and tool provenance,
* target risk history, finding history and recurrence detection,
* coverage memory and coverage-gap detection,
* attack-path history and preserved contradictions,
* campaigns with campaign intelligence, and
* advisory next-action recommendations for the mission planner.

This layer NEVER duplicates or replaces Target Intelligence, TIDB, Finding,
Evidence, Mission, Knowledge or Correlation systems: it references canonical
entities by id and adds the historical dimension on top.

Pure domain models and engines — no I/O, no tool execution. The application
layer (`hunterx.application.target_memory`) wires them to the TIDB.
"""

from __future__ import annotations

from hunterx.domain.target_memory.engines import (
    CampaignIntelligenceEngine,
    ChangeSignificanceEngine,
    ContradictionDetector,
    CoverageGapEngine,
    FindingRecurrenceDetector,
    MemoryAwarePlannerContextBuilder,
    MemoryConfidenceEngine,
    NextActionRecommender,
    ObservationFreshnessEngine,
    PlannerContext,
    RevalidationPlanner,
    TargetDiffEngine,
    TargetMemoryAssembler,
    TargetRiskEvaluator,
    build_memory,
)
from hunterx.domain.target_memory.enums import (
    CampaignStatus,
    ChangeSignificance,
    CoverageGapKind,
    DiffChangeKind,
    FreshnessState,
    HypothesisOutcome,
    MemoryContradictionState,
    MemoryObservationState,
    MemoryValidity,
    RecurrenceKind,
    RevalidationPriority,
    RiskLevel,
)
from hunterx.domain.target_memory.models import (
    AttackPathMemory,
    Campaign,
    CampaignIntelligence,
    CoverageGap,
    FindingMemory,
    FindingRecurrence,
    HypothesisMemory,
    MemoryContradiction,
    MemoryObservation,
    MissionMemory,
    NextActionRecommendation,
    RevalidationItem,
    RevalidationPlan,
    TargetChange,
    TargetDiff,
    TargetMemory,
    TargetRiskEntry,
    TargetSnapshot,
    ToolObservation,
    campaign_key,
    memory_observation_key,
)

__all__ = [
    "AttackPathMemory",
    "Campaign",
    "CampaignIntelligence",
    "CampaignIntelligenceEngine",
    "CampaignStatus",
    "ChangeSignificance",
    "ChangeSignificanceEngine",
    "ContradictionDetector",
    "CoverageGap",
    "CoverageGapEngine",
    "CoverageGapKind",
    "DiffChangeKind",
    "FindingMemory",
    "FindingRecurrence",
    "FindingRecurrenceDetector",
    "FreshnessState",
    "HypothesisMemory",
    "HypothesisOutcome",
    "MemoryAwarePlannerContextBuilder",
    "MemoryConfidenceEngine",
    "MemoryContradiction",
    "MemoryContradictionState",
    "MemoryObservation",
    "MemoryObservationState",
    "MemoryValidity",
    "MissionMemory",
    "NextActionRecommender",
    "NextActionRecommendation",
    "ObservationFreshnessEngine",
    "PlannerContext",
    "RecurrenceKind",
    "RevalidationItem",
    "RevalidationPlan",
    "RevalidationPlanner",
    "RevalidationPriority",
    "RiskLevel",
    "TargetChange",
    "TargetDiff",
    "TargetDiffEngine",
    "TargetMemory",
    "TargetMemoryAssembler",
    "TargetRiskEntry",
    "TargetRiskEvaluator",
    "TargetSnapshot",
    "ToolObservation",
    "build_memory",
    "campaign_key",
    "memory_observation_key",
]
