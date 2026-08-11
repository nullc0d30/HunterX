# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Offensive Tool Orchestration — domain models.

The orchestration domain is the mission-execution half of HunterX: it defines
the canonical mission lifecycle (created → scoping → planning → ready →
running → … → completed | partial | failed | cancelled), the execution plan
decomposition (phases, steps, dependencies, conditions, tool bindings), the
policy envelopes (risk, safety, execution, tool), tool selection contracts,
execution records, coverage and quality metrics, and the persistence records
that make every mission traceable end to end.

These models are pure data. Execution lives in
``hunterx.engines.orchestration``; persistence lives in the TIDB entity set
(``hunterx.domain.entities.tidb.orchestration``) and the generic repository
factory.

Responsibilities:
    - Canonical mission lifecycle and mission-type vocabulary.
    - Execution plan decomposition (phases → steps) with dependencies.
    - Policy envelopes (execution, safety, tool, retry, rate-limit).
    - Tool selection contracts and persisted selection records.

Extension points:
    - New mission types and phases via the enums module.
    - New persistence adapters implementing ``hunterx.domain.ports.orchestration``.

Dependencies:
    - ``hunterx.shared`` for identifiers and timestamps.
"""

from hunterx.domain.orchestration.enums import (
    CoverageKind,
    ExecutionPolicyLevel,
    FailureClass,
    FailureManagement,
    MissionPhaseKind,
    MissionState,
    MissionType,
    ScopeClassification,
    TaskState,
)
from hunterx.domain.orchestration.models import (
    Authorization,
    ExecutionPlan,
    MissionScope,
    MissionStep,
    OffensiveMission,
    Phase,
    Policies,
    RateLimitPolicy,
    RetryPolicy,
    SafetyPolicy,
    TargetSet,
    ToolPolicy,
)
from hunterx.domain.orchestration.selection import (
    CapabilityNeed,
    ToolSelection,
    ToolSelectionResult,
)

__all__ = [
    "Authorization",
    "CapabilityNeed",
    "CoverageKind",
    "ExecutionPlan",
    "ExecutionPolicyLevel",
    "FailureClass",
    "FailureManagement",
    "MissionPhaseKind",
    "MissionScope",
    "MissionState",
    "MissionStep",
    "MissionType",
    "OffensiveMission",
    "Phase",
    "Policies",
    "RateLimitPolicy",
    "RetryPolicy",
    "SafetyPolicy",
    "ScopeClassification",
    "TargetSet",
    "TaskState",
    "ToolPolicy",
    "ToolSelection",
    "ToolSelectionResult",
]
