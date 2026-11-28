# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Target-agnostic attack-surface model and mission orchestration primitives."""

from __future__ import annotations

from hunterx.domain.attack_surface.capability_map import CapabilityMapper, CapabilityMappingRule
from hunterx.domain.attack_surface.completion import CompletionGate
from hunterx.domain.attack_surface.enums import (
    AssessmentStatus,
    AuthContextState,
    CompletionVerdict,
    ExhaustionCriterion,
    SurfaceKind,
    SurfaceLayer,
    VerificationState,
)
from hunterx.domain.attack_surface.graph import SurfaceGraph
from hunterx.domain.attack_surface.models import (
    AssessmentTask,
    CapabilityAssignment,
    DynamicObject,
    ExhaustionReport,
    SurfaceContext,
    SurfaceEdge,
    SurfaceNode,
    layer_for,
    surface_key,
)
from hunterx.domain.attack_surface.queue import AssessmentQueue, schedule_assignments
from hunterx.domain.attack_surface.registry import SurfaceKindRegistry, SurfaceKindSpec

__all__ = [
    "AssessmentQueue",
    "AssessmentStatus",
    "AssessmentTask",
    "AuthContextState",
    "CapabilityAssignment",
    "CapabilityMapper",
    "CapabilityMappingRule",
    "CompletionGate",
    "CompletionVerdict",
    "DynamicObject",
    "ExhaustionCriterion",
    "ExhaustionReport",
    "SurfaceContext",
    "SurfaceEdge",
    "SurfaceGraph",
    "SurfaceKind",
    "SurfaceKindRegistry",
    "SurfaceKindSpec",
    "SurfaceLayer",
    "SurfaceNode",
    "VerificationState",
    "layer_for",
    "schedule_assignments",
    "surface_key",
]
