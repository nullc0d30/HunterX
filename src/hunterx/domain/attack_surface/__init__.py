# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Target-agnostic attack-surface model and mission orchestration primitives.

Phase 1. This package provides the generic capability model the orchestration
walk uses: a unified, extensible attack-surface representation
(:class:`~hunterx.domain.attack_surface.graph.SurfaceGraph`), the
``Capability × Surface × Context`` mapping
(:class:`~hunterx.domain.attack_surface.capability_map.CapabilityMapper`), the
universal assessment queue
(:class:`~hunterx.domain.attack_surface.queue.AssessmentQueue`) and the
exhaustion completion gate
(:class:`~hunterx.domain.attack_surface.completion.CompletionGate`).

Responsibilities
    * Represent every discovered surface generically (target, asset, service,
      application, surface, input, object, state, workflow, capability).
    * Map each discovered surface to the security capabilities the live HunterX
      catalog offers, conditioned on authentication/authorization/technology
      context.
    * Schedule mapped ``Capability × Surface × Context`` combinations through a
      universal assessment queue.
    * Decide assessment exhaustion (discovery, dynamic discovery, combinations,
      assessment queue, verification queue, attack paths) as the completion
      gate — failure is never converted into completion.

Dependencies
    * ``hunterx.shared`` (identifiers, time) for stable identity and stamps.
    * Other ``hunterx.domain`` packages (target intelligence coverage
      vocabulary) for the capability catalog; the domain layer never depends on
      infrastructure, tools, engines or application.

Extension points
    * :class:`SurfaceKindRegistry` — register new surface kinds and their
      observation-type classification without touching core orchestration.
    * :class:`CapabilityMappingRule` — add new ``Capability × SurfaceKind``
      mapping rules (with optional context predicates).
    * Target-specific business objects are represented dynamically through
      :class:`DynamicObject`; no new object model is required per target.

Nothing here assumes a specific target technology, route, object model or
authentication flow. Adding a new target technology requires registering kinds
and observing surfaces — never changing core orchestration logic.
"""

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
