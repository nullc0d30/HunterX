# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Architecture tests for the target-agnostic attack-surface subsystem.

Verifies the Phase 1 discipline: pure domain (no infrastructure/tools/engines),
an explainable capability mapper, a completion gate with no execution
primitive, a universal assessment queue carrying every required field, and
extensibility without a closed switch over target-specific kinds.
"""

from __future__ import annotations

import inspect

from hunterx.architecture.layers import resolve_layer
from hunterx.domain.attack_surface.capability_map import CapabilityMapper
from hunterx.domain.attack_surface.completion import CompletionGate
from hunterx.domain.attack_surface.graph import SurfaceGraph
from hunterx.domain.attack_surface.models import AssessmentTask, CapabilityAssignment
from hunterx.domain.attack_surface.queue import AssessmentQueue
from hunterx.domain.attack_surface.registry import SurfaceKindRegistry

_DOMAIN_MODULES = (
    "hunterx.domain.attack_surface",
    "hunterx.domain.attack_surface.enums",
    "hunterx.domain.attack_surface.models",
    "hunterx.domain.attack_surface.registry",
    "hunterx.domain.attack_surface.graph",
    "hunterx.domain.attack_surface.capability_map",
    "hunterx.domain.attack_surface.queue",
    "hunterx.domain.attack_surface.completion",
)


def test_domain_modules_resolve_to_domain_layer() -> None:
    for module in _DOMAIN_MODULES:
        assert resolve_layer(module).name == "domain", module


def test_application_module_resolves_to_application_layer() -> None:
    assert resolve_layer("hunterx.application.attack_surface").name == "application"


def test_domain_does_not_import_infrastructure_or_tools() -> None:
    banned = ("infrastructure", "tools", "platform", "application", "engines")
    for module_name in _DOMAIN_MODULES:
        module = __import__(module_name, fromlist=["*"])
        source = inspect.getsource(module)
        matches = [part for part in banned if f"hunterx.{part}" in source]
        assert not matches, f"{module_name} must not import hunterx.{banned}: {matches}"


def test_no_hardcoded_universal_tool_pipeline() -> None:
    """The mapper/graph/queue/completion must not hardcode a tool chain."""
    for component in (CapabilityMapper, SurfaceGraph, AssessmentQueue, CompletionGate, SurfaceKindRegistry):
        source = inspect.getsource(component)
        for tool in ("subfinder", "nuclei", "sqlmap", "katana", "arjun", "nmap", "httpx"):
            assert tool not in source, f"{component.__name__} hardcodes {tool}"


def test_mapper_is_explainable() -> None:
    """Capability assignments must carry a rationale, not a black-box score."""
    source = inspect.getsource(CapabilityMapper)
    assert "rationale" in source
    assert "priority" in source


def test_completion_gate_never_executes() -> None:
    """The completion gate is intelligence only: no execution primitive."""
    source = inspect.getsource(CompletionGate)
    assert "execute" not in source
    assert "EXHAUSTED" in source
    assert "TARGET_UNAVAILABLE" in source


def test_assessment_task_carries_required_fields() -> None:
    """The universal queue item bundles every Phase 1 scheduling attribute."""
    fields = AssessmentTask.__dataclass_fields__  # type: ignore[attr-defined]
    for required in (
        "surface_key",
        "capability_id",
        "context",
        "strategy",
        "priority",
        "status",
        "attempts",
        "evidence",
        "verification_state",
    ):
        assert required in fields, f"AssessmentTask missing {required}"
    # Authentication + authorization state are accessible from the item.
    assert hasattr(AssessmentTask, "auth_state")
    assert hasattr(AssessmentTask, "authorization_state")
    # Identity is surface × capability × context.
    assert hasattr(AssessmentTask, "dedup_key")


def test_capability_assignment_carries_surface_capability_context() -> None:
    """The Capability × Surface × Context triple is first-class."""
    fields = CapabilityAssignment.__dataclass_fields__  # type: ignore[attr-defined]
    for required in ("surface_key", "capability_id", "context", "applicable", "rationale", "priority", "status"):
        assert required in fields


def test_graph_is_kind_agnostic() -> None:
    """Core traversal must not branch on a specific surface kind."""
    source = inspect.getsource(SurfaceGraph).lower()
    # No target-specific object names are allowed in the graph core.
    for forbidden in ("order", "user", "product", "checkout", "basket", "juice", "shop"):
        assert not _has_word(source, forbidden), f"SurfaceGraph core hardcodes {forbidden}"


def test_queue_is_target_agnostic() -> None:
    source = inspect.getsource(AssessmentQueue).lower()
    for forbidden in ("order", "user", "product", "juice", "shop"):
        assert not _has_word(source, forbidden), f"AssessmentQueue hardcodes {forbidden}"


def _has_word(text: str, word: str) -> bool:
    """Return ``True`` when ``word`` appears as a whole word in ``text``."""
    import re

    return re.search(rf"\b{word}\b", text) is not None
