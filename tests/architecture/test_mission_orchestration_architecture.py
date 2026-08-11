# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Architecture tests for the Autonomous Mission Orchestration layer.

Sprint 032 §55. Verifies the Domain → Application → Ports → Adapters →
Infrastructure layering: the orchestration domain stays free of I/O and
concrete tools, the engine facade is injectable/composable, decisions are
explainable, and mission orchestration never depends on concrete tool
implementations.
"""

from __future__ import annotations

import inspect

from hunterx.architecture.layers import resolve_layer
from hunterx.domain.mission_orchestration.decision import MissionDecisionEngine
from hunterx.domain.mission_orchestration.hypothesis import HypothesisLoopEngine
from hunterx.domain.mission_orchestration.mission import new_orchestrated_mission
from hunterx.domain.mission_orchestration.orchestrator import MissionOrchestrator
from hunterx.engines.mission_orchestration import MissionOrchestrationEngine

_DOMAIN_MODULES = (
    "hunterx.domain.mission_orchestration.enums",
    "hunterx.domain.mission_orchestration.models",
    "hunterx.domain.mission_orchestration.mission",
    "hunterx.domain.mission_orchestration.hypothesis",
    "hunterx.domain.mission_orchestration.decision",
    "hunterx.domain.mission_orchestration.baseline",
    "hunterx.domain.mission_orchestration.negative",
    "hunterx.domain.mission_orchestration.coverage",
    "hunterx.domain.mission_orchestration.gap",
    "hunterx.domain.mission_orchestration.confidence",
    "hunterx.domain.mission_orchestration.branch",
    "hunterx.domain.mission_orchestration.telemetry",
    "hunterx.domain.mission_orchestration.trace",
    "hunterx.domain.mission_orchestration.policy",
    "hunterx.domain.mission_orchestration.impact",
    "hunterx.domain.mission_orchestration.cascade",
    "hunterx.domain.mission_orchestration.orchestrator",
)


def test_domain_modules_resolve_to_domain_layer() -> None:
    for module in _DOMAIN_MODULES:
        assert resolve_layer(module).name == "domain"


def test_engine_and_application_resolve_to_their_layers() -> None:
    assert resolve_layer("hunterx.engines.mission_orchestration.engine").name == "engines"
    assert resolve_layer("hunterx.application.mission_orchestration").name == "application"
    assert resolve_layer("hunterx.api.mission_orchestration").name == "api"


def test_domain_does_not_import_infrastructure_or_tools() -> None:
    """Pure domain modules must stay free of I/O, infrastructure and tools."""
    import re

    banned = ("infrastructure", "tools", "platform", "application", "engines")
    for module_name in _DOMAIN_MODULES:
        module = __import__(module_name, fromlist=["*"])
        source = inspect.getsource(module)
        matches = re.findall(rf"(?:import|from)\s+hunterx\.{banned}", source)
        assert not matches, f"{module_name} must not import hunterx.{' or hunterx.'.join(banned)}: {matches}"


def test_no_hardcoded_tool_names_in_decision_engine() -> None:
    """The decision engine must not hardcode concrete tool chains."""
    source = inspect.getsource(MissionDecisionEngine)
    for tool in ("subfinder", "nuclei", "sqlmap", "katana", "arjun", "amass", "dalfox"):
        assert tool not in source


def test_decision_is_explainable() -> None:
    """Decisions must carry NEXT_ACTION/REASON/EXPECTED_RESULT/ALTERNATIVES."""
    source = inspect.getsource(MissionDecisionEngine)
    assert "reason" in source
    assert "expected_result" in source
    assert "alternatives" in source
    assert "information_gain" in source


def test_orchestrator_composes_pure_engines() -> None:
    """The orchestrator is composed from pure engines; no I/O at construction."""
    orchestrator = MissionOrchestrator()
    assert isinstance(orchestrator.hypothesis_loop, HypothesisLoopEngine)
    assert isinstance(orchestrator.decision, MissionDecisionEngine)


def test_orchestration_never_imports_concrete_tool_adapters() -> None:
    """Mission orchestration must not depend on concrete tool implementations."""
    source = inspect.getsource(MissionOrchestrator)
    assert "hunterx.tools" not in source
    assert "ExecutionEngine" not in source
    # the orchestrator consumes normalized observations, never raw tool calls
    assert "ingest_result" in source


def test_engine_facade_is_injectable() -> None:
    """The engine facade is injectable with a pre-composed orchestrator."""
    engine = MissionOrchestrationEngine()
    assert isinstance(engine.orchestrator, MissionOrchestrator)


def test_mission_model_is_stateful_adaptive_not_static() -> None:
    """The mission aggregate holds a planning graph plus reasoning state."""
    mission = new_orchestrated_mission()
    assert hasattr(mission, "mission")  # wraps the adaptive planning aggregate
    assert hasattr(mission, "context")
    assert hasattr(mission, "hypotheses")
    assert hasattr(mission, "decisions")
    assert hasattr(mission, "branches")
    assert hasattr(mission, "coverage")
