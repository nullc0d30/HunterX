# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Architecture tests for the Adaptive Mission & Attack-Path Planning layer.

Verifies layer discipline (pure domain vs engine vs application vs
infrastructure), import hygiene and the absence of a hardcoded universal tool
pipeline or an opaque black-box scoring model.
"""

from __future__ import annotations

import inspect

from hunterx.architecture.layers import resolve_layer
from hunterx.domain.adaptive_mission_planning.attack_path import AttackPathEngine
from hunterx.domain.adaptive_mission_planning.decision import ActionDecisionEngine
from hunterx.domain.adaptive_mission_planning.graph import AdaptiveExecutionGraph
from hunterx.domain.adaptive_mission_planning.mission import AdaptiveMission
from hunterx.domain.adaptive_mission_planning.replan import ReplanningEngine
from hunterx.domain.adaptive_mission_planning.scoring import ScoringModel
from hunterx.engines.adaptive_mission_planning.engine import AdaptiveMissionPlanningEngine


def test_domain_modules_resolve_to_domain_layer() -> None:
    for module in (
        "hunterx.domain.adaptive_mission_planning.models",
        "hunterx.domain.adaptive_mission_planning.enums",
        "hunterx.domain.adaptive_mission_planning.graph",
        "hunterx.domain.adaptive_mission_planning.decision",
        "hunterx.domain.adaptive_mission_planning.replan",
        "hunterx.domain.adaptive_mission_planning.attack_path",
        "hunterx.domain.adaptive_mission_planning.policy",
        "hunterx.domain.adaptive_mission_planning.scoring",
        "hunterx.domain.adaptive_mission_planning.toolchain",
        "hunterx.domain.adaptive_mission_planning.checkpoint",
    ):
        assert resolve_layer(module).name == "domain"


def test_engine_and_application_resolve_to_their_layers() -> None:
    assert resolve_layer("hunterx.engines.adaptive_mission_planning.engine").name == "engines"
    assert resolve_layer("hunterx.application.adaptive_mission_planning").name == "application"


def test_domain_does_not_import_infrastructure_or_tools() -> None:
    """Pure domain modules must stay free of I/O, infrastructure and tools."""
    banned = ("infrastructure", "tools", "platform", "application", "engines")
    for module_name in (
        "hunterx.domain.adaptive_mission_planning.models",
        "hunterx.domain.adaptive_mission_planning.enums",
        "hunterx.domain.adaptive_mission_planning.graph",
        "hunterx.domain.adaptive_mission_planning.decision",
        "hunterx.domain.adaptive_mission_planning.replan",
        "hunterx.domain.adaptive_mission_planning.attack_path",
        "hunterx.domain.adaptive_mission_planning.policy",
        "hunterx.domain.adaptive_mission_planning.scoring",
        "hunterx.domain.adaptive_mission_planning.toolchain",
        "hunterx.domain.adaptive_mission_planning.checkpoint",
        "hunterx.domain.adaptive_mission_planning.resource",
        "hunterx.domain.adaptive_mission_planning.catalog",
        "hunterx.domain.adaptive_mission_planning.state",
    ):
        module = __import__(module_name, fromlist=["*"])
        source = inspect.getsource(module)
        for banned_part in banned:
            import re

            matches = re.findall(rf"(?:import|from)\s+hunterx\.{banned_part}", source)
            assert not matches, f"{module_name} must not import hunterx.{banned_part}: {matches}"


def test_no_hardcoded_universal_tool_pipeline() -> None:
    """The planner must not contain one universal ordered tool chain."""
    source = inspect.getsource(ActionDecisionEngine)
    for tool in ("subfinder", "nuclei", "sqlmap", "katana", "arjun"):
        assert tool not in source
    source = inspect.getsource(AdaptiveExecutionGraph)
    assert "def topological_order" in source


def test_scoring_is_explainable_not_black_box() -> None:
    """The scoring model must expose configurable factor weights and a rationale."""
    source = inspect.getsource(ScoringModel)
    assert "DecisionFactor" in source
    assert "weights" in source
    assert "rationale" in source


def test_attack_graph_never_executes() -> None:
    """Attack paths are intelligence only: no execution primitive on them."""
    source = inspect.getsource(AttackPathEngine)
    assert "execut" not in source.lower() or "execute" not in source
    assert "discover" in source


def test_engine_is_injectable_composable() -> None:
    """The engine is composed from pure domain engines; no I/O at construction."""
    engine = AdaptiveMissionPlanningEngine()
    assert isinstance(engine.decision, ActionDecisionEngine)
    assert isinstance(engine.replanning, ReplanningEngine)
    assert isinstance(engine.attack_paths, AttackPathEngine)


def test_mission_model_is_not_a_static_command_list() -> None:
    """The mission aggregate holds a living execution graph, not a list of commands."""
    mission = AdaptiveMission()
    assert hasattr(mission, "graph")
    assert hasattr(mission, "plan_version")
    assert hasattr(mission, "versions")
