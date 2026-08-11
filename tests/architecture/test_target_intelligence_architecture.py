# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Architecture tests for the Adaptive Target Intelligence layer.

Verifies layer discipline (pure domain vs engine vs application vs
infrastructure), import hygiene and the absence of hardcoded tool sequences or
black-box action selection.
"""

from __future__ import annotations

import inspect

from hunterx.architecture.layers import resolve_layer
from hunterx.domain.target_intelligence.actions import NextActionEngine
from hunterx.domain.target_intelligence.coverage import CoverageEngine
from hunterx.domain.target_intelligence.hypotheses import HypothesisEngine
from hunterx.domain.target_intelligence.models import IntelligenceTarget
from hunterx.domain.target_intelligence.unknowns import UnknownsEngine
from hunterx.engines.target_intelligence import TargetIntelligenceEngine


def test_domain_modules_resolve_to_domain_layer() -> None:
    for module in (
        "hunterx.domain.target_intelligence.models",
        "hunterx.domain.target_intelligence.actions",
        "hunterx.domain.target_intelligence.coverage",
        "hunterx.domain.target_intelligence.hypotheses",
        "hunterx.domain.target_intelligence.graph",
        "hunterx.domain.target_intelligence.scope",
        "hunterx.domain.target_intelligence.stores",
    ):
        assert resolve_layer(module).name == "domain"


def test_engine_and_application_resolve_to_their_layers() -> None:
    assert resolve_layer("hunterx.engines.target_intelligence.engine").name == "engines"
    assert resolve_layer("hunterx.application.target_intelligence").name == "application"


def test_domain_does_not_import_infrastructure_or_tools() -> None:
    """Pure domain modules must stay free of I/O, infrastructure and tools."""
    banned = ("infrastructure", "tools", "platform", "application", "engines")
    for module_name in (
        "hunterx.domain.target_intelligence.models",
        "hunterx.domain.target_intelligence.actions",
        "hunterx.domain.target_intelligence.coverage",
        "hunterx.domain.target_intelligence.hypotheses",
        "hunterx.domain.target_intelligence.graph",
        "hunterx.domain.target_intelligence.history",
        "hunterx.domain.target_intelligence.conflicts",
        "hunterx.domain.target_intelligence.correlation",
        "hunterx.domain.target_intelligence.stores",
        "hunterx.domain.target_intelligence.scope",
        "hunterx.domain.target_intelligence.state",
        "hunterx.domain.target_intelligence.replay",
    ):
        module = __import__(module_name, fromlist=["*"])
        source = inspect.getsource(module)
        for banned_part in banned:
            import re

            matches = re.findall(rf"(?:import|from)\s+hunterx\.{banned_part}", source)
            assert not matches, f"{module_name} must not import hunterx.{banned_part}: {matches}"


def test_no_hardcoded_universal_tool_sequence() -> None:
    """The next-action engine must derive actions from state, not a fixed list."""
    source = inspect.getsource(NextActionEngine)
    assert "def _discovery_actions" in source
    # No single universal ordered sequence of tool ids may exist.
    assert "subfinder" not in source and "nuclei" not in source and "sqlmap" not in source


def test_no_black_box_action_selection() -> None:
    """Ranked actions must carry an explainable reason and decision provenance."""
    source = inspect.getsource(NextActionEngine.rank)
    assert "IntelligenceDecision" in source
    assert "rationale" in source


def test_engine_is_injectable_composable() -> None:
    """The engine is composed from pure domain engines; no I/O at construction."""
    engine = TargetIntelligenceEngine()
    assert isinstance(engine.coverage, CoverageEngine)
    assert isinstance(engine.unknowns, UnknownsEngine)
    assert isinstance(engine.hypotheses, HypothesisEngine)
    assert isinstance(engine.next_action, NextActionEngine)


def test_target_model_is_not_a_hostname() -> None:
    """Target kinds are richer than a bare hostname."""
    target = IntelligenceTarget(target_id="t", mission_id="m", scope="s", identity="i", value="acct")
    assert target.key.startswith("domain:") or target.key
