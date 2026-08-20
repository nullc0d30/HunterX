# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Architecture tests for the adaptive attack subsystem.

Verifies the Phase 2 discipline: pure domain (no infrastructure/tools/engines),
no hardcoded tool chains, bounded controls (no runaway concurrency/retries),
explainable state transitions, and target-agnosticism (no Juice Shop or
target-specific objects).
"""

from __future__ import annotations

import inspect

from hunterx.architecture.layers import resolve_layer
from hunterx.domain.adaptive_attack.control import AdaptiveRateController, AttackControlConfig
from hunterx.domain.adaptive_attack.feedback import FeedbackClassifier, FeedbackMonitor
from hunterx.domain.adaptive_attack.probe import AttackProbePlan, profile_for
from hunterx.domain.adaptive_attack.vector import VectorSelector
from hunterx.domain.adaptive_attack.workflow import AttackWorkflow

_DOMAIN_MODULES = (
    "hunterx.domain.adaptive_attack",
    "hunterx.domain.adaptive_attack.enums",
    "hunterx.domain.adaptive_attack.feedback",
    "hunterx.domain.adaptive_attack.control",
    "hunterx.domain.adaptive_attack.vector",
    "hunterx.domain.adaptive_attack.probe",
    "hunterx.domain.adaptive_attack.workflow",
)


def test_domain_modules_resolve_to_domain_layer() -> None:
    for module in _DOMAIN_MODULES:
        assert resolve_layer(module).name == "domain", module


def test_application_module_resolves_to_application_layer() -> None:
    assert resolve_layer("hunterx.application.adaptive_attack").name == "application"


def test_domain_does_not_import_infrastructure_or_tools() -> None:
    banned = ("infrastructure", "tools", "platform", "application", "engines")
    for module_name in _DOMAIN_MODULES:
        module = __import__(module_name, fromlist=["*"])
        source = inspect.getsource(module)
        matches = [part for part in banned if f"hunterx.{part}" in source]
        assert not matches, f"{module_name} must not import hunterx.{banned}: {matches}"


def test_no_hardcoded_universal_tool_pipeline() -> None:
    """The adaptive engine must not hardcode a tool chain."""
    for component in (AdaptiveRateController, FeedbackMonitor, FeedbackClassifier, VectorSelector, AttackProbePlan, AttackWorkflow):
        source = inspect.getsource(component).lower()
        for tool in ("subfinder", "nuclei", "sqlmap", "katana", "arjun", "nmap", "httpx"):
            assert tool not in source, f"{component.__name__} hardcodes {tool}"


def test_controls_are_bounded() -> None:
    """Every intensity control must be config-capped — never runaway."""
    source = inspect.getsource(AttackControlConfig)
    for knob in ("max_concurrency", "max_pacing_s", "max_backoff_s", "max_retries"):
        assert knob in source, f"AttackControlConfig missing bound {knob}"
    # No unbounded loops or infinite recursion in the controller.
    controller_source = inspect.getsource(AdaptiveRateController)
    assert "while True" not in controller_source
    assert "for _ in range" not in controller_source


def test_probe_profiles_are_bounded() -> None:
    """Aggression profiles carry hard payload/mutation ceilings."""
    for level in ("LOW", "MEDIUM", "HIGH", "MAXIMUM"):
        from hunterx.domain.adaptive_attack.enums import AggressionLevel

        profile = profile_for(AggressionLevel[level])
        assert 0 < profile.payload_budget <= 50
        assert 0 < profile.mutation_depth <= 4


def test_state_transitions_are_explainable() -> None:
    """Transitions must record from/to/signal provenance."""
    source = inspect.getsource(AdaptiveRateController)
    assert "from" in source
    assert "to" in source
    assert "signal" in source
    assert "transition_history" in source


def test_feedback_keeps_source_and_signal() -> None:
    """Feedback samples must carry a classified signal and provenance."""
    source = inspect.getsource(FeedbackMonitor)
    assert "observe" in source
    assert "last_signal" in source
    assert "defensive_ratio" in source


def test_target_agnostic_vocabulary() -> None:
    """No target-specific objects in the adaptive engine."""
    import re

    combined = ""
    for module_name in _DOMAIN_MODULES:
        module = __import__(module_name, fromlist=["*"])
        combined += inspect.getsource(module).lower()
    for forbidden in ("juice", "juice-shop", "checkout", "basket"):
        assert not re.search(rf"\b{forbidden}\b", combined), f"adaptive engine mentions '{forbidden}'"


def test_vector_selector_is_extensible() -> None:
    """Vector selection must support registering new kind mappings."""
    source = inspect.getsource(VectorSelector)
    assert "register" in source
    assert "extra_mapping" in source
