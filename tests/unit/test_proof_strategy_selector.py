# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for the proof strategy selector."""

from __future__ import annotations

from hunterx.domain.vulnerability_proof.library import default_strategy_library
from hunterx.domain.vulnerability_proof.registry import ProofStrategyRegistry
from hunterx.domain.vulnerability_proof.selector import (
    TOOL_CAPABILITY_TO_SDK,
    ProofStrategySelector,
    ProofStrategySelectorInput,
)
from hunterx.domain.vulnerability_proof.strategy import ProofExecutability, ToolCapability
from hunterx.domain.vulnerability_validation.enums import ValidationClass


def _resolver(sdk_capability: str) -> tuple[str, ...]:
    return ("proof-replay",) if sdk_capability in ("proof-replay", "safe-validation") else ()


def _selector(registry: ProofStrategyRegistry | None = None) -> ProofStrategySelector:
    return ProofStrategySelector(
        registry or ProofStrategyRegistry(default_strategy_library()),
        capability_resolver=_resolver,
    )


class TestSelectorBasics:
    def test_selects_sql_injection_strategy(self) -> None:
        selector = _selector()
        selection = selector.select(
            ProofStrategySelectorInput(vulnerability_class=ValidationClass.SQL_INJECTION)
        )
        assert selection.strategy.strategy_id == "strategy.sql_injection"
        assert selection.executability == ProofExecutability.EXECUTABLE
        assert selection.selection_reasoning

    def test_evidence_aware_selection(self) -> None:
        selector = _selector()
        selection = selector.select(
            ProofStrategySelectorInput(
                vulnerability_class=ValidationClass.SQL_INJECTION,
                available_evidence=("behavioral_differential",),
            )
        )
        assert "behavioral_differential" in selection.evidence_covered
        assert selection.evidence_missing == ()

    def test_missing_evidence_reported(self) -> None:
        selector = _selector()
        selection = selector.select(
            ProofStrategySelectorInput(vulnerability_class=ValidationClass.SQL_INJECTION)
        )
        assert "behavioral_differential" in selection.evidence_missing

    def test_unknown_class_returns_not_executable(self) -> None:
        selector = _selector()
        selection = selector.select(
            ProofStrategySelectorInput(vulnerability_class=ValidationClass.INJECTION)
        )
        assert selection.executability == ProofExecutability.PROOF_NOT_EXECUTABLE
        assert "no active proof strategy" in selection.selection_reasoning[0]

    def test_lowest_risk_preferred_when_equivalent(self) -> None:
        selector = _selector()
        selection = selector.select(
            ProofStrategySelectorInput(vulnerability_class=ValidationClass.SSRF)
        )
        assert selection.strategy.safety_class.value == "controlled"
        assert selection.risk_level.value in ("low", "medium", "high")


class TestSelectorCapabilities:
    def test_missing_capability_blocks_executable_strategy(self) -> None:
        selector = ProofStrategySelector(
            ProofStrategyRegistry(default_strategy_library()),
            capability_resolver=lambda _sdk: (),
        )
        selection = selector.select(
            ProofStrategySelectorInput(vulnerability_class=ValidationClass.SQL_INJECTION)
        )
        assert selection.executability == ProofExecutability.PROOF_NOT_EXECUTABLE

    def test_cloud_capability_resolution(self) -> None:
        selector = _selector()
        selection = selector.select(
            ProofStrategySelectorInput(vulnerability_class=ValidationClass.CLOUD_EXPOSURE)
        )
        # CLOUD_METADATA + CONFIGURATION_QUERY cannot be satisfied by the test resolver.
        assert selection.executability == ProofExecutability.PROOF_NOT_EXECUTABLE

    def test_tool_capability_mapping_covers_all(self) -> None:
        for capability in ToolCapability:
            assert capability in TOOL_CAPABILITY_TO_SDK

    def test_scope_conflict_blocks_strategy(self) -> None:
        selector = _selector()
        selection = selector.select(
            ProofStrategySelectorInput(
                vulnerability_class=ValidationClass.SSRF,
                scope={"loopback-control-authorized": "no"},
            )
        )
        assert any("loopback-control-authorized" in blocked for blocked in selection.blocked_strategies)

    def test_missing_scope_prerequisite_reported(self) -> None:
        selector = _selector()
        selection = selector.select(
            ProofStrategySelectorInput(vulnerability_class=ValidationClass.SSRF)
        )
        assert any("scope:loopback-control-authorized" in item for item in selection.missing_prerequisites)


class TestSelectorPriority:
    def test_more_evidence_preferred(self) -> None:
        selector = _selector()
        without_evidence = selector.select(
            ProofStrategySelectorInput(vulnerability_class=ValidationClass.SQL_INJECTION)
        )
        with_evidence = selector.select(
            ProofStrategySelectorInput(
                vulnerability_class=ValidationClass.SQL_INJECTION,
                available_evidence=("behavioral_differential", "error_message"),
            )
        )
        assert with_evidence.strategy.strategy_id == without_evidence.strategy.strategy_id
        assert len(with_evidence.evidence_covered) > len(without_evidence.evidence_covered)

    def test_alternatives_are_ranked(self) -> None:
        selector = _selector()
        selection = selector.select(
            ProofStrategySelectorInput(vulnerability_class=ValidationClass.UNKNOWN_BEHAVIOR)
        )
        # UNKNOWN_BEHAVIOR has multiple strategies (unknown_behavior, unknown_class).
        assert selection.strategy.strategy_id in ("strategy.unknown_behavior", "strategy.unknown_class")
        assert selection.alternative_strategies
