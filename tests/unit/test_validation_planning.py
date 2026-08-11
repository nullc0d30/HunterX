# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for validation planning, tool selection and normalization."""

from __future__ import annotations

from hunterx.domain.vulnerability_validation.enums import (
    SafetyClass,
    ValidationClass,
    ValidationStrategy,
    VulnerabilityState,
)
from hunterx.domain.vulnerability_validation.models import VulnerabilityHypothesis
from hunterx.domain.vulnerability_validation.normalization import ValidationNormalizer
from hunterx.domain.vulnerability_validation.planning import ValidationPlanner
from hunterx.domain.vulnerability_validation.tool_selection import (
    ToolSelectionPolicy,
    ValidationToolSelector,
)


class TestValidationPlanner:
    def test_plan_produces_safe_steps(self) -> None:
        hypothesis = VulnerabilityHypothesis(
            mission_id="m1",
            target_id="t1",
            asset_id="app.example.com",
            vulnerability_id="CVE-2024-1234",
            type=ValidationClass.KNOWN_VULNERABLE_SOFTWARE,
            state=VulnerabilityState.SUSPECTED,
        )
        planner = ValidationPlanner()
        assert planner.can_plan(hypothesis) is True
        plan = planner.plan(hypothesis)
        assert plan.hypothesis_id == hypothesis.hypothesis_id
        assert len(plan.steps) >= 1
        assert all(step.safety_class != SafetyClass.DESTRUCTIVE for step in plan.steps)

    def test_unknown_class_not_plannable(self) -> None:
        hypothesis = VulnerabilityHypothesis(
            vulnerability_id="CVE-1",
            type=ValidationClass.KNOWN_VULNERABLE_SOFTWARE,
            state=VulnerabilityState.CONFIRMED,
        )
        planner = ValidationPlanner()
        assert planner.can_plan(hypothesis) is False

    def test_strategy_capability_hint(self) -> None:
        planner = ValidationPlanner()
        assert planner.strategy_capability(ValidationStrategy.VERSION_VALIDATION) == "version-validation"


class TestToolSelector:
    def test_selects_registered_tool(self) -> None:
        selector = ValidationToolSelector(registered={"passive-probe", "version-probe", "error-behavior-probe"})
        selection = selector.select_tool(
            strategy=ValidationStrategy.VERSION_VALIDATION,
            policy=ToolSelectionPolicy(),
        )
        assert selection is not None
        assert selection.tool_id in {"passive-probe", "version-probe", "error-behavior-probe"}

    def test_no_registered_tool_returns_none(self) -> None:
        selector = ValidationToolSelector(registered=set())
        selection = selector.select_tool(
            strategy=ValidationStrategy.VERSION_VALIDATION,
            policy=ToolSelectionPolicy(),
        )
        assert selection is None

    def test_select_for_class(self) -> None:
        selector = ValidationToolSelector(registered={"passive-probe"})
        selection = selector.select_for_class(
            ValidationClass.CORS,
            policy=ToolSelectionPolicy(),
        )
        assert selection is not None
        assert selection.tool_id == "passive-probe"


class TestNormalizer:
    def test_normalizes_canonical_observations(self) -> None:
        normalizer = ValidationNormalizer()
        observations = normalizer.normalize_output(
            {"observations": [{"kind": "version", "value": "1.24.0", "confidence": 1.0}]},
            source="version-probe",
        )
        assert len(observations) == 1
        assert observations[0].kind.value == "version"
        assert observations[0].value == "1.24.0"

    def test_rejects_malformed_output(self) -> None:
        normalizer = ValidationNormalizer()
        assert normalizer.normalize_output(None) == []
        assert normalizer.normalize_output({"findings": "not-a-list"}) == []
        assert normalizer.normalize_output({"observations": [{"value": ""}]}) == []

    def test_unknown_kind_coerced_safely(self) -> None:
        normalizer = ValidationNormalizer()
        observations = normalizer.normalize_output(
            {"observations": [{"kind": "not-a-real-kind", "value": "x"}]}
        )
        # Unknown kinds are coerced defensively to EXTERNAL, never dropped unsafely.
        assert len(observations) == 1
        assert observations[0].kind.value == "external"

    def test_bounds_confidence(self) -> None:
        normalizer = ValidationNormalizer()
        observations = normalizer.normalize_output(
            {"observations": [{"kind": "header", "value": "x", "confidence": 5.0}]}
        )
        assert observations[0].confidence <= 1.0
