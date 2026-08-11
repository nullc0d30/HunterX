# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Component tests for the vulnerability validation service.

Exercises the full safe validation pipeline against in-memory stores and the
Tool Integration SDK: hypothesis → plan → scope/safety gates → probe →
normalize → evidence → verdict → persist → events → graph → report → diff.
"""

from __future__ import annotations

from hunterx.application.vulnerability_validation import VulnerabilityValidationService
from hunterx.domain.vulnerability_validation.enums import (
    ValidationClass,
    VerdictResult,
    VulnerabilityState,
)
from hunterx.domain.vulnerability_validation.history import HypothesisSnapshot
from hunterx.domain.vulnerability_validation.safety import SafetyPolicy
from hunterx.domain.vulnerability_validation.scope import ValidationScopePolicy
from hunterx.infrastructure.db.graph import InMemoryKnowledgeGraph
from hunterx.infrastructure.db.sql.memory import InMemoryTidbRepositoryFactory
from hunterx.infrastructure.event_bus import InMemoryEventBus
from hunterx.tools.safe_validation import register_validation_adapters
from hunterx.tools.sdk.engine import ExecutionEngine


def _build_service() -> VulnerabilityValidationService:
    engine = ExecutionEngine()
    register_validation_adapters(engine)
    for tool_id in ("passive-probe", "version-probe", "error-behavior-probe"):
        engine.install_hook(tool_id, lambda tool_id, version: "1.0.0")
        engine.install(tool_id, version="1.0.0")
    return VulnerabilityValidationService(
        engine=engine,
        stores=InMemoryTidbRepositoryFactory(),
        event_bus=InMemoryEventBus(),
        knowledge_graph=InMemoryKnowledgeGraph(),
    )


SCOPE = ValidationScopePolicy(targets=("app.example.com",))
SAFETY = SafetyPolicy()


def _version_observation(value: str, expected: str) -> dict:
    return {
        "observations": [
            {"kind": "version", "value": value, "confidence": 1.0, "metadata": {"expected": expected}}
        ]
    }


class TestValidationService:
    def test_hypothesis_create_persists_and_emits_event(self) -> None:
        service = _build_service()
        hypothesis = service.create_hypothesis(
            mission_id="m1",
            target_id="app.example.com",
            asset_id="app.example.com",
            vulnerability_id="CVE-2024-1234",
            class_name=ValidationClass.KNOWN_VULNERABLE_SOFTWARE,
            confidence=0.8,
        )
        assert hypothesis.state == VulnerabilityState.HYPOTHESIS
        assert service.hypotheses(mission_id="m1")[0].hypothesis_id == hypothesis.hypothesis_id

    def test_plan_validation_marks_state(self) -> None:
        service = _build_service()
        hypothesis = service.create_hypothesis(
            mission_id="m1", target_id="app.example.com", asset_id="app.example.com",
            vulnerability_id="CVE-2024-1234", class_name=ValidationClass.KNOWN_VULNERABLE_SOFTWARE,
        )
        plan = service.plan_validation(hypothesis)
        assert hypothesis.state == VulnerabilityState.VALIDATION_PLANNED
        assert plan.hypothesis_id == hypothesis.hypothesis_id
        assert plan.steps

    def test_confirmed_flow_persists_everything(self) -> None:
        service = _build_service()
        hypothesis = service.create_hypothesis(
            mission_id="m1", target_id="app.example.com", asset_id="app.example.com",
            vulnerability_id="CVE-2024-1234", class_name=ValidationClass.KNOWN_VULNERABLE_SOFTWARE,
            expected_behavior="version in range", confidence=0.8,
        )
        plan = service.plan_validation(hypothesis)
        result = service.run_validation(
            hypothesis, plan=plan, scope_policy=SCOPE, safety_policy=SAFETY,
            probe_parameters=_version_observation("1.24.0", "1.24.0"),
        )
        assert result.verdict is not None
        assert result.verdict.result == VerdictResult.CONFIRMED
        assert hypothesis.state == VulnerabilityState.CONFIRMED
        assert len(result.evidence) == 1
        assert result.report is not None
        assert result.report["summary"]["confirmed"] == 1
        assert service.evidence(hypothesis_id=hypothesis.hypothesis_id)
        assert service.verdicts(hypothesis_id=hypothesis.hypothesis_id)

    def test_scope_blocked_never_executes(self) -> None:
        service = _build_service()
        hypothesis = service.create_hypothesis(
            mission_id="m1", target_id="other.example.com", asset_id="other.example.com",
            vulnerability_id="CVE-2024-1234", class_name=ValidationClass.KNOWN_VULNERABLE_SOFTWARE,
        )
        plan = service.plan_validation(hypothesis)
        result = service.run_validation(
            hypothesis, plan=plan, scope_policy=SCOPE, safety_policy=SAFETY,
            probe_parameters=_version_observation("1.24.0", "1.24.0"),
        )
        assert result.blocked is True
        assert result.verdict is not None
        assert result.verdict.result == VerdictResult.SCOPE_BLOCKED
        assert not result.evidence

    def test_safety_blocked_on_forbidden_parameter(self) -> None:
        service = _build_service()
        hypothesis = service.create_hypothesis(
            mission_id="m1", target_id="app.example.com", asset_id="app.example.com",
            vulnerability_id="CVE-2024-0001", class_name=ValidationClass.COMMAND_INJECTION,
            confidence=0.9,
        )
        plan = service.plan_validation(hypothesis)
        result = service.run_validation(
            hypothesis, plan=plan, scope_policy=SCOPE, safety_policy=SAFETY,
            probe_parameters={"observations": [{"kind": "error_message", "value": "rm -rf"}], "command": "rm -rf /"},
        )
        assert result.verdict.result == VerdictResult.SAFETY_BLOCKED

    def test_tool_unavailable_is_blocked_not_crashed(self) -> None:
        engine = ExecutionEngine()  # no validation adapters registered
        service = VulnerabilityValidationService(
            engine=engine,
            stores=InMemoryTidbRepositoryFactory(),
        )
        hypothesis = service.create_hypothesis(
            mission_id="m1", target_id="app.example.com", asset_id="app.example.com",
            vulnerability_id="CVE-2024-1234", class_name=ValidationClass.KNOWN_VULNERABLE_SOFTWARE,
        )
        plan = service.plan_validation(hypothesis)
        result = service.run_validation(hypothesis, plan=plan, scope_policy=SCOPE, safety_policy=SAFETY)
        assert result.blocked is True
        assert result.verdict is not None

    def test_stop_condition_stops_execution(self) -> None:
        service = _build_service()
        hypothesis = service.create_hypothesis(
            mission_id="m1", target_id="app.example.com", asset_id="app.example.com",
            vulnerability_id="CVE-2024-1234", class_name=ValidationClass.KNOWN_VULNERABLE_SOFTWARE,
        )
        plan = service.plan_validation(hypothesis)
        result = service.run_validation(
            hypothesis, plan=plan, scope_policy=SCOPE, safety_policy=SAFETY,
            stop_check=lambda: "mission-cancelled",
            probe_parameters=_version_observation("1.24.0", "1.24.0"),
        )
        assert result.blocked is True
        assert "stop condition" in result.block_reason

    def test_rate_limit_blocks_second_run(self) -> None:
        service = _build_service()

        hypothesis = service.create_hypothesis(
            mission_id="m1", target_id="app.example.com", asset_id="app.example.com",
            vulnerability_id="CVE-2024-1234", class_name=ValidationClass.KNOWN_VULNERABLE_SOFTWARE,
        )
        plan = service.plan_validation(hypothesis, rate_limit=1.0)
        result = service.run_validation(
            hypothesis, plan=plan, scope_policy=SCOPE, safety_policy=SAFETY,
            probe_parameters=_version_observation("1.24.0", "1.24.0"),
        )
        assert result.verdict.result == VerdictResult.CONFIRMED
        # Re-run after reopening; the rate limit of 1 must refuse the action.
        service.reopen_hypothesis(hypothesis)
        result2 = service.run_validation(
            hypothesis, plan=plan, scope_policy=SCOPE, safety_policy=SAFETY,
            probe_parameters=_version_observation("1.24.0", "1.24.0"),
        )
        assert result2.blocked is True
        assert "rate limit" in result2.block_reason

    def test_false_positive_differential(self) -> None:
        service = _build_service()
        first = service.create_hypothesis(
            mission_id="m1", target_id="app.example.com", asset_id="app.example.com",
            vulnerability_id="CVE-2024-1234", class_name=ValidationClass.KNOWN_VULNERABLE_SOFTWARE,
            confidence=0.8,
        )
        plan1 = service.plan_validation(first)
        service.run_validation(
            first, plan=plan1, scope_policy=SCOPE, safety_policy=SAFETY,
            probe_parameters=_version_observation("1.24.0", "1.24.0"),
        )
        previous = [HypothesisSnapshot.from_hypothesis(first)]

        second = service.create_hypothesis(
            mission_id="m2", target_id="app.example.com", asset_id="app.example.com",
            vulnerability_id="CVE-2024-1234", class_name=ValidationClass.KNOWN_VULNERABLE_SOFTWARE,
            confidence=0.8,
        )
        plan2 = service.plan_validation(second)
        result = service.run_validation(
            second, plan=plan2, scope_policy=SCOPE, safety_policy=SAFETY,
            probe_parameters=_version_observation("1.25.0", "1.24.0"),
            previous=previous, previous_mission_id="m1",
        )
        assert result.verdict.result == VerdictResult.FALSE_POSITIVE
        assert result.differentials
        from hunterx.domain.vulnerability_validation.enums import DifferentialChange

        assert DifferentialChange.FIXED in result.differentials[0].changes
        assert result.report is not None
        assert result.report["risk_changes"]

    def test_resolve_and_reopen(self) -> None:
        service = _build_service()
        hypothesis = service.create_hypothesis(
            mission_id="m1", target_id="app.example.com", asset_id="app.example.com",
            vulnerability_id="CVE-2024-1234", class_name=ValidationClass.KNOWN_VULNERABLE_SOFTWARE,
        )
        service.resolve_hypothesis(hypothesis)
        assert hypothesis.state == VulnerabilityState.RESOLVED
        service.reopen_hypothesis(hypothesis)
        assert hypothesis.state == VulnerabilityState.REOPENED

    def test_cross_mission_contamination_prevented(self) -> None:
        service = _build_service()
        service.create_hypothesis(
            mission_id="alpha", target_id="app.example.com", asset_id="app.example.com",
            vulnerability_id="CVE-2024-1234", class_name=ValidationClass.KNOWN_VULNERABLE_SOFTWARE,
        )
        service.create_hypothesis(
            mission_id="beta", target_id="app.example.com", asset_id="app.example.com",
            vulnerability_id="CVE-2024-1234", class_name=ValidationClass.KNOWN_VULNERABLE_SOFTWARE,
        )
        alpha_only = service.hypotheses(mission_id="alpha")
        beta_only = service.hypotheses(mission_id="beta")
        assert len(alpha_only) == 1
        assert len(beta_only) == 1
        assert all(h.mission_id == "alpha" for h in alpha_only)
        assert all(h.mission_id == "beta" for h in beta_only)
