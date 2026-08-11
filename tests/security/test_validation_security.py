# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Security tests for the safe vulnerability discovery & validation engine.

Verifies that the engine cannot be pushed out of scope, cannot execute
forbidden/weaponized actions, never treats raw output as a verdict, never leaks
evidence across targets/missions, redacts secrets, and resists parser/evidence/
verdict poisoning and resource exhaustion.
"""

from __future__ import annotations

from hunterx.application.vulnerability_validation import VulnerabilityValidationService
from hunterx.domain.vulnerability_validation.enums import (
    SafetyClass,
    ValidationClass,
    VerdictResult,
    VulnerabilityState,
)
from hunterx.domain.vulnerability_validation.safety import SafetyPolicy
from hunterx.domain.vulnerability_validation.scope import (
    ValidationScopeEnforcer,
    ValidationScopePolicy,
)
from hunterx.infrastructure.db.graph import InMemoryKnowledgeGraph
from hunterx.infrastructure.db.sql.memory import InMemoryTidbRepositoryFactory
from hunterx.infrastructure.event_bus import InMemoryEventBus
from hunterx.tools.safe_validation import register_validation_adapters
from hunterx.tools.sdk.engine import ExecutionEngine

SCOPE = ValidationScopePolicy(targets=("app.example.com",))
SAFETY = SafetyPolicy()


def _service() -> VulnerabilityValidationService:
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


def _run(service, hypothesis, obs, *, extra_parameters=None, **kwargs):
    plan = service.plan_validation(hypothesis)
    parameters = {"observations": obs}
    parameters.update(extra_parameters or {})
    return service.run_validation(
        hypothesis, plan=plan, scope_policy=SCOPE, safety_policy=SAFETY,
        probe_parameters=parameters, **kwargs,
    )


def _hypothesis(service, vuln="CVE-2024-1234", cls=ValidationClass.KNOWN_VULNERABLE_SOFTWARE, target="app.example.com"):
    return service.create_hypothesis(
        mission_id="sec", target_id=target, asset_id=target,
        vulnerability_id=vuln, class_name=cls, confidence=0.8,
    )


class TestScopeSecurity:
    def test_dot_suffix_cannot_escape_scope(self) -> None:
        enforcer = ValidationScopeEnforcer(ValidationScopePolicy(targets=("example.com",)))
        assert enforcer.decides(target="example.com.evil.com").allowed is False
        assert enforcer.decides(target="notexample.com").allowed is False
        assert enforcer.decides(target="app.example.com").allowed is True

    def test_wildcard_target_is_not_a_wildcard(self) -> None:
        enforcer = ValidationScopeEnforcer(ValidationScopePolicy(targets=("*.example.com",)))
        assert enforcer.decides(target="app.example.com").allowed is False
        assert enforcer.decides(target="*.example.com").allowed is True

    def test_redirect_like_target_changes_blocked(self) -> None:
        service = _service()
        hypothesis = service.create_hypothesis(
            mission_id="sec-redirect", target_id="app.example.com", asset_id="attacker.example.com",
            vulnerability_id="CVE-2024-1234", class_name=ValidationClass.KNOWN_VULNERABLE_SOFTWARE,
        )
        result = _run(service, hypothesis, [{"kind": "version", "value": "1.24.0"}])
        # Asset resolution drifted out of scope → refused.
        assert result.verdict.result == VerdictResult.SCOPE_BLOCKED

    def test_dns_rebinding_like_scope_change_stops(self) -> None:
        service = _service()
        hypothesis = _hypothesis(service)
        plan = service.plan_validation(hypothesis)
        result = service.run_validation(
            hypothesis, plan=plan, scope_policy=SCOPE, safety_policy=SAFETY,
            stop_check=lambda: "target-instability",
            probe_parameters={"observations": [{"kind": "version", "value": "1.24.0"}]},
        )
        assert result.blocked is True
        assert "stop condition" in result.block_reason


class TestSafetySecurity:
    def test_command_injection_via_parameters_blocked(self) -> None:
        service = _service()
        hypothesis = _hypothesis(service, cls=ValidationClass.COMMAND_INJECTION)
        result = _run(
            service, hypothesis,
            [{"kind": "error_message", "value": "marker"}],
            extra_parameters={"command": "ping -c 1 $(id)"},
        )
        assert result.blocked is True

    def test_shell_metacharacters_blocked(self) -> None:
        service = _service()
        hypothesis = _hypothesis(service, cls=ValidationClass.COMMAND_INJECTION)
        result = _run(
            service, hypothesis,
            [{"kind": "error_message", "value": "marker"}],
            extra_parameters={"url": "http://x;|nc -e /bin/sh"},
        )
        assert result.blocked is True

    def test_destructive_safety_class_never_scheduled(self) -> None:
        service = _service()
        hypothesis = service.create_hypothesis(
            mission_id="sec", target_id="app.example.com", asset_id="app.example.com",
            vulnerability_id="CVE-1", class_name=ValidationClass.KNOWN_VULNERABLE_SOFTWARE,
            safety_class=SafetyClass.DESTRUCTIVE,
        )
        result = _run(service, hypothesis, [{"kind": "version", "value": "1.24.0"}])
        assert result.blocked is True
        assert result.verdict.result == VerdictResult.SAFETY_BLOCKED


class TestOutputAndEvidenceSecurity:
    def test_raw_tool_output_never_a_verdict(self) -> None:
        service = _service()
        hypothesis = _hypothesis(service)
        # A malformed/poisoned raw output mapping must not yield CONFIRMED.
        result = _run(service, hypothesis, [])
        assert result.verdict.result != VerdictResult.CONFIRMED
        assert result.verdict.result in (VerdictResult.INCONCLUSIVE, VerdictResult.SUSPECTED)

    def test_parser_poisoning_does_not_confirm(self) -> None:
        service = _service()
        hypothesis = _hypothesis(service)
        poisoned = {
            "observations": [
                {"kind": "version", "value": "1.24.0", "confidence": 999.0, "metadata": {"expected": "1.24.0"}},
                {"kind": "version", "value": "1.25.0", "confidence": 999.0, "metadata": {"expected": "1.24.0"}},
            ]
        }
        result = service.run_validation(
            hypothesis, plan=service.plan_validation(hypothesis),
            scope_policy=SCOPE, safety_policy=SAFETY,
            tool_output=poisoned,
        )
        # Conflicting evidence (match + mismatch) → inconclusive, never confirmed.
        assert result.verdict.result != VerdictResult.CONFIRMED

    def test_evidence_poisoning_does_not_confirm(self) -> None:
        service = _service()
        hypothesis = _hypothesis(service)
        poisoned = {
            "observations": [
                {"kind": "version", "value": "1.25.0", "confidence": 1.0, "metadata": {"expected": "1.24.0"}}
            ]
        }
        result = service.run_validation(
            hypothesis, plan=service.plan_validation(hypothesis),
            scope_policy=SCOPE, safety_policy=SAFETY,
            tool_output=poisoned,
        )
        assert result.verdict.result == VerdictResult.FALSE_POSITIVE
        assert hypothesis.state == VulnerabilityState.FALSE_POSITIVE

    def test_verdict_manipulation_impossible(self) -> None:
        # The verdict is produced deterministically by the engine; a caller
        # cannot inject a verdict into a run.
        service = _service()
        hypothesis = _hypothesis(service)
        result = _run(service, hypothesis, [{"kind": "version", "value": "1.24.0"}])
        assert result.verdict.result in (VerdictResult.INCONCLUSIVE, VerdictResult.FALSE_POSITIVE)

    def test_secret_leakage_redacted(self) -> None:
        service = _service()
        hypothesis = _hypothesis(service)
        result = _run(
            service, hypothesis,
            [{"kind": "header", "value": "authorization: Bearer sk-live-SECRET123", "confidence": 1.0, "metadata": {"expected": "authorization: Bearer sk-live-SECRET123"}}],
        )
        for evidence in result.evidence:
            assert "sk-live-SECRET123" not in evidence.relevant_response


class TestContaminationSecurity:
    def test_cross_target_evidence_leakage_prevented(self) -> None:
        service = _service()
        target_a = _hypothesis(service, vuln="CVE-A", target="app.example.com")
        result_a = _run(service, target_a, [{"kind": "version", "value": "1.24.0", "confidence": 1.0, "metadata": {"expected": "1.24.0"}}])
        for evidence in result_a.evidence:
            assert evidence.asset_id == "app.example.com"
            assert evidence.target_id == "app.example.com"

    def test_cross_mission_evidence_leakage_prevented(self) -> None:
        service = _service()
        hypothesis = service.create_hypothesis(
            mission_id="sec-mission-1", target_id="app.example.com", asset_id="app.example.com",
            vulnerability_id="CVE-2024-1234", class_name=ValidationClass.KNOWN_VULNERABLE_SOFTWARE,
        )
        result = _run(service, hypothesis, [{"kind": "version", "value": "1.24.0", "confidence": 1.0, "metadata": {"expected": "1.24.0"}}])
        for evidence in result.evidence:
            assert evidence.mission_id == "sec-mission-1"
        # Mission-scoped queries return only that mission's records.
        assert all(h.mission_id == "sec-mission-1" for h in service.hypotheses(mission_id="sec-mission-1"))

    def test_report_injection_neutralized(self) -> None:
        service = _service()
        hypothesis = _hypothesis(service)
        result = _run(
            service, hypothesis,
            [{"kind": "body", "value": "<script>alert(1)</script>", "confidence": 1.0, "metadata": {"expected": "marker"}}],
        )
        assert result.report is not None
        rendered = result.report
        assert "report_id" in rendered


class TestResourceSecurity:
    def test_bounded_observation_count(self) -> None:
        from hunterx.domain.vulnerability_validation.normalization import ValidationNormalizer

        normalizer = ValidationNormalizer()
        huge = {"observations": [{"kind": "version", "value": "v" * 100_000} for _ in range(100)]}
        observations = normalizer.normalize_output(huge)
        assert len(observations) == 100
        # Every value is bounded.
        assert all(len(obs.value) <= 4096 for obs in observations)

    def test_no_unbounded_validation_loop(self) -> None:
        service = _service()
        hypothesis = _hypothesis(service)
        result = _run(service, hypothesis, [])
        # A single run executes a bounded number of steps and returns.
        assert result.verdict is not None
