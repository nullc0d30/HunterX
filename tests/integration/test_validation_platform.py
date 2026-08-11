# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Integration tests: the safe validation engine wired through the platform."""

from __future__ import annotations

from hunterx.domain.entities.tidb.validation import (
    ValidationEvidence as TidbValidationEvidence,
)
from hunterx.domain.entities.tidb.validation import (
    ValidationExecution as TidbValidationExecution,
)
from hunterx.domain.entities.tidb.validation import (
    ValidationHistory as TidbValidationHistory,
)
from hunterx.domain.entities.tidb.validation import (
    ValidationPlan as TidbValidationPlan,
)
from hunterx.domain.entities.tidb.validation import (
    ValidationPolicyDecision as TidbValidationPolicyDecision,
)
from hunterx.domain.entities.tidb.validation import (
    ValidationToolUsage as TidbValidationToolUsage,
)
from hunterx.domain.entities.tidb.validation import (
    ValidationVerdict as TidbValidationVerdict,
)
from hunterx.domain.entities.tidb.validation import (
    VulnerabilityHypothesis as TidbVulnerabilityHypothesis,
)
from hunterx.domain.vulnerability_validation.enums import ValidationClass, VerdictResult
from hunterx.domain.vulnerability_validation.safety import SafetyPolicy
from hunterx.domain.vulnerability_validation.scope import ValidationScopePolicy
from hunterx.platform.assembler import build_platform

SCOPE = ValidationScopePolicy(targets=("app.example.com",))
SAFETY = SafetyPolicy()


class TestValidationPlatform:
    def test_platform_wires_validation_service(self) -> None:
        platform = build_platform()
        assert platform.vulnerability_validation_service is not None

    def test_full_validation_flow_persists_to_tidb(self) -> None:
        platform = build_platform()
        service = platform.vulnerability_validation_service
        hypothesis = service.create_hypothesis(
            mission_id="integration-1",
            target_id="app.example.com",
            asset_id="app.example.com",
            vulnerability_id="CVE-2024-1234",
            class_name=ValidationClass.KNOWN_VULNERABLE_SOFTWARE,
            expected_behavior="version in range",
            confidence=0.8,
        )
        plan = service.plan_validation(hypothesis)
        result = service.run_validation(
            hypothesis,
            plan=plan,
            scope_policy=SCOPE,
            safety_policy=SAFETY,
            probe_parameters={
                "observations": [
                    {"kind": "version", "value": "1.24.0", "confidence": 1.0, "metadata": {"expected": "1.24.0"}}
                ]
            },
        )
        assert result.verdict is not None
        assert result.verdict.result == VerdictResult.CONFIRMED

        stores = platform.tidb
        assert stores.repository_for(TidbVulnerabilityHypothesis).count() == 1
        assert stores.repository_for(TidbValidationPlan).count() == 1
        assert stores.repository_for(TidbValidationExecution).count() == 1
        assert stores.repository_for(TidbValidationEvidence).count() == 1
        assert stores.repository_for(TidbValidationVerdict).count() == 1
        assert stores.repository_for(TidbValidationHistory).count() >= 1
        assert stores.repository_for(TidbValidationPolicyDecision).count() >= 1
        assert stores.repository_for(TidbValidationToolUsage).count() >= 1

    def test_event_catalog_covers_validation_events(self) -> None:
        platform = build_platform()
        registry = platform.event_registry
        for event_type in (
            "vulnerability.hypothesis.created",
            "vulnerability.validation.planned",
            "vulnerability.validation.started",
            "vulnerability.validation.step.started",
            "vulnerability.validation.step.completed",
            "vulnerability.validation.blocked",
            "vulnerability.validation.failed",
            "vulnerability.evidence.created",
            "vulnerability.verdict.created",
            "vulnerability.confirmed",
            "vulnerability.false_positive",
            "vulnerability.inconclusive",
            "vulnerability.resolved",
            "vulnerability.reopened",
            "vulnerability.validation.completed",
        ):
            assert registry.has(event_type), event_type

    def test_knowledge_graph_updated(self) -> None:
        platform = build_platform()
        service = platform.vulnerability_validation_service
        hypothesis = service.create_hypothesis(
            mission_id="integration-2",
            target_id="app.example.com",
            asset_id="app.example.com",
            vulnerability_id="CVE-2024-1234",
            class_name=ValidationClass.KNOWN_VULNERABLE_SOFTWARE,
            confidence=0.8,
        )
        plan = service.plan_validation(hypothesis)
        service.run_validation(
            hypothesis, plan=plan, scope_policy=SCOPE, safety_policy=SAFETY,
            probe_parameters={"observations": [
                {"kind": "version", "value": "1.24.0", "confidence": 1.0, "metadata": {"expected": "1.24.0"}}
            ]},
        )
        graph = platform.knowledge_graph
        neighbors = graph.query_neighbors("app.example.com")
        assert any(item.get("type") == "has_hypothesis" for item in neighbors)

    def test_report_from_persisted_records(self) -> None:
        platform = build_platform()
        service = platform.vulnerability_validation_service
        hypothesis = service.create_hypothesis(
            mission_id="integration-3",
            target_id="app.example.com",
            asset_id="app.example.com",
            vulnerability_id="CVE-2024-1234",
            class_name=ValidationClass.KNOWN_VULNERABLE_SOFTWARE,
            confidence=0.8,
        )
        plan = service.plan_validation(hypothesis)
        service.run_validation(
            hypothesis, plan=plan, scope_policy=SCOPE, safety_policy=SAFETY,
            probe_parameters={"observations": [
                {"kind": "version", "value": "1.24.0", "confidence": 1.0, "metadata": {"expected": "1.24.0"}}
            ]},
        )
        report = service.build_report(mission_id="integration-3", target_id="app.example.com")
        assert report["summary"]["confirmed"] == 1
        assert report["reproducibility"]["deterministic"] is True
        assert report["confidence_summary"]["mean"] > 0.0

    def test_scope_blocked_through_platform(self) -> None:
        platform = build_platform()
        service = platform.vulnerability_validation_service
        hypothesis = service.create_hypothesis(
            mission_id="integration-4",
            target_id="out-of-scope.example.com",
            asset_id="out-of-scope.example.com",
            vulnerability_id="CVE-2024-1234",
            class_name=ValidationClass.KNOWN_VULNERABLE_SOFTWARE,
        )
        plan = service.plan_validation(hypothesis)
        result = service.run_validation(
            hypothesis, plan=plan, scope_policy=SCOPE, safety_policy=SAFETY,
            probe_parameters={"observations": [
                {"kind": "version", "value": "1.24.0", "confidence": 1.0, "metadata": {"expected": "1.24.0"}}
            ]},
        )
        assert result.verdict.result == VerdictResult.SCOPE_BLOCKED
        assert platform.tidb.repository_for(TidbValidationPolicyDecision).count() >= 1
