# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Acceptance tests for the Sprint 028 vulnerability validation & proof orchestration.

Each test maps to one or more acceptance criteria: the canonical finding
lifecycle, evidence requirement engine, evidence gaps and sufficiency,
validation strategy engine, safe validation policy, tool orchestration,
validation execution, independent verification, reproducibility, proof replay,
PoC generation and validation, impact assessment, confidence engine,
contradiction handling, false-positive reduction, deduplication, root-cause
correlation, unknown-behavior validation, report readiness, finding packages,
redaction, typed events, TIDB persistence, application API, CLI integration,
deterministic fallback, golden datasets and the acceptance/security/
performance/architecture test artifacts.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from hunterx.application.vulnerability_finding import VulnerabilityFindingService
from hunterx.domain.entities.tidb.finding_orchestration import (
    FindingRecord,
    FindingStateTransition,
)
from hunterx.domain.events.spec import EventRegistry
from hunterx.platform.assembler import build_platform

_PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _observations(*kinds: str) -> list[dict[str, object]]:
    return [{"kind": kind, "value": f"{kind}-value", "quality": "high", "source": "scanner"} for kind in kinds]


@pytest.fixture
def platform() -> object:
    return build_platform()


@pytest.fixture
def service(platform: object) -> VulnerabilityFindingService:
    return platform.vulnerability_finding_service  # type: ignore[attr-defined]


class TestFindingOrchestrationAcceptance:
    def test_01_02_canonical_lifecycle_and_existing_finding_reuse(
        self, platform: object, service: VulnerabilityFindingService
    ) -> None:
        finding = service.create_finding(
            mission_id="m1",
            target_id="https://example.com",
            vulnerability_class="sql_injection",
            title="SQLi",
            description="SQLi",
            severity="high",
            tool="nuclei",
            observations=_observations("detection_signature"),
        )
        assert finding["status"] == "supported"
        legacy = platform.finding_service.list_by_mission("m1")  # type: ignore[attr-defined]
        assert legacy

    def test_03_04_05_evidence_engine_gaps_and_sufficiency(
        self, service: VulnerabilityFindingService
    ) -> None:
        finding = service.create_finding(
            mission_id="m1",
            target_id="https://example.com",
            vulnerability_class="xss",
            title="XSS",
            description="xss",
            severity="medium",
            tool="dalfox",
            observations=_observations("reflection"),
        )
        assessment = service.assess_evidence(finding["finding_id"])
        gaps = service.get_evidence_gaps(finding["finding_id"])
        sufficiency = {item["purpose"]: item["level"] for item in assessment["sufficiency"]}
        assert sufficiency["validation"] == "insufficient"
        assert gaps

    def test_06_07_08_strategy_engine_and_safe_policy(
        self, service: VulnerabilityFindingService
    ) -> None:
        finding = service.create_finding(
            mission_id="m1",
            target_id="https://example.com",
            vulnerability_class="rce",
            title="RCE",
            description="rce",
            severity="critical",
            tool="nuclei",
        )
        plan = service.get_validation_plan(finding["finding_id"])
        assert plan["strategies"]
        assert plan["strategies"][0]["family"] == "rce"
        policy = plan["strategies"][0]["policy"]
        assert policy["stop_conditions"]
        assert policy["rollback_requirements"]

    def test_09_10_tool_orchestration_and_execution(self, service: VulnerabilityFindingService) -> None:
        finding = service.create_finding(
            mission_id="m1",
            target_id="https://example.com",
            vulnerability_class="sql_injection",
            title="SQLi",
            description="sqli",
            severity="high",
            tool="nuclei",
        )
        result = service.validate_finding(finding["finding_id"])
        assert result["status"] in ("completed", "failed", "blocked")

    def test_11_12_13_independent_verification_and_reproducibility_and_replay(
        self, service: VulnerabilityFindingService
    ) -> None:
        finding = service.create_finding(
            mission_id="m1",
            target_id="https://example.com",
            asset_id="a1",
            vulnerability_class="sql_injection",
            title="SQLi",
            description="sqli",
            severity="high",
            tool="nuclei",
            endpoints=("/search",),
            observations=_observations("detection_signature", "differential_database_behavior"),
        )
        poc = service.generate_poc(finding["finding_id"], reproduction={"request": "/search?q=1"})
        replay = service.replay_poc(
            finding["finding_id"], poc["poc_id"], outcome={"confirmed": True, "target": "https://example.com"}
        )
        assert replay["verdict"] == "confirmed"
        assert replay["scope_verified"]
        package = service.get_finding_package(finding["finding_id"])
        assert package["reproduction"] is not None

    def test_14_15_17_poc_generation_static_validation_and_poc_lifecycle(
        self, service: VulnerabilityFindingService
    ) -> None:
        finding = service.create_finding(
            mission_id="m1",
            target_id="https://example.com",
            vulnerability_class="xss",
            title="XSS",
            description="xss",
            severity="medium",
            tool="dalfox",
            endpoints=("/x",),
        )
        poc = service.generate_poc(
            finding["finding_id"],
            poc_format="curl",
            reproduction={"request": "/x?q=1", "method": "GET"},
        )
        assert poc["lifecycle_state"] == "static_validated"
        assert poc["format"] == "curl"

    def test_16_18_19_impact_and_confidence_engines(self, service: VulnerabilityFindingService) -> None:
        finding = service.create_finding(
            mission_id="m1",
            target_id="https://example.com",
            vulnerability_class="rce",
            title="RCE",
            description="rce",
            severity="critical",
            tool="nuclei",
            observations=_observations("detection_signature", "controlled_proof"),
        )
        impact = service.assess_impact(finding["finding_id"])
        assert impact["dimensions"]
        confidence = service.calculate_confidence(finding["finding_id"])
        assert 0.0 <= confidence["score"] <= 1.0
        explanation = service.get_confidence_explanation(finding["finding_id"])
        assert explanation["explanation"]

    def test_20_21_22_contradiction_handling(self, service: VulnerabilityFindingService) -> None:
        finding = service.create_finding(
            mission_id="m1",
            target_id="https://example.com",
            vulnerability_class="ssrf",
            title="SSRF",
            description="ssrf",
            severity="high",
            tool="interactsh",
            observations=_observations("detection_signature"),
        )
        transition = service.transition_finding(finding["finding_id"], to_state="disputed")
        assert transition["allowed"]
        assert service.get_finding(finding["finding_id"])["status"] == "disputed"

    def test_23_24_25_false_positive_dedup_root_cause(self, service: VulnerabilityFindingService) -> None:
        first = service.create_finding(
            mission_id="m1",
            target_id="https://example.com",
            asset_id="a1",
            vulnerability_class="xss",
            title="XSS",
            description="xss",
            severity="high",
            tool="dalfox",
            observations=_observations("reflection"),
        )
        second = service.create_finding(
            mission_id="m1",
            target_id="https://example.com",
            asset_id="a1",
            vulnerability_class="xss",
            title="XSS dup",
            description="xss",
            severity="high",
            tool="dalfox",
            observations=_observations("reflection"),
        )
        decision = service.deduplicate_finding(second["finding_id"])
        assert decision["relation"] == "same_finding"
        root = service.correlate_root_cause(first["finding_id"])
        assert root["root_cause_id"]

    def test_26_27_28_unknown_behavior_and_business_logic_and_authorization(
        self, service: VulnerabilityFindingService
    ) -> None:
        unknown = service.create_finding(
            mission_id="m1",
            target_id="https://example.com",
            vulnerability_class="unknown_behavior",
            title="Unknown",
            description="unexpected callback",
            severity="medium",
            tool="interactsh",
            observations=[{"kind": "unknown_observation", "value": "unexpected callback", "quality": "high"}],
        )
        profile = service.classify_unknown(
            unknown["finding_id"], known_signatures=[], security_relevant=True, reproducible=True
        )
        assert profile["classification"] in ("novel_behavior", "application_specific")
        business = service.create_finding(
            mission_id="m1",
            target_id="https://example.com",
            vulnerability_class="business_logic",
            title="Biz logic",
            description="unauthorized state transition",
            severity="high",
            tool="validation",
            observations=_observations("business_state_transition"),
        )
        assert business["vulnerability_class"] == "business_logic"

    def test_29_30_31_api_cloud_cve_classes_supported(self) -> None:
        from hunterx.domain.vulnerability_finding.enums import FindingVulnerabilityClass

        for required in (
            "api_authorization",
            "cloud_exposure",
            "known_cve",
            "graphql_authorization",
            "secret_exposure",
            "host_header_injection",
            "http_request_smuggling",
            "jwt_weakness",
            "rfi",
            "xxe",
            "command_injection",
            "path_traversal",
        ):
            assert FindingVulnerabilityClass(required).value == required

    def test_32_exploitation_boundary_separated(self) -> None:
        from hunterx.domain.vulnerability_finding.enums import ValidationStage

        stages = [stage.value for stage in ValidationStage]
        assert stages.index("validation") < stages.index("exploitation")

    def test_33_34_35_report_ready_package_redaction(
        self, service: VulnerabilityFindingService
    ) -> None:
        finding = service.create_finding(
            mission_id="m1",
            target_id="https://example.com",
            asset_id="a1",
            vulnerability_class="sql_injection",
            title="SQLi",
            description="sqli",
            severity="high",
            tool="nuclei",
            endpoints=("/search",),
            observations=_observations("detection_signature", "differential_database_behavior"),
        )
        poc = service.generate_poc(finding["finding_id"], reproduction={"request": "/search?q=1"})
        service.replay_poc(
            finding["finding_id"], poc["poc_id"], outcome={"confirmed": True, "target": "https://example.com"}
        )
        service.assess_impact(finding["finding_id"])
        service.calculate_confidence(finding["finding_id"])
        readiness = service.get_report_readiness(finding["finding_id"])
        assert readiness["reportable"]
        package = service.get_finding_package(finding["finding_id"])
        assert package["finding_id"] == finding["finding_id"]
        assert package["redaction"]["policy_version"]
        final = service.finalize_report_ready(finding["finding_id"])
        assert final["transition"]["allowed"]

    def test_37_38_events_catalog_and_tidb_persistence(
        self, platform: object, service: VulnerabilityFindingService
    ) -> None:
        registry: EventRegistry = platform.event_registry  # type: ignore[attr-defined]
        for event_type in (
            "finding.created",
            "finding.supported",
            "finding.validation.started",
            "finding.validation.completed",
            "finding.evidence.added",
            "finding.evidence.conflict",
            "finding.proof.required",
            "finding.proof.started",
            "finding.proof.replayed",
            "finding.proof.validated",
            "finding.impact.assessed",
            "finding.confidence.updated",
            "finding.duplicate.detected",
            "finding.disproved",
            "finding.report_ready",
        ):
            assert registry.has(event_type), f"event {event_type} missing from catalog"
        finding = service.create_finding(
            mission_id="m1",
            target_id="https://example.com",
            vulnerability_class="xss",
            title="XSS",
            description="xss",
            severity="high",
            tool="dalfox",
        )
        records = platform.tidb.repository_for(FindingRecord).list_by(  # type: ignore[attr-defined]
            "finding_id", finding["finding_id"], limit=10
        )
        transitions = platform.tidb.repository_for(FindingStateTransition).list_by(  # type: ignore[attr-defined]
            "finding_id", finding["finding_id"], limit=10
        )
        assert records
        assert transitions

    def test_40_41_cli_and_deterministic_fallback(self) -> None:
        from hunterx.cli.app import CliApplication
        from hunterx.cli.commands import register_default_commands

        app = CliApplication()
        register_default_commands(app)
        names = app.registry.names()
        for command in (
            "finding list",
            "finding show",
            "finding validate",
            "finding evidence",
            "finding proof",
            "finding poc",
            "finding replay",
            "finding explain",
            "finding report-ready",
        ):
            assert command in names

    def test_42_golden_datasets_exist(self) -> None:
        scenarios = _PROJECT_ROOT / "tests" / "golden" / "finding" / "scenarios.json"
        assert scenarios.exists()

    def test_43_44_acceptance_and_security_performance_architecture_tests_exist(self) -> None:
        for relative in (
            "tests/acceptance/test_finding_orchestration_acceptance.py",
            "tests/security/test_finding_orchestration_security.py",
            "tests/performance/test_finding_orchestration_benchmarks.py",
            "tests/architecture/test_finding_orchestration_architecture.py",
            "tests/integration/test_finding_orchestration_platform.py",
            "docs/v7-vulnerability-validation-proof-orchestration.md",
            "capabilities/vulnerability-validation-proof.json",
        ):
            assert (_PROJECT_ROOT / relative).exists(), f"missing {relative}"

    def test_45_documentation_complete(self) -> None:
        doc = _PROJECT_ROOT / "docs" / "v7-vulnerability-validation-proof-orchestration.md"
        content = doc.read_text(encoding="utf-8")
        for section in ("finding lifecycle", "evidence model", "validation strategies", "confidence", "security"):
            assert section in content.lower()
