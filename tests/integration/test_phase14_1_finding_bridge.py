# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Phase 14.1 finding-bridge regression tests.

Proves the validated mission finding bridges into the finding orchestration
service and completes the full lifecycle (verification evidence → reproduction
→ PoC → replay → impact → confidence → REPORT_READY) for the
``security_misconfiguration`` class that the real DVWA runs validate — the
class vocabulary was completed so the already-registered capability
(``security-misconfiguration``) can be verified by the finding service.

Also proves: duplicate prevention (idempotent materialization per hypothesis),
lifecycle ordering, REPORT_READY remaining checklist-gated, and that the CLI
hunt path (platform-assembled ``MissionExecutionService``) carries the wired
finding service.
"""

from __future__ import annotations

import dataclasses

import pytest

from hunterx.application.mission_execution import MissionExecutionService
from hunterx.application.mission_orchestration import MissionOrchestrationService
from hunterx.application.vulnerability_finding import VulnerabilityFindingService
from hunterx.domain.adaptive_mission_planning.toolchain import ToolSelectionEngine
from hunterx.domain.mission_orchestration.enums import StopCondition
from hunterx.domain.mission_orchestration.orchestrator import MissionOrchestrator
from hunterx.domain.vulnerability_finding.enums import FindingVulnerabilityClass
from hunterx.engines.adaptive_mission_planning.engine import AdaptiveMissionPlanningEngine
from hunterx.engines.mission_orchestration import MissionOrchestrationEngine
from hunterx.infrastructure.db.graph import InMemoryKnowledgeGraph
from hunterx.infrastructure.db.sql.memory import InMemoryTidbRepositoryFactory
from hunterx.infrastructure.event_bus import InMemoryEventBus
from hunterx.infrastructure.memory import InMemoryFindingRepository
from hunterx.platform.assembler import build_platform
from hunterx.tools.intelligence.api import ToolIntelligenceAPI
from hunterx.tools.sdk.engine import ExecutionEngine
from tests.framework.fakes import FakeExecutionEngine
from tests.framework.vulnerable_app import VulnerableApp

_CANDIDATES: dict[str, tuple[str, ...]] = {
    "technology_fingerprint": ("whatweb",),
    "vulnerability_scanning": ("nuclei",),
    "dependency_check": ("osv-scanner",),
}

_STOP_CONDITIONS = (
    StopCondition.COVERAGE_TARGET_ACHIEVED,
    StopCondition.HIGH_VALUE_HYPOTHESES_RESOLVED,
    StopCondition.FINDINGS_VALIDATED,
    StopCondition.RESOURCE_BUDGET_EXHAUSTED,
)


@pytest.fixture(scope="module")
def app() -> VulnerableApp:
    with VulnerableApp() as server:
        yield server


def _service() -> VulnerabilityFindingService:
    return VulnerabilityFindingService(
        engine=ExecutionEngine(),
        stores=InMemoryTidbRepositoryFactory(),
        event_bus=InMemoryEventBus(),
        knowledge_graph=InMemoryKnowledgeGraph(),
        tip=ToolIntelligenceAPI(),
        findings=InMemoryFindingRepository(),
    )


def _create_misconfig(service: VulnerabilityFindingService, app: VulnerableApp, *, safe: bool = False) -> dict:
    path = "/safe/headers" if safe else "/vuln/headers"
    endpoint = app.base_url + path
    return service.create_finding(
        mission_id="m-bridge",
        target_id=app.base_url,
        asset_id="app",
        asset="vulnerable-app",
        vulnerability_class="security_misconfiguration",
        title=f"missing security headers on {path}",
        description=f"required security headers are absent on {path}",
        severity="medium",
        tool="hunterx-capability",
        endpoints=(endpoint,),
        parameters=(),
        observations=[
            {
                "kind": "detection_signature",
                "value": "candidate surfaced from discovered surface",
                "quality": "medium",
                "source": "discovery",
            }
        ],
    )


class TestSecurityMisconfigurationLifecycle:
    def test_full_lifecycle_to_report_ready(self, app: VulnerableApp) -> None:
        service = _service()
        finding = _create_misconfig(service, app)
        assert finding["status"] == "supported"
        assert finding["vulnerability_class"] == "security_misconfiguration"
        finding_id = finding["finding_id"]

        # Lifecycle ordering: verify → impact → poc → replay → confidence → finalize.
        verify = service.verify_with_probe(finding_id)
        assert verify["status"] == "validated", verify
        assert service.get_finding(finding_id)["status"] == "validated"
        package = service.get_finding_package(finding_id)
        kinds = {item["kind"] for item in package["evidence"]}
        assert "behavioral_differential" in kinds, kinds

        pkg = service.generate_reproduction_and_poc(finding_id)
        assert pkg["reproduction"]
        assert set(pkg["pocs"]) >= {"http_request", "curl"}

        replay = service.replay_probe(finding_id)
        assert replay["status"] == "reproduced", replay
        assert replay["replay"]["verdict"] == "confirmed"
        assert service.get_finding(finding_id)["status"] == "proved"
        package = service.get_finding_package(finding_id)
        kinds = {item["kind"] for item in package["evidence"]}
        assert "replay" in kinds, kinds

        service.assess_impact(finding_id)
        service.calculate_confidence(finding_id)
        ready = service.finalize_report_ready(finding_id)
        assert ready["transition"]["allowed"] is True, ready
        assert service.get_finding(finding_id)["status"] == "report_ready"
        readiness = service.get_report_readiness(finding_id)
        assert readiness["complete"] is True
        package = service.get_finding_package(finding_id)
        assert package["finding_state"] == "report_ready"
        assert package["reproduction"] is not None
        assert package["pocs"]
        assert package["impact"] is not None
        assert package["confidence"] is not None

    def test_lifecycle_event_ordering(self, app: VulnerableApp) -> None:
        bus = InMemoryEventBus()
        seen: list[str] = []
        bus.subscribe("finding.*", lambda event: seen.append(event.event_type))
        service = VulnerabilityFindingService(
            engine=ExecutionEngine(),
            stores=InMemoryTidbRepositoryFactory(),
            event_bus=bus,
            knowledge_graph=InMemoryKnowledgeGraph(),
            tip=ToolIntelligenceAPI(),
            findings=InMemoryFindingRepository(),
        )
        finding = _create_misconfig(service, app)
        finding_id = finding["finding_id"]
        service.verify_with_probe(finding_id)
        service.assess_impact(finding_id)
        service.generate_reproduction_and_poc(finding_id)
        service.replay_probe(finding_id)
        service.calculate_confidence(finding_id)
        service.finalize_report_ready(finding_id)
        assert "finding.created" in seen
        assert "finding.supported" in seen
        assert "finding.validation.completed" in seen
        assert "finding.proof.required" in seen
        assert "finding.report_ready" in seen
        created = seen.index("finding.created")
        supported = seen.index("finding.supported")
        validated = seen.index("finding.validation.completed")
        report_ready = seen.index("finding.report_ready")
        assert created < supported < validated < report_ready

    def test_safe_headers_do_not_validate(self, app: VulnerableApp) -> None:
        service = _service()
        finding = _create_misconfig(service, app, safe=True)
        verify = service.verify_with_probe(finding["finding_id"])
        assert verify["status"] in ("contradicted", "blocked"), verify
        state = service.get_finding(finding["finding_id"])["status"]
        assert state != "validated"
        ready = service.finalize_report_ready(finding["finding_id"])
        assert ready.get("reportable") is False
        assert service.get_finding(finding["finding_id"])["status"] != "report_ready"

    def test_report_ready_remains_gated_without_verification(self, app: VulnerableApp) -> None:
        service = _service()
        finding = _create_misconfig(service, app)
        ready = service.finalize_report_ready(finding["finding_id"])
        assert ready.get("reportable") is False, ready
        assert service.get_finding(finding["finding_id"])["status"] == "supported"


def _runner(
    app: VulnerableApp,
    payload: dict,
) -> tuple[MissionExecutionService, MissionOrchestrationService, VulnerabilityFindingService, str]:
    stores = InMemoryTidbRepositoryFactory()
    finding_service = VulnerabilityFindingService(
        engine=ExecutionEngine(),
        stores=stores,
        event_bus=InMemoryEventBus(),
        knowledge_graph=InMemoryKnowledgeGraph(),
        tip=ToolIntelligenceAPI(),
        findings=InMemoryFindingRepository(),
    )
    planning = AdaptiveMissionPlanningEngine(
        tool_selection_engine=ToolSelectionEngine(
            mission_type="bug-bounty",
            default_candidates=dict(_CANDIDATES),
        ),
    )
    orchestrator = MissionOrchestrator(planning=planning)
    orchestration = MissionOrchestrationService(
        engine=MissionOrchestrationEngine(orchestrator=orchestrator),
        stores=stores,
    )
    runner = MissionExecutionService(
        orchestration=orchestration,
        planning=planning,
        execution_engine=FakeExecutionEngine(outputs={"nuclei": payload}),
        finding_service=finding_service,
    )
    mission = orchestration.create_mission(objective="bug_bounty_assessment", target=app.base_url)
    mission.policy = dataclasses.replace(
        mission.policy,
        coverage_target=0.99,
        stop_conditions=_STOP_CONDITIONS,
    )
    orchestration.start(mission.mission_id)
    return runner, orchestration, finding_service, mission.mission_id


def _misconfig_payload(app: VulnerableApp) -> dict:
    return {
        "candidates": [
            {
                "vulnerability_class": "security-misconfiguration",
                "endpoint": f"{app.base_url}/vuln/headers",
                "parameter": "",
                "severity": "medium",
            }
        ],
        "count": 1,
    }


class TestMissionBridgeSecurityMisconfiguration:
    def test_validated_hypothesis_bridges_to_report_ready_finding(self, app: VulnerableApp) -> None:
        runner, orchestration, finding_service, mission_id = _runner(app, _misconfig_payload(app))
        runner.run(mission_id, max_cycles=16)

        findings = finding_service.list_findings(mission_id)
        assert findings, "the probe-verified hypothesis must create a finding record"
        report_ready = [f for f in findings if f.get("status") == "report_ready"]
        assert report_ready, f"no finding reached REPORT_READY: {findings}"
        record = report_ready[0]
        assert record["vulnerability_class"] == "security_misconfiguration"
        assert record["provenance"].startswith("hypothesis:")

        mission = orchestration.get(mission_id)
        validated = [h for h in mission.hypotheses if h.state.value == "validated"]
        assert validated, "the hypothesis must have been validated by the differential probe"

        readiness = finding_service.get_report_readiness(record["finding_id"])
        assert readiness["complete"] is True
        package = finding_service.get_finding_package(record["finding_id"])
        kinds = {item["kind"] for item in package["evidence"]}
        assert "behavioral_differential" in kinds, kinds
        assert "replay" in kinds, kinds
        assert package["reproduction"] is not None
        assert package["pocs"]
        assert package["impact"] is not None
        assert package["confidence"] is not None
        assert any(f.get("stage") == "report_ready" for f in mission.context.findings), "context sync must reflect REPORT_READY"

    def test_materialization_is_idempotent_no_duplicate_records(self, app: VulnerableApp) -> None:
        runner, orchestration, finding_service, mission_id = _runner(app, _misconfig_payload(app))
        runner.run(mission_id, max_cycles=16)
        mission = orchestration.get(mission_id)
        validated = [h for h in mission.hypotheses if h.state.value == "validated"]
        assert validated
        hypothesis = validated[0]
        records = [
            f
            for f in finding_service.list_findings(mission_id)
            if f.get("provenance") == f"hypothesis:{hypothesis.hypothesis_id}"
        ]
        assert len(records) == 1

        runner._materialize_validated_finding(mission_id, hypothesis)  # noqa: SLF001 - idempotency guard under test
        runner._materialize_validated_finding(mission_id, hypothesis)  # noqa: SLF001
        records = [
            f
            for f in finding_service.list_findings(mission_id)
            if f.get("provenance") == f"hypothesis:{hypothesis.hypothesis_id}"
        ]
        assert len(records) == 1, "a hypothesis must never produce duplicate finding records"

    def test_refuted_surface_materializes_nothing(self, app: VulnerableApp) -> None:
        payload = {
            "candidates": [
                {
                    "vulnerability_class": "security-misconfiguration",
                    "endpoint": f"{app.base_url}/safe/headers",
                    "parameter": "",
                    "severity": "medium",
                }
            ],
            "count": 1,
        }
        runner, orchestration, finding_service, mission_id = _runner(app, payload)
        runner.run(mission_id, max_cycles=16)
        assert finding_service.list_findings(mission_id) == [], "no valid finding means nothing materialized"
        mission = orchestration.get(mission_id)
        assert all(h.state.is_terminal for h in mission.hypotheses)


class TestCliBridgeWiring:
    def test_platform_wires_finding_service_into_cli_execution(self) -> None:
        platform = build_platform()
        assert platform.mission_execution_service._finding_service is platform.vulnerability_finding_service  # noqa: SLF001

    def test_security_misconfiguration_is_a_known_class(self) -> None:
        assert FindingVulnerabilityClass.SECURITY_MISCONFIGURATION.value == "security_misconfiguration"
