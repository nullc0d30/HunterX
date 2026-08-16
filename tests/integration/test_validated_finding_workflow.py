# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Validated-finding workflow regression tests.

Proves the complete pipeline: endpoint → parameter → hypothesis → targeted
probe → verification → vulnerability evidence → reproducible PoC → real replay
→ VALIDATED finding → REPORT_READY, against the loopback vulnerable fixture.
Also proves the honest negative: a contradicted probe never produces a
validated finding or vulnerability evidence.

Evidence semantics: a probe *observation* (MissionObservation type "probe")
proves a probe ran; only a FindingRecord evidence artifact
(BEHAVIORAL_DIFFERENTIAL / REPLAY) proves the vulnerability was verified.
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
from hunterx.engines.adaptive_mission_planning.engine import AdaptiveMissionPlanningEngine
from hunterx.engines.mission_orchestration import MissionOrchestrationEngine
from hunterx.infrastructure.db.graph import InMemoryKnowledgeGraph
from hunterx.infrastructure.db.sql.memory import InMemoryTidbRepositoryFactory
from hunterx.infrastructure.event_bus import InMemoryEventBus
from hunterx.infrastructure.memory import InMemoryFindingRepository
from hunterx.tools.intelligence.api import ToolIntelligenceAPI
from hunterx.tools.sdk.engine import ExecutionEngine
from tests.framework.fakes import FakeExecutionEngine
from tests.framework.vulnerable_app import VulnerableApp

_CANDIDATES: dict[str, tuple[str, ...]] = {
    "technology_fingerprint": ("whatweb",),
    "vulnerability_scanning": ("nuclei",),
    "dependency_check": ("osv-scanner",),
}


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


def _create_sqli(service: VulnerabilityFindingService, app: VulnerableApp, *, safe: bool = False) -> dict:
    path = "/safe/search" if safe else "/vuln/search"
    endpoint = app.base_url + path
    return service.create_finding(
        mission_id="m-gate",
        target_id=app.base_url,
        asset_id="app",
        asset="juice-shop",
        vulnerability_class="sql_injection",
        title="SQL injection in product search",
        description=f"SQL injection through the 'q' parameter on {path}",
        severity="high",
        tool="hunterx-capability",
        endpoints=(endpoint,),
        parameters=("q",),
        observations=[
            {
                "kind": "detection_signature",
                "value": "candidate surfaced from discovered surface",
                "quality": "medium",
                "source": "discovery",
            }
        ],
    )


class TestVerifiedFindingWorkflow:
    def test_full_workflow_to_report_ready(self, app: VulnerableApp) -> None:
        service = _service()
        finding = _create_sqli(service, app)
        assert finding["status"] == "supported"
        finding_id = finding["finding_id"]

        # 1. Targeted probe verification.
        verify = service.verify_with_probe(finding_id)
        assert verify["status"] == "validated", verify
        assert service.get_finding(finding_id)["status"] == "validated"
        # 2. Vulnerability evidence persisted (not merely a probe observation).
        package = service.get_finding_package(finding_id)
        kinds = {item["kind"] for item in package["evidence"]}
        assert kinds & {"behavioral_differential", "differential_database_behavior"}, kinds
        # 3. Reproduction + PoC.
        pkg = service.generate_reproduction_and_poc(finding_id)
        assert pkg["reproduction"]
        assert set(pkg["pocs"]) >= {"http_request", "curl"}
        # 4. Real replay re-executes the probe and reconfirms.
        replay = service.replay_probe(finding_id)
        assert replay["status"] == "reproduced", replay
        assert replay["replay"]["verdict"] == "confirmed"
        package = service.get_finding_package(finding_id)
        kinds = {item["kind"] for item in package["evidence"]}
        assert "replay" in kinds, kinds
        assert service.get_finding(finding_id)["status"] == "proved"
        # 5. Impact + confidence + report-ready.
        service.assess_impact(finding_id)
        service.calculate_confidence(finding_id)
        ready = service.finalize_report_ready(finding_id)
        assert ready["transition"]["allowed"] is True, ready
        assert service.get_finding(finding_id)["status"] == "report_ready"
        readiness = service.get_report_readiness(finding_id)
        assert readiness["complete"] is True
        package = service.get_finding_package(finding_id)
        assert package["finding_state"] == "report_ready"
        assert package["evidence"]
        assert package["reproduction"] is not None
        assert package["pocs"]
        assert package["impact"] is not None
        assert package["confidence"] is not None

    def test_contradicted_probe_never_validates(self, app: VulnerableApp) -> None:
        service = _service()
        finding = _create_sqli(service, app, safe=True)
        verify = service.verify_with_probe(finding["finding_id"])
        assert verify["status"] in ("contradicted", "blocked"), verify
        state = service.get_finding(finding["finding_id"])["status"]
        assert state != "validated"
        assert state in ("candidate", "supported", "validation_required", "validating")
        package = service.get_finding_package(finding["finding_id"])
        assert not any(item["kind"] == "behavioral_differential" and not item.get("contradictory") for item in package["evidence"])


class TestMissionBridge:
    def test_validated_hypothesis_bridges_to_report_ready_finding(self, app: VulnerableApp) -> None:
        """The mission pipeline's probe-verified hypothesis produces the full
        finding record (evidence → PoC → replay → report-ready)."""
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
        target = app.base_url
        payload = {
            "candidates": [
                {
                    "vulnerability_class": "sql-injection",
                    "endpoint": f"{target}/vuln/search",
                    "parameter": "q",
                    "severity": "medium",
                }
            ],
            "count": 1,
        }
        runner = MissionExecutionService(
            orchestration=orchestration,
            planning=planning,
            execution_engine=FakeExecutionEngine(outputs={"nuclei": payload}),
            finding_service=finding_service,
        )
        mission = orchestration.create_mission(objective="vulnerability_discovery", target=target)
        mission.policy = dataclasses.replace(
            mission.policy,
            coverage_target=0.99,
            stop_conditions=(StopCondition.COVERAGE_TARGET_ACHIEVED, StopCondition.RESOURCE_BUDGET_EXHAUSTED),
        )
        orchestration.start(mission.mission_id)
        runner.run(mission.mission_id, max_cycles=16)

        findings = finding_service.list_findings(mission.mission_id)
        assert findings, "the probe-verified hypothesis must create a finding record"
        validated = [
            f
            for f in findings
            if f.get("status") == "report_ready"
        ]
        assert validated, "at least one finding must reach REPORT_READY"
        finding_id = validated[0]["finding_id"]
        readiness = finding_service.get_report_readiness(finding_id)
        assert readiness["complete"] is True
        package = finding_service.get_finding_package(finding_id)
        kinds = {item["kind"] for item in package["evidence"]}
        assert kinds & {"behavioral_differential", "differential_database_behavior"}
        assert package["reproduction"] is not None
        assert package["pocs"]
        assert package["impact"] is not None
        assert package["confidence"] is not None
