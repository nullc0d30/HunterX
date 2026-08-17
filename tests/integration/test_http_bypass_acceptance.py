# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Phase 9 — HTTP access / response differential end-to-end acceptance.

Proves the generalized access-differential capability through the existing
architecture against controlled loopback fixtures:

endpoint discovered → access-control hypothesis → targeted mutation →
meaningful unauthorized access (proof marker exposed) → verification →
evidence → reproduction → PoC → replay → VALIDATED → PROVED → REPORT_READY.

Also proves the mandatory false-positive guards: status-code-only changes,
body-length-only changes and generic-error bodies NEVER validate.
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
    "endpoint_enumeration": ("httpx",),
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


def _create_access(
    service: VulnerabilityFindingService,
    app: VulnerableApp,
    *,
    path: str,
    marker: str,
    observed_status: int = 403,
) -> dict:
    endpoint = app.base_url + path
    return service.create_finding(
        mission_id="m-bypass",
        target_id=app.base_url,
        asset_id="app",
        asset="web",
        vulnerability_class="http_access_differential",
        title=f"HTTP access differential on {path}",
        description=f"restricted resource on {path} reachable via an alternate representation",
        severity="high",
        tool="hunterx-capability",
        endpoints=(endpoint,),
        parameters=(),
        observations=[
            {
                "kind": "detection_signature",
                "value": "candidate from discovered restricted surface",
                "quality": "medium",
                "source": "discovery",
            }
        ],
        scope={
            "observed_status": observed_status,
            "proof_marker": marker,
            "reproduction_request": endpoint + "/",
            "reproduction_method": "GET",
        },
    )


class TestAccessDifferentialFindingService:
    def test_403_authorization_bypass_to_report_ready(self, app: VulnerableApp) -> None:
        service = _service()
        finding = _create_access(service, app, path="/protected", marker="hxbypass_protected")
        finding_id = finding["finding_id"]
        assert finding["status"] == "supported"

        verify = service.verify_with_probe(finding_id)
        assert verify["status"] == "validated", verify
        assert service.get_finding(finding_id)["status"] == "validated"

        package = service.get_finding_package(finding_id)
        kinds = {item["kind"] for item in package["evidence"]}
        assert "authorization_state_comparison" in kinds, kinds
        differential = next(
            (item for item in package["evidence"] if item["kind"] == "authorization_state_comparison"),
            None,
        )
        assert differential is not None
        assert "hxbypass_protected" in str(differential["value"]), "the protected marker must be captured"

        pkg = service.generate_reproduction_and_poc(finding_id)
        assert pkg["reproduction"]
        assert set(pkg["pocs"]) >= {"http_request", "curl"}

        replay = service.replay_probe(finding_id)
        assert replay["status"] == "reproduced", replay
        assert replay["replay"]["verdict"] == "confirmed"
        assert service.get_finding(finding_id)["status"] == "proved"

        service.assess_impact(finding_id)
        service.calculate_confidence(finding_id)
        ready = service.finalize_report_ready(finding_id)
        assert ready["transition"]["allowed"] is True, ready
        assert service.get_finding(finding_id)["status"] == "report_ready"
        assert service.get_report_readiness(finding_id)["complete"] is True
        assert service.get_finding_package(finding_id)["impact"]["dimensions"]["authorization_boundary"] == "high"

    def test_404_hidden_resource_bypass_to_report_ready(self, app: VulnerableApp) -> None:
        service = _service()
        finding = _create_access(service, app, path="/hidden", marker="hxbypass_hidden", observed_status=404)
        finding_id = finding["finding_id"]

        verify = service.verify_with_probe(finding_id)
        assert verify["status"] == "validated", verify
        assert service.get_finding(finding_id)["status"] == "validated"

        service.generate_reproduction_and_poc(finding_id)
        replay = service.replay_probe(finding_id)
        assert replay["status"] == "reproduced", replay
        service.assess_impact(finding_id)
        service.calculate_confidence(finding_id)
        ready = service.finalize_report_ready(finding_id)
        assert ready["transition"]["allowed"] is True, ready
        assert service.get_finding(finding_id)["status"] == "report_ready"

    @pytest.mark.parametrize(
        "path,marker,status",
        [
            ("/safe/protected", "hxbypass_protected", 403),
            ("/statusbypass", "hxbypass_protected", 403),
            ("/lengthonly", "hxbypass_protected", 403),
            ("/error", "hxbypass_protected", 502),
            ("/safe/hidden", "hxbypass_hidden", 404),
        ],
    )
    def test_status_or_generic_only_changes_never_validate(
        self, app: VulnerableApp, path: str, marker: str, status: int
    ) -> None:
        service = _service()
        finding = _create_access(service, app, path=path, marker=marker, observed_status=status)
        verify = service.verify_with_probe(finding["finding_id"])
        assert verify["status"] in ("contradicted", "blocked"), verify
        state = service.get_finding(finding["finding_id"])["status"]
        assert state != "validated"
        assert state not in ("proved", "report_ready")


class TestAccessDifferentialMissionBridge:
    def test_discovered_restricted_surface_derives_bypass_to_report_ready(self, app: VulnerableApp) -> None:
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
        outputs = {
            "httpx": {
                "status_code": 403,
                "proof_marker": "hxbypass_protected",
                "technologies": [{"type": "technology", "asset": f"{target}/protected", "raw_name": f"{target}/protected"}],
            }
        }
        runner = MissionExecutionService(
            orchestration=orchestration,
            planning=planning,
            execution_engine=FakeExecutionEngine(outputs=outputs),
            finding_service=finding_service,
        )
        mission = orchestration.create_mission(objective="bug_bounty_assessment", target=target)
        mission.policy = dataclasses.replace(
            mission.policy,
            coverage_target=0.99,
            stop_conditions=(StopCondition.COVERAGE_TARGET_ACHIEVED, StopCondition.RESOURCE_BUDGET_EXHAUSTED),
        )
        orchestration.start(mission.mission_id)
        runner.run(mission.mission_id, max_cycles=16)
        mission = orchestration.get(mission.mission_id)

        assert mission.context.endpoints, "an endpoint must be discovered"
        assert any(
            (h.provenance or {}).get("vulnerability_class") == "http-access-differential"
            for h in mission.hypotheses
        ), "an access-control hypothesis must be derived from the restricted surface"

        findings = finding_service.list_findings(mission.mission_id)
        report_ready = [f for f in findings if f.get("status") == "report_ready"]
        assert report_ready, "at least one HTTP access-differential finding must reach REPORT_READY"
        assert report_ready[0]["vulnerability_class"] == "http_access_differential"
        assert finding_service.get_report_readiness(report_ready[0]["finding_id"])["complete"] is True
