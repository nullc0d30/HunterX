# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Phase 8 — XSS end-to-end acceptance.

Proves the full chain through the existing architecture against the controlled
loopback vulnerable fixture:

endpoint discovered → parameter discovered → XSS hypothesis (derived from the
discovered reflection surface) → XSS capability probe → reflection analysis →
verification → evidence → reproduction → PoC → replay → VALIDATED →
REPORT_READY.

The XSS hypothesis is derived from a discovered, unclassified input
(``msg``) — never hardcoded to a known XSS endpoint.
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


def _create_xss(service: VulnerabilityFindingService, app: VulnerableApp, *, safe: bool = False) -> dict:
    path = "/safe/reflect" if safe else "/vuln/reflect"
    endpoint = app.base_url + path
    return service.create_finding(
        mission_id="m-xss",
        target_id=app.base_url,
        asset_id="app",
        asset="web",
        vulnerability_class="xss",
        title="Cross-site scripting on product page",
        description=f"Reflected XSS through the 'msg' parameter on {path}",
        severity="medium",
        tool="hunterx-capability",
        endpoints=(endpoint,),
        parameters=("msg",),
        observations=[
            {
                "kind": "detection_signature",
                "value": "candidate from discovered reflection surface",
                "quality": "medium",
                "source": "discovery",
            }
        ],
    )


class TestXssFindingService:
    def test_xss_workflow_to_report_ready(self, app: VulnerableApp) -> None:
        service = _service()
        finding = _create_xss(service, app)
        assert finding["status"] == "supported"
        finding_id = finding["finding_id"]

        verify = service.verify_with_probe(finding_id)
        assert verify["status"] == "validated", verify
        assert service.get_finding(finding_id)["status"] == "validated"

        package = service.get_finding_package(finding_id)
        kinds = {item["kind"] for item in package["evidence"]}
        assert "behavioral_differential" in kinds, kinds
        assert any("hxprobe" in str(item["value"]) for item in package["evidence"]), "reflection marker must be captured"

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
        package = service.get_finding_package(finding_id)
        assert package["impact"] is not None
        assert package["confidence"] is not None

    def test_safe_control_never_validates(self, app: VulnerableApp) -> None:
        service = _service()
        finding = _create_xss(service, app, safe=True)
        verify = service.verify_with_probe(finding["finding_id"])
        assert verify["status"] in ("contradicted", "blocked"), verify
        assert service.get_finding(finding["finding_id"])["status"] != "validated"

    def test_report_ready_finding_generates_professional_report(self, app: VulnerableApp) -> None:
        """An actual probe-verified XSS finding produces a professional report
        with the required fields — and no FindingRootCause exception."""
        from hunterx.application.professional_reporting import ProfessionalReportingService
        from hunterx.infrastructure.event_bus import InMemoryEventBus
        from hunterx.reporting.exporter import ReportExporter

        stores = InMemoryTidbRepositoryFactory()
        service = VulnerabilityFindingService(
            engine=ExecutionEngine(),
            stores=stores,
            event_bus=InMemoryEventBus(),
            knowledge_graph=InMemoryKnowledgeGraph(),
            tip=ToolIntelligenceAPI(),
            findings=InMemoryFindingRepository(),
        )
        finding = _create_xss(service, app)
        finding_id = finding["finding_id"]
        service.complete_validated_finding(finding_id)
        service.correlate_root_cause(finding_id)
        assert service.get_finding(finding_id)["status"] == "report_ready"

        reporting = ProfessionalReportingService(
            stores=stores,
            event_bus=InMemoryEventBus(),
            exporter=ReportExporter(),
        )
        report = reporting.generate_report(finding_id)
        assert report["status"] == "report_generated"
        intelligence = report["intelligence"]
        assert intelligence["vulnerability_class"] == "xss"
        assert intelligence["target_id"] == app.base_url
        # Endpoint + parameter surface is present.
        assert report["reproduction"]["endpoint"] == app.base_url + "/vuln/reflect"
        assert report["reproduction"]["parameter"] == "msg"
        # Evidence / impact / confidence / PoC / verification / root cause.
        assert report["evidence_bundle"]["artifacts"]
        assert any(
            artifact.get("kind") == "behavioral_differential" for artifact in report["evidence_bundle"]["artifacts"]
        )
        assert report["impact"]
        assert intelligence["confidence"]
        assert report["poc"]
        assert report["root_causes"], "the correlated root cause must appear in the report"
        assert report["executive_summary"]["finding_count"] == 1


class TestXssMissionBridge:
    def test_attack_surface_derives_xss_to_report_ready(self, app: VulnerableApp) -> None:
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
                "technologies": [
                    {
                        "type": "technology",
                        "asset": f"{target}/vuln/reflect?msg=hello",
                        "raw_name": f"{target}/vuln/reflect",
                    }
                ]
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
        assert mission.context.parameters, "a parameter must be discovered"
        xss_hypotheses = [
            h for h in mission.hypotheses if (h.provenance or {}).get("vulnerability_class") == "xss"
        ]
        assert xss_hypotheses, "an XSS hypothesis must be derived from the discovered surface"
        assert any(h.state.value == "validated" for h in xss_hypotheses)

        findings = finding_service.list_findings(mission.mission_id)
        report_ready = [f for f in findings if f.get("status") == "report_ready"]
        assert report_ready, "at least one XSS finding must reach REPORT_READY"
        assert report_ready[0]["vulnerability_class"] == "xss"
        assert finding_service.get_report_readiness(report_ready[0]["finding_id"])["complete"] is True
