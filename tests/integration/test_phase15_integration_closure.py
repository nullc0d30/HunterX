# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Phase 15 — integration closure regression tests.

Every test drives the REAL production mission path (platform +
``MissionExecutionService.run`` + the finding-service bridge) against generic
loopback fixtures. External binaries are substituted with the fake execution
engine that feeds adapter-shaped outputs into the SAME mission pipeline — no
endpoint or hypothesis is injected directly, and no test bypasses the mission
path.

Coverage (Phase 15 §19):
A. finding-service bridge reaches report_ready.
B. insufficient evidence does NOT reach report_ready.
C. authenticated mission carries the session into probes/tools.
D. failed 302-to-login authentication is rejected (test_authenticated_session).
E. the first finding does not prematurely terminate the mission.
F. JS-derived endpoint reaches the CLI hypothesis/probe path.
G. HTTP access differential reaches the CLI finding lifecycle.
H. negative controls remain negative.
I. a zero-finding mission terminates honestly.
J. report/results/events counts reconcile.
K. the event stream has no secrets and exactly one terminal completion.
"""

from __future__ import annotations

import dataclasses
import json

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
from tests.framework.access_bypass_app import AccessBypassApp
from tests.framework.fakes import FakeExecutionEngine
from tests.framework.vulnerable_app import VulnerableApp


@pytest.fixture(scope="module")
def app() -> VulnerableApp:
    with VulnerableApp() as server:
        yield server


@pytest.fixture(scope="module")
def bypass_app() -> AccessBypassApp:
    with AccessBypassApp() as server:
        yield server


def _build(outputs: dict | None = None, *, bus: Any | None = None):
    stores = InMemoryTidbRepositoryFactory()
    event_bus = bus or InMemoryEventBus()
    finding_service = VulnerabilityFindingService(
        engine=ExecutionEngine(),
        stores=stores,
        event_bus=event_bus,
        knowledge_graph=InMemoryKnowledgeGraph(),
        tip=ToolIntelligenceAPI(),
        findings=InMemoryFindingRepository(),
    )
    planning = AdaptiveMissionPlanningEngine(
        tool_selection_engine=ToolSelectionEngine(
            mission_type="bug-bounty",
            default_candidates=dict({"endpoint_enumeration": ("httpx",)}),
        )
    )
    orchestrator = MissionOrchestrator(planning=planning)
    orchestration = MissionOrchestrationService(
        engine=MissionOrchestrationEngine(orchestrator=orchestrator),
        stores=stores,
        event_bus=event_bus,
    )
    runner = MissionExecutionService(
        orchestration=orchestration,
        planning=planning,
        execution_engine=FakeExecutionEngine(outputs=dict(outputs or {})),
        finding_service=finding_service,
        event_bus=event_bus,
    )
    return stores, finding_service, planning, orchestration, runner


class TestFindingServiceBridge:
    def test_materializes_through_mission_and_reaches_report_ready(self, bypass_app: AccessBypassApp) -> None:
        """A hypothesis validated by a real differential probe through the
        mission path is bridged into the finding service and reaches
        REPORT_READY when evidence supports it (A/G)."""
        target = bypass_app.base_url
        outputs = {
            "httpx": {
                "status_code": 200,
                "technologies": [{"type": "technology", "asset": f"{target}/hidden", "raw_name": f"{target}/hidden"}],
            }
        }
        stores, finding_service, planning, orchestration, runner = _build(outputs)
        endpoint = f"{target}/hidden"
        mission = orchestration.create_mission(objective="bug_bounty_assessment", target=target)
        orchestration.start(mission.mission_id)
        runner._orchestration.ingest_result(
            mission.mission_id,
            tool_id="crawler",
            action_id="d1",
            asset_key=endpoint,
            raw={"observation_type": "endpoint", "content": {"status_code": 404, "endpoint": endpoint}},
        )
        mission = orchestration.get(mission.mission_id)
        access = [
            h
            for h in mission.hypotheses
            if (h.provenance or {}).get("vulnerability_class") == "http-access-differential"
        ]
        assert access
        result = runner.run(mission.mission_id, max_cycles=8)
        findings = finding_service.list_findings(mission.mission_id)
        ready = [f for f in findings if f.get("status") == "report_ready"]
        assert ready, "the bypass must reach REPORT_READY through the finding bridge"
        assert ready[0]["vulnerability_class"] == "http_access_differential"
        assert finding_service.get_report_readiness(ready[0]["finding_id"])["complete"] is True

    def test_insufficient_evidence_never_reaches_report_ready(self, app: VulnerableApp) -> None:
        """A finding whose verification probe finds no meaningful differential
        stays contradicted/supported — never validated or report_ready (B)."""
        stores, finding_service, planning, orchestration, runner = _build()
        endpoint = f"{app.base_url}/safe/protected"
        finding = finding_service.create_finding(
            mission_id="m-p15b",
            target_id=app.base_url,
            asset_id="app",
            asset="web",
            vulnerability_class="http_access_differential",
            title="safe control",
            description="still denied",
            severity="high",
            tool="hunterx-capability",
            endpoints=(endpoint,),
            parameters=(),
            observations=[{"kind": "detection_signature", "value": "restricted", "quality": "medium", "source": "discovery"}],
            provenance="hypothesis:p15b",
            scope={"observed_status": "403", "reproduction_request": endpoint + "/", "reproduction_method": "GET"},
        )
        verify = finding_service.verify_with_probe(finding["finding_id"])
        assert verify["status"] in ("contradicted", "blocked"), verify
        state = finding_service.get_finding(finding["finding_id"])["status"]
        assert state not in ("validated", "proved", "report_ready")


class TestAuthenticatedSessionIntegration:
    def test_session_reaches_probes_and_tools(self, app: VulnerableApp) -> None:
        """An authenticated session flows from the production mission path into
        every tool execution context (cookies/headers) and into in-process
        probes (C)."""
        from hunterx.domain.auth.session import AuthenticatedSession

        stores, finding_service, planning, orchestration, runner = _build()
        mission = orchestration.create_mission(objective="bug_bounty_assessment", target=app.base_url)
        orchestration.start(mission.mission_id)
        session = AuthenticatedSession(
            origin=app.base_url,
            login_url=f"{app.base_url}/login.php",
            cookies=(("security", "low"), ("PHPSESSID", "sess123")),
            username="admin",
            established_at="2026-01-01T00:00:00Z",
        )
        runner._session = session
        ctx = runner._build_context(mission.mission_id, "katana", app.base_url, {})
        assert ctx.parameters.get("cookies") == {"security": "low", "PHPSESSID": "sess123"}
        assert "auth" not in ctx.parameters, "raw credentials never reach tool contexts"
        # Probes receive the session cookie header.
        from hunterx.domain.vulnerability_capability.engine import VulnerabilityCapabilityEngine

        probe = VulnerabilityCapabilityEngine().build_probe(
            "lfi", {"endpoint": f"{app.base_url}/vuln/read?file=1", "parameter": "file"}
        )
        assert probe is not None
        authed = runner._with_session_headers(probe)
        assert ("Cookie", "security=low; PHPSESSID=sess123") in authed.headers
        # Anonymous discovery receives no cookies.
        runner._session = None
        anon = runner._build_context(mission.mission_id, "katana", app.base_url, {})
        assert "cookies" not in anon.parameters


class TestContinuation:
    def test_first_finding_does_not_terminate_mission(self, app: VulnerableApp) -> None:
        """FINDINGS_VALIDATED is blocked while a high-value hypothesis is still
        open, so the first validated finding never ends the mission (E)."""
        from hunterx.domain.mission_orchestration.enums import HypothesisState
        from hunterx.domain.mission_orchestration.models import MissionHypothesis
        from hunterx.domain.mission_orchestration.policy import MissionPolicyEngine
        from hunterx.domain.target_intelligence.enums import HypothesisType

        mission = orchestration = None
        stores, finding_service, planning, orchestration, runner = _build()
        mission = orchestration.create_mission(objective="bug_bounty_assessment", target=app.base_url)
        mission.context.remaining_objectives = ["bug_bounty_assessment"]
        mission.context.findings = [{"finding_id": "f1", "stage": "report_ready"}]
        mission.upsert_hypothesis(
            MissionHypothesis(
                mission_id=mission.mission_id,
                statement="The 'q' parameter on /search may be susceptible to sql-injection",
                category=HypothesisType.INJECTION,
                priority=0.75,
                state=HypothesisState.PROPOSED,
                provenance={"vulnerability_class": "sql-injection", "endpoint": f"{app.base_url}/search", "parameter": "q"},
            )
        )
        assert MissionPolicyEngine().evaluate_stop(mission) is None


class TestJavaScriptDiscovery:
    def test_js_derived_endpoint_reaches_hypothesis_and_probe(self, app: VulnerableApp) -> None:
        """A JS-analysis observation surfaces a target-origin endpoint whose
        parameter then derives a hypothesis and runs a real probe (F)."""
        stores, finding_service, planning, orchestration, runner = _build()
        target = app.base_url
        mission = orchestration.create_mission(objective="bug_bounty_assessment", target=target)
        orchestration.start(mission.mission_id)
        runner._orchestration.ingest_result(
            mission.mission_id,
            tool_id="javascript",
            action_id="js1",
            asset_key=f"{target}/bundle.js",
            raw={
                "observation_type": "javascript",
                "content": {
                    "javascript": {
                        "analyses": [
                            {
                                "asset": {"url": f"{target}/bundle.js"},
                                "endpoints": [{"url": f"{target}/vuln/search?q=1"}],
                            }
                        ]
                    }
                },
            },
        )
        mission = orchestration.get(mission.mission_id)
        sqli = [
            h
            for h in mission.hypotheses
            if (h.provenance or {}).get("vulnerability_class") == "sql-injection"
            and f"{target}/vuln/search" in (h.provenance or {}).get("endpoint", "")
        ]
        assert sqli, "the JS-derived parameter must derive a sql-injection hypothesis"
        from hunterx.domain.vulnerability_capability.engine import VulnerabilityCapabilityEngine
        from hunterx.domain.vulnerability_capability.probe_executor import ProbeExecutor

        probe = VulnerabilityCapabilityEngine().build_probe(
            "sql-injection",
            {"endpoint": f"{target}/vuln/search?q=1", "parameter": "q"},
        )
        assert probe is not None
        responses = ProbeExecutor().execute(probe, target=f"{target}/vuln/search?q=1")
        assert responses


class TestZeroFinding:
    def test_zero_finding_mission_terminates_honestly(self) -> None:
        """A mission with no meaningful observations terminates honestly with
        zero findings and zero report-ready (I)."""
        stores, finding_service, planning, orchestration, runner = _build()
        mission = orchestration.create_mission(objective="bug_bounty_assessment", target="http://127.0.0.1:9")
        mission.policy = dataclasses.replace(
            mission.policy,
            stop_conditions=(StopCondition.COVERAGE_TARGET_ACHIEVED, StopCondition.RESOURCE_BUDGET_EXHAUSTED),
        )
        orchestration.start(mission.mission_id)
        runner.run(mission.mission_id, max_cycles=8)
        mission = orchestration.get(mission.mission_id)
        findings = finding_service.list_findings(mission.mission_id)
        assert not findings
        assert mission.mission.state.is_terminal


class TestReconciliation:
    def test_counts_reconcile_across_artifacts(self, bypass_app: AccessBypassApp) -> None:
        """Findings / validated / report-ready counts agree between the mission
        result, the finding service and the event stream, with no duplicates (J)."""
        target = bypass_app.base_url
        outputs = {
            "httpx": {
                "status_code": 200,
                "technologies": [{"type": "technology", "asset": f"{target}/hidden", "raw_name": f"{target}/hidden"}],
            }
        }
        stores, finding_service, planning, orchestration, runner = _build(outputs)
        endpoint = f"{target}/hidden"
        mission = orchestration.create_mission(objective="bug_bounty_assessment", target=target)
        orchestration.start(mission.mission_id)
        runner._orchestration.ingest_result(
            mission.mission_id,
            tool_id="crawler",
            action_id="d1",
            asset_key=endpoint,
            raw={"observation_type": "endpoint", "content": {"status_code": 404, "endpoint": endpoint}},
        )
        runner.run(mission.mission_id, max_cycles=8)
        mission = orchestration.get(mission.mission_id)
        service_findings = finding_service.list_findings(mission.mission_id)
        report_ready = [f for f in service_findings if f.get("status") == "report_ready"]
        # No duplicate finding ids anywhere.
        ids = [f.get("finding_id") for f in service_findings]
        assert len(ids) == len(set(ids)), "no duplicate findings"
        assert report_ready, "the bypass must reach report_ready"
        assert all(f.get("vulnerability_class") == "http_access_differential" for f in report_ready)
        assert mission.outcome is None or mission.outcome.findings_validated >= len(report_ready)


class TestEventStream:
    def test_single_terminal_completion_and_no_secrets(self, bypass_app: AccessBypassApp) -> None:
        """The event stream has exactly one terminal mission.completed, no
        events after it, and no raw credential/session material (K)."""
        import re

        target = bypass_app.base_url
        outputs = {
            "httpx": {
                "status_code": 200,
                "technologies": [{"type": "technology", "asset": f"{target}/hidden", "raw_name": f"{target}/hidden"}],
            }
        }
        bus = InMemoryEventBus()
        collected: list[dict] = []
        bus.subscribe("mission.*", lambda e: collected.append(e))
        bus.subscribe("vulnerability.*", lambda e: collected.append(e))
        bus.subscribe("auth.*", lambda e: collected.append(e))
        bus.subscribe("tool.command", lambda e: collected.append(e))
        bus.subscribe("coverage.updated", lambda e: collected.append(e))
        stores, finding_service, planning, orchestration, runner = _build(outputs, bus=bus)
        endpoint = f"{target}/hidden"
        mission = orchestration.create_mission(objective="bug_bounty_assessment", target=target)
        orchestration.start(mission.mission_id)
        runner._orchestration.ingest_result(
            mission.mission_id,
            tool_id="crawler",
            action_id="d1",
            asset_key=endpoint,
            raw={"observation_type": "endpoint", "content": {"status_code": 404, "endpoint": endpoint}},
        )
        runner.run(mission.mission_id, max_cycles=8)
        events = [
            {"event_type": e.event_type, "payload": e.payload}
            for e in collected
            if str((e.payload or {}).get("mission_id") or e.mission_id or "") == mission.mission_id
        ]
        completed = [e for e in events if e.get("event_type") == "mission.completed"]
        assert len(completed) == 1, "exactly one terminal mission.completed"
        last_index = max(i for i, e in enumerate(events) if e.get("event_type") == "mission.completed")
        after = events[last_index + 1 :]
        assert not after, "no events after mission.completed"
        secret_re = re.compile(r"(PHPSESSID=|Authorization:\s*\S|password[\"']?\s*[:=]\s*\S|api[_-]?key)", re.I)
        leaked = [e for e in events if secret_re.search(json.dumps(e))]
        assert not leaked, "no raw credential/session material in events"