# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Phase 14.3 — toolchain health + HTTP status/access-control bypass.

PART A — toolchain: the audited tool adapters (httpx/arjun/katana/nuclei/
ffuf/sqlmap) must never emit an invocation the installed binary rejects.
Regression: ffuf fails closed on a missing wordlist (its siblings already do).

PART B — generic HTTP 402/404/502 / access-control bypass. The existing
``http-access-differential`` capability must function end-to-end with REAL
discovery (no injected proof markers): a restricted endpoint observed on the
surface derives a hypothesis, a controlled mutation that exposes meaningful
protected content validates, and status-only / length-only / generic bodies
are always contradicted (never a vulnerability). Loopback-only probes are
preserved; nothing is DVWA-specific.
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
from hunterx.domain.vulnerability_capability.engine import VulnerabilityCapabilityEngine
from hunterx.domain.vulnerability_capability.probe_executor import ProbeExecutor
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


@pytest.fixture(scope="module")
def app() -> VulnerableApp:
    with VulnerableApp() as server:
        yield server


# ---------------------------------------------------------------------------
# PART A — toolchain health
# ---------------------------------------------------------------------------


class TestToolchainInvocationContracts:
    def test_ffuf_fails_closed_without_wordlist(self) -> None:
        """A content tool must never emit an invocation the binary rejects."""
        from hunterx.domain.execution import ExecutionContext
        from hunterx.tools.content.ffuf import FfufAdapter

        with pytest.raises(ValueError, match="wordlist"):
            FfufAdapter().build_argv(
                ExecutionContext(tool_id="ffuf", execution_id="e", target="http://127.0.0.1:9/")
            )

    def test_ffuf_argv_carries_wordlist(self) -> None:
        from hunterx.domain.execution import ExecutionContext
        from hunterx.tools.content.ffuf import FfufAdapter

        argv = FfufAdapter().build_argv(
            ExecutionContext(
                tool_id="ffuf",
                execution_id="e",
                target="http://127.0.0.1:9/",
                parameters={"wordlist": "/tmp/wl.txt"},
            )
        )
        assert "-w" in argv
        assert "/tmp/wl.txt" in argv
        assert "-o" in argv and "-" in argv  # JSON to stdout

    @pytest.mark.skipif(
        __import__("os").name == "nt" or not __import__("shutil").which("httpx"),
        reason="real binary invocation runs in the WSL toolchain environment (Windows pytest cannot resolve it)",
    )
    def test_real_httpx_invocation_parses(self, app: VulnerableApp) -> None:
        """The installed httpx must run the adapter argv and parse observations."""
        from hunterx.domain.execution import ExecutionContext
        from hunterx.tools.recon.runner import CommandResult
        from hunterx.tools.tech.httpx import HttpxAdapter

        adapter = HttpxAdapter()
        context = ExecutionContext(tool_id="httpx", execution_id="p14-3", target=app.base_url, timeout_seconds=20)
        argv = adapter.build_argv(context)
        import subprocess

        proc = subprocess.run(argv, capture_output=True, text=True, timeout=45)
        observations = adapter.parse_output(
            context, CommandResult(proc.returncode, proc.stdout, proc.stderr, argv)
        )
        assert proc.returncode == 0, proc.stderr
        assert observations, "httpx must produce at least one technology observation"

    @pytest.mark.skipif(
        __import__("os").name == "nt" or not __import__("shutil").which("katana"),
        reason="real binary invocation runs in the WSL toolchain environment (Windows pytest cannot resolve it)",
    )
    def test_real_katana_invocation_parses(self, app: VulnerableApp) -> None:
        """The installed katana must crawl the fixture index and parse URLs."""
        from hunterx.domain.execution import ExecutionContext
        from hunterx.tools.recon.runner import CommandResult
        from hunterx.tools.web.katana import KatanaAdapter

        adapter = KatanaAdapter()
        context = ExecutionContext(tool_id="katana", execution_id="p14-3", target=app.base_url, timeout_seconds=20)
        argv = adapter.build_argv(context)
        import subprocess

        proc = subprocess.run(argv, capture_output=True, text=True, timeout=45)
        observations = adapter.parse_output(
            context, CommandResult(proc.returncode, proc.stdout, proc.stderr, argv)
        )
        assert proc.returncode == 0, proc.stderr
        assert any("/protected" in str(getattr(o, "url", o)) for o in observations)


# ---------------------------------------------------------------------------
# PART B — HTTP status/access-control bypass capability
# ---------------------------------------------------------------------------


class TestHttpAccessDifferentialCapability:
    def test_class_is_registered(self) -> None:
        from hunterx.domain.vulnerability_capability.registry import (
            capability_for,
            is_vulnerability_class,
        )

        assert is_vulnerability_class("http-access-differential")
        capability = capability_for("http-access-differential")
        assert capability is not None
        assert capability.vulnerability_class == "http-access-differential"

    def test_probe_builds_mutations(self, app: VulnerableApp) -> None:
        engine = VulnerabilityCapabilityEngine()
        probe = engine.build_probe(
            "http-access-differential",
            {"endpoint": f"{app.base_url}/protected", "observed_status": "403"},
        )
        assert probe is not None
        assert probe.mutations, "the probe must carry controlled mutations"

    def test_mutation_exposes_protected_content(self, app: VulnerableApp) -> None:
        engine = VulnerabilityCapabilityEngine()
        endpoint = f"{app.base_url}/protected"
        probe = engine.build_probe(
            "http-access-differential", {"endpoint": endpoint, "observed_status": "403"}
        )
        assert probe is not None
        responses = ProbeExecutor().execute(probe, target=endpoint)
        assert responses[0]["status"] == 403, "baseline must be restricted"
        verdict = engine.analyze_probe("http-access-differential", probe, responses)
        assert verdict.supported, verdict.notes
        assert "meaningful_access" in verdict.evidence

    def test_safe_control_is_contradicted(self, app: VulnerableApp) -> None:
        engine = VulnerabilityCapabilityEngine()
        endpoint = f"{app.base_url}/safe/protected"
        probe = engine.build_probe(
            "http-access-differential", {"endpoint": endpoint, "observed_status": "403"}
        )
        assert probe is not None
        responses = ProbeExecutor().execute(probe, target=endpoint)
        verdict = engine.analyze_probe("http-access-differential", probe, responses)
        assert verdict.contradicted, verdict.notes

    @pytest.mark.parametrize(
        "path,status",
        [
            ("/statusbypass", 403),  # 403 -> 200 "ok": status-only
            ("/lengthonly", 403),  # 403 -> 200 generic denied body
            ("/error", 502),  # 502 -> 503: proxy status change
            ("/safe/hidden", 404),  # 404 -> 404: still denied
        ],
    )
    def test_status_only_changes_never_validate(self, app: VulnerableApp, path: str, status: int) -> None:
        engine = VulnerabilityCapabilityEngine()
        endpoint = f"{app.base_url}{path}"
        probe = engine.build_probe(
            "http-access-differential", {"endpoint": endpoint, "observed_status": str(status)}
        )
        assert probe is not None
        responses = ProbeExecutor().execute(probe, target=endpoint)
        assert responses[0]["status"] == status
        verdict = engine.analyze_probe("http-access-differential", probe, responses)
        assert not verdict.supported, verdict.notes
        assert verdict.contradicted or verdict.uninformative

    def test_proof_marker_path_still_requires_meaningful_access(self, app: VulnerableApp) -> None:
        engine = VulnerabilityCapabilityEngine()
        endpoint = f"{app.base_url}/protected"
        probe = engine.build_probe(
            "http-access-differential",
            {"endpoint": endpoint, "observed_status": "403", "proof_marker": "hxbypass_protected"},
        )
        assert probe is not None
        responses = ProbeExecutor().execute(probe, target=endpoint)
        verdict = engine.analyze_probe("http-access-differential", probe, responses)
        assert verdict.supported
        assert verdict.evidence["proof_marker"] == "hxbypass_protected"

    def test_marker_path_rejects_missing_marker(self, app: VulnerableApp) -> None:
        engine = VulnerabilityCapabilityEngine()
        endpoint = f"{app.base_url}/safe/protected"
        probe = engine.build_probe(
            "http-access-differential",
            {"endpoint": endpoint, "observed_status": "403", "proof_marker": "hxbypass_protected"},
        )
        assert probe is not None
        responses = ProbeExecutor().execute(probe, target=endpoint)
        verdict = engine.analyze_probe("http-access-differential", probe, responses)
        assert not verdict.supported


class TestRestrictedEndpointDiscovery:
    def test_parameter_discovery_records_restricted_status(self, app: VulnerableApp) -> None:
        stores = InMemoryTidbRepositoryFactory()
        planning = AdaptiveMissionPlanningEngine(
            tool_selection_engine=ToolSelectionEngine(mission_type="bug-bounty", default_candidates={})
        )
        orchestrator = MissionOrchestrator(planning=planning)
        orchestration = MissionOrchestrationService(
            engine=MissionOrchestrationEngine(orchestrator=orchestrator),
            stores=stores,
        )
        runner = MissionExecutionService(
            orchestration=orchestration,
            planning=planning,
            execution_engine=FakeExecutionEngine(outputs={}),
        )
        mission = orchestration.create_mission(objective="bug_bounty_assessment", target=app.base_url)
        endpoint = f"{app.base_url}/protected"
        observation, status = runner._form_field_observation(mission.mission_id, endpoint)
        assert observation is None  # no forms on the 403 page
        assert status == 403

    def test_restricted_surface_derives_hypothesis(self, app: VulnerableApp) -> None:
        stores = InMemoryTidbRepositoryFactory()
        planning = AdaptiveMissionPlanningEngine(
            tool_selection_engine=ToolSelectionEngine(mission_type="bug-bounty", default_candidates={})
        )
        orchestrator = MissionOrchestrator(planning=planning)
        orchestration = MissionOrchestrationService(
            engine=MissionOrchestrationEngine(orchestrator=orchestrator),
            stores=stores,
        )
        runner = MissionExecutionService(
            orchestration=orchestration,
            planning=planning,
            execution_engine=FakeExecutionEngine(outputs={}),
        )
        mission = orchestration.create_mission(objective="bug_bounty_assessment", target=app.base_url)
        endpoint = f"{app.base_url}/protected"
        runner._orchestration.ingest_result(
            mission.mission_id,
            tool_id="crawler",
            action_id="a1",
            asset_key=endpoint,
            raw={"observation_type": "endpoint", "content": {"status_code": 403, "endpoint": endpoint}},
        )
        mission = orchestration.get(mission.mission_id)
        access = [
            h for h in mission.hypotheses if (h.provenance or {}).get("vulnerability_class") == "http-access-differential"
        ]
        assert access, "a restricted endpoint must derive an http-access-differential hypothesis"
        assert (access[0].provenance or {}).get("observed_status") == 403

    def test_safe_endpoint_does_not_derive_hypothesis(self, app: VulnerableApp) -> None:
        stores = InMemoryTidbRepositoryFactory()
        planning = AdaptiveMissionPlanningEngine(
            tool_selection_engine=ToolSelectionEngine(mission_type="bug-bounty", default_candidates={})
        )
        orchestrator = MissionOrchestrator(planning=planning)
        orchestration = MissionOrchestrationService(
            engine=MissionOrchestrationEngine(orchestrator=orchestrator),
            stores=stores,
        )
        runner = MissionExecutionService(
            orchestration=orchestration,
            planning=planning,
            execution_engine=FakeExecutionEngine(outputs={}),
        )
        mission = orchestration.create_mission(objective="bug_bounty_assessment", target=app.base_url)
        endpoint = f"{app.base_url}/search"
        runner._orchestration.ingest_result(
            mission.mission_id,
            tool_id="crawler",
            action_id="a1",
            asset_key=endpoint,
            raw={"observation_type": "endpoint", "content": {"status_code": 200, "endpoint": endpoint}},
        )
        mission = orchestration.get(mission.mission_id)
        access = [
            h for h in mission.hypotheses if (h.provenance or {}).get("vulnerability_class") == "http-access-differential"
        ]
        assert not access, "a 200 endpoint must never derive an access-control hypothesis"

    def test_parameter_discovery_negative_records_status_and_derives_hypothesis(
        self, app: VulnerableApp
    ) -> None:
        """The full hook path: an empty arjun result on a restricted endpoint
        records its status through ``_handle_execution`` and the orchestrator
        derives an http-access-differential hypothesis."""
        from hunterx.domain.adaptive_mission_planning.enums import ReplanTrigger
        from hunterx.domain.execution import ExecutionContext

        stores = InMemoryTidbRepositoryFactory()
        planning = AdaptiveMissionPlanningEngine(
            tool_selection_engine=ToolSelectionEngine(mission_type="bug-bounty", default_candidates={})
        )
        orchestrator = MissionOrchestrator(planning=planning)
        orchestration = MissionOrchestrationService(
            engine=MissionOrchestrationEngine(orchestrator=orchestrator),
            stores=stores,
        )
        fake = FakeExecutionEngine(outputs={"arjun": {"parameters": {"findings": []}}})
        runner = MissionExecutionService(
            orchestration=orchestration,
            planning=planning,
            execution_engine=fake,
        )
        mission = orchestration.create_mission(objective="bug_bounty_assessment", target=app.base_url)
        orchestration.start(mission.mission_id)
        endpoint = f"{app.base_url}/protected"
        runner._planning.replan_for_change(
            mission.mission_id,
            trigger=ReplanTrigger.NEW_ENDPOINT_DISCOVERED,
            asset_key=endpoint,
            reason="test fixture",
        )
        action = next(
            a
            for a in runner._planning.get_plan(mission.mission_id).actions.values()
            if a.capability == "parameter_discovery" and a.asset == endpoint
        )
        context = ExecutionContext(tool_id="arjun", execution_id="exec-1", target=endpoint)
        pipeline = fake.execute(context)
        runner._handle_execution(
            mission.mission_id,
            action_id=action.action_id,
            capability="parameter_discovery",
            tool_id="arjun",
            target=endpoint,
            pipeline=pipeline,
        )
        mission = orchestration.get(mission.mission_id)
        entry = mission.context.endpoints.get(f"endpoint:{endpoint}")
        assert entry is not None and entry.get("status") == 403
        access = [
            h
            for h in mission.hypotheses
            if (h.provenance or {}).get("vulnerability_class") == "http-access-differential"
        ]
        assert access, "the restricted status must derive an http-access-differential hypothesis"


class TestAccessDifferentialFindingLifecycle:
    """Generic (no injected proof marker) bypass reaches REPORT_READY via the
    finding service when and only when a mutation exposes meaningful content.
    """

    @staticmethod
    def _service():
        return VulnerabilityFindingService(
            engine=ExecutionEngine(),
            stores=InMemoryTidbRepositoryFactory(),
            event_bus=InMemoryEventBus(),
            knowledge_graph=InMemoryKnowledgeGraph(),
            tip=ToolIntelligenceAPI(),
            findings=InMemoryFindingRepository(),
        )

    def test_bypass_finding_reaches_report_ready(self, app: VulnerableApp) -> None:
        service = self._service()
        endpoint = f"{app.base_url}/protected"
        finding = service.create_finding(
            mission_id="m-p143",
            target_id=app.base_url,
            asset_id="app",
            asset="web",
            vulnerability_class="http_access_differential",
            title="HTTP access differential on /protected",
            description="restricted resource reachable via an alternate representation",
            severity="high",
            tool="hunterx-capability",
            endpoints=(endpoint,),
            parameters=(),
            observations=[{"kind": "detection_signature", "value": "restricted surface", "quality": "medium", "source": "discovery"}],
            provenance="hypothesis:test",
            scope={"observed_status": "403", "reproduction_request": endpoint + "/", "reproduction_method": "GET"},
        )
        finding_id = finding["finding_id"]
        verify = service.verify_with_probe(finding_id)
        assert verify["status"] == "validated", verify
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
        assert ready["transition"]["allowed"] is True
        assert service.get_finding(finding_id)["status"] == "report_ready"
        assert service.get_report_readiness(finding_id)["complete"] is True

    def test_safe_control_never_reaches_validated(self, app: VulnerableApp) -> None:
        service = self._service()
        endpoint = f"{app.base_url}/safe/protected"
        finding = service.create_finding(
            mission_id="m-p143",
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
            observations=[{"kind": "detection_signature", "value": "restricted surface", "quality": "medium", "source": "discovery"}],
            provenance="hypothesis:safe",
            scope={"observed_status": "403", "reproduction_request": endpoint + "/", "reproduction_method": "GET"},
        )
        verify = service.verify_with_probe(finding_id) if (finding_id := finding["finding_id"]) else {}
        assert verify["status"] in ("contradicted", "blocked"), verify
        state = service.get_finding(finding_id)["status"]
        assert state not in ("proved", "report_ready")


class TestAccessDifferentialMissionBridge:
    """A discovered restricted surface (no injected proof marker) flows through
    the mission: hypothesis → generic differential probe → validated → finding
    lifecycle → REPORT_READY. Duplicate findings are prevented.
    """

    def _runner(self, app: VulnerableApp):
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
                default_candidates=dict({"endpoint_enumeration": ("httpx",)}),
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
            execution_engine=FakeExecutionEngine(outputs={}),
            finding_service=finding_service,
        )
        return stores, finding_service, planning, orchestrator, orchestration, runner

    def test_bypass_mission_to_report_ready_without_marker(self, app: VulnerableApp) -> None:
        stores, finding_service, planning, orchestrator, orchestration, runner = self._runner(app)
        target = app.base_url
        outputs = {
            "httpx": {
                "status_code": 200,
                "technologies": [{"type": "technology", "asset": f"{target}/protected", "raw_name": f"{target}/protected"}],
            }
        }
        runner._engine = FakeExecutionEngine(outputs=outputs)
        mission = orchestration.create_mission(objective="bug_bounty_assessment", target=target)
        mission.policy = dataclasses.replace(
            mission.policy,
            coverage_target=0.99,
            stop_conditions=(StopCondition.COVERAGE_TARGET_ACHIEVED, StopCondition.RESOURCE_BUDGET_EXHAUSTED),
        )
        orchestration.start(mission.mission_id)
        endpoint = f"{target}/protected"
        runner._orchestration.ingest_result(
            mission.mission_id,
            tool_id="crawler",
            action_id="disc-1",
            asset_key=endpoint,
            raw={"observation_type": "endpoint", "content": {"status_code": 403, "endpoint": endpoint}},
        )
        mission = orchestration.get(mission.mission_id)
        access = [
            h
            for h in mission.hypotheses
            if (h.provenance or {}).get("vulnerability_class") == "http-access-differential"
        ]
        assert access, "the restricted endpoint must derive an access-control hypothesis"

        # The hypothesis's differential probe (no marker) must validate via the
        # generic meaningful-access path.
        from hunterx.domain.vulnerability_capability.engine import VulnerabilityCapabilityEngine
        from hunterx.domain.vulnerability_capability.probe_executor import ProbeExecutor

        hypothesis = access[0]
        evidence = {
            "endpoint": str((hypothesis.provenance or {}).get("endpoint") or endpoint),
            "parameter": str((hypothesis.provenance or {}).get("parameter") or ""),
            "observed_status": str((hypothesis.provenance or {}).get("observed_status") or "403"),
        }
        probe = VulnerabilityCapabilityEngine().build_probe("http-access-differential", evidence)
        assert probe is not None
        responses = ProbeExecutor().execute(probe, target=evidence["endpoint"])
        verdict = VulnerabilityCapabilityEngine().analyze_probe("http-access-differential", probe, responses)
        assert verdict.supported, verdict.notes
        assert responses[0]["status"] == 403

        # Drive the full lifecycle through the mission service.
        runner.run(mission.mission_id, max_cycles=8)
        findings = finding_service.list_findings(mission.mission_id)
        report_ready = [f for f in findings if f.get("status") == "report_ready"]
        assert report_ready, "the bypass must reach REPORT_READY"
        assert report_ready[0]["vulnerability_class"] == "http_access_differential"
        assert finding_service.get_report_readiness(report_ready[0]["finding_id"])["complete"] is True

    def test_duplicate_bypass_findings_are_prevented(self, app: VulnerableApp) -> None:
        stores, finding_service, planning, orchestrator, orchestration, runner = self._runner(app)
        target = app.base_url
        endpoint = f"{target}/protected"
        mission = orchestration.create_mission(objective="bug_bounty_assessment", target=target)
        orchestration.start(mission.mission_id)
        raw = {"observation_type": "endpoint", "content": {"status_code": 403, "endpoint": endpoint}}
        runner._orchestration.ingest_result(
            mission.mission_id, tool_id="crawler", action_id="d1", asset_key=endpoint, raw=raw
        )
        runner._orchestration.ingest_result(
            mission.mission_id, tool_id="crawler", action_id="d2", asset_key=endpoint, raw=raw
        )
        mission = orchestration.get(mission.mission_id)
        access = [
            h
            for h in mission.hypotheses
            if (h.provenance or {}).get("vulnerability_class") == "http-access-differential"
        ]
        assert len(access) == 1, "repeated observation of the same restricted surface must derive one hypothesis"
        assert len(
            {str((h.provenance or {}).get("statement") or "") for h in access}
        ) == 1
