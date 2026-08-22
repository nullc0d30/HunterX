# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Focused regression tests for the mission-runner workflow defects.

Each test class pins one defect:

1. Scheme-aware target normalization (web vs host tools).
2. Empty-but-successful results are never TESTED coverage without evidence.
3. Replanned capabilities are re-checked against tool readiness.
5. Empty observations never fabricate phantom target-model entities.
6. Observations only create hypotheses/findings when they carry evidence.
7. The orchestration phase advances with the meaningful workflow state.
8. Every terminal runner exit finalizes the run (idempotent).
"""

from __future__ import annotations

import dataclasses
from types import SimpleNamespace

from hunterx.application.mission_execution import MissionExecutionService
from hunterx.application.mission_orchestration import MissionOrchestrationService
from hunterx.domain.adaptive_mission_planning.toolchain import ToolSelectionEngine
from hunterx.domain.execution import (
    ExecutionOutput,
    ExecutionResult,
    ExecutionStatus,
    OutputFormat,
)
from hunterx.domain.mission_orchestration.enums import MissionPhase, StopCondition
from hunterx.domain.mission_orchestration.orchestrator import MissionOrchestrator
from hunterx.domain.target_intelligence.enums import CoverageState
from hunterx.engines.adaptive_mission_planning.engine import AdaptiveMissionPlanningEngine
from hunterx.engines.mission_orchestration import MissionOrchestrationEngine
from hunterx.infrastructure.db.sql.memory import InMemoryTidbRepositoryFactory
from hunterx.tools.sdk.pipeline import ExecutionSession, PipelineResult
from tests.framework.fakes import FakeExecutionEngine

_TARGET = "http://localhost:3010"

_DEFAULT_CANDIDATES: dict[str, tuple[str, ...]] = {
    "asset_discovery": ("subfinder", "amass", "assetfinder"),
    "subdomain_enumeration": ("subfinder", "amass", "assetfinder"),
    "dns_enumeration": ("dnsx", "dig"),
    "port_discovery": ("nmap", "rustscan", "masscan"),
    "service_detection": ("nmap", "httpx"),
    "technology_fingerprint": ("whatweb", "wappalyzer"),
    "certificate_enumeration": ("certspotter", "crt.sh"),
    "endpoint_enumeration": ("httpx", "katana", "gospider"),
    "parameter_discovery": ("arjun", "x8"),
    "vulnerability_scanning": ("nuclei", "nikto"),
}

_MEANINGFUL_OUTPUTS: dict[str, dict[str, object]] = {
    "subfinder": {
        "discoveries": [{"kind": "subdomain", "name": "api.localhost"}],
        "count": 1,
    },
    "dnsx": {"records": ["api.localhost -> 127.0.0.1"]},
    "nmap": {"ports": [80, 3010]},
    "whatweb": {"name": "express", "technologies": ["node.js", "express"]},
    "httpx": {"endpoints": ["/rest/products/search", "/api/products"]},
    "arjun": {"parameters": ["q", "id"]},
    "nuclei": {
        "findings": [
            {
                "template_id": "missing-security-headers",
                "template_name": "Missing Security Headers",
                "severity": "low",
                "matched_at": "http://localhost:3010/",
            }
        ]
    },
    "certspotter": {"certificates": ["localhost"]},
    "katana": {"endpoints": ["/api"]},
}

_EMPTY_OUTPUTS: dict[str, dict[str, object]] = {
    "subfinder": {},
    "dnsx": {},
    "nmap": {},
    "whatweb": {},
    "httpx": {},
    "arjun": {},
    "nuclei": {},
    "certspotter": {},
    "katana": {},
}


def _runner(
    fake: FakeExecutionEngine,
    *,
    readiness: object | None = None,
    target: str = _TARGET,
    objective: str = "full_security_assessment",
) -> tuple[MissionExecutionService, MissionOrchestrationService, str]:
    """Assemble a runner over real planning/orchestration (deterministic fake engine)."""
    planning = AdaptiveMissionPlanningEngine(
        tool_selection_engine=ToolSelectionEngine(
            mission_type="bug-bounty",
            default_candidates=_DEFAULT_CANDIDATES,
        ),
    )
    orchestrator = MissionOrchestrator(planning=planning)
    orchestration = MissionOrchestrationService(
        engine=MissionOrchestrationEngine(orchestrator=orchestrator),
        stores=InMemoryTidbRepositoryFactory(),
    )
    runner = MissionExecutionService(
        orchestration=orchestration,
        planning=planning,
        execution_engine=fake,
        readiness=readiness,
    )
    mission = orchestration.create_mission(objective=objective, target=target)
    mission.policy = dataclasses.replace(
        mission.policy,
        coverage_target=0.99,
        stop_conditions=(
            StopCondition.COVERAGE_TARGET_ACHIEVED,
            StopCondition.RESOURCE_BUDGET_EXHAUSTED,
        ),
    )
    orchestration.start(mission.mission_id)
    return runner, orchestration, mission.mission_id


class _AdapterDescriptor:
    """Minimal adapter descriptor exposing declared target kinds."""

    def __init__(self, targets: tuple[str, ...], permissions: tuple[str, ...] = ("network",)) -> None:
        self.targets = targets
        self.permissions = permissions


class _AdapterStub:
    """Adapter stub whose descriptor declares the tool's target kinds."""

    def __init__(self, targets: tuple[str, ...]) -> None:
        self.descriptor = _AdapterDescriptor(targets)


class _EngineWithAdapters(FakeExecutionEngine):
    """Fake engine exposing adapter descriptors for target derivation."""

    def __init__(self, outputs: dict[str, dict[str, object]], adapters: dict[str, _AdapterStub]) -> None:
        super().__init__(outputs=outputs)
        self._adapters = adapters

    def adapter_for(self, tool_id: str) -> _AdapterStub | None:
        return self._adapters.get(tool_id)


class _UninformativeEngine(FakeExecutionEngine):
    """Fake engine whose executions produce empty stdout and no JSON."""

    def execute(self, context) -> PipelineResult:  # noqa: ANN001
        self.calls.append(context)
        result = ExecutionResult(
            execution_id=context.execution_id,
            tool_id=context.tool_id,
            status=ExecutionStatus.COMPLETED,
            output=ExecutionOutput(exit_code=0, stdout="", formats={OutputFormat.STDOUT}),
            started_at="2026-01-01T00:00:00Z",
            completed_at="2026-01-01T00:00:01Z",
            duration_ms=10,
        )
        return PipelineResult(result=result, session=ExecutionSession(context), attempts=1)


class _ReadinessService:
    """Readiness double: preflight passes; per-tool probe verdicts from a set."""

    def __init__(self, available: set[str]) -> None:
        self._available = set(available)
        self.checked: list[str] = []

    def preflight(self, capabilities, *, mission_id="", auto_provision=True):  # noqa: ANN001
        from hunterx.tools.readiness.models import PreflightResult, PreflightStatus

        return PreflightResult(status=PreflightStatus.PASS, mission_id=mission_id)

    def check(self, tool_ids=None, *, sync_engine=True):  # noqa: ANN001
        self.checked.extend(tool_ids or [])
        tools = [
            SimpleNamespace(
                tool_id=tool_id,
                status=SimpleNamespace(value="available" if tool_id in self._available else "missing"),
            )
            for tool_id in (tool_ids or [])
        ]
        return SimpleNamespace(tools=tools)


def _coverage_cell(mission, capability: str) -> SimpleNamespace:
    cells = mission.coverage.get(mission.context.target_id or "target", {})
    cell = cells.get(capability)
    if cell is None:
        return SimpleNamespace(state=None, notes="")
    return SimpleNamespace(state=cell.state.value, notes=getattr(cell, "notes", ""))


class TestDefect1TargetNormalization:
    def test_web_and_host_tools_receive_their_declared_target_shape(self) -> None:
        adapters = {
            "subfinder": _AdapterStub(("host", "domain")),
            "dnsx": _AdapterStub(("host", "domain")),
            "nmap": _AdapterStub(("ip", "cidr", "host", "domain")),
            "whatweb": _AdapterStub(("url", "host", "domain", "ip")),
            "httpx": _AdapterStub(("url", "host", "domain", "ip")),
        }
        fake = _EngineWithAdapters(outputs=dict(_MEANINGFUL_OUTPUTS), adapters=adapters)
        runner, orchestration, mission_id = _runner(fake)

        runner.run(mission_id, max_cycles=16)

        by_tool = {context.tool_id: context for context in fake.calls}
        for tool_id in ("subfinder", "dnsx", "nmap"):
            assert by_tool[tool_id].target == "localhost", f"{tool_id} must get the bare host"
            assert by_tool[tool_id].target_type in ("host", "domain", "ip")
        for tool_id in ("whatweb", "httpx"):
            assert by_tool[tool_id].target == _TARGET, f"{tool_id} must get the full URL"
            assert by_tool[tool_id].target_type == "url"


class TestDefect2EmptySuccessIsNotCoverage:
    def test_uninformative_success_is_not_assessed_without_negative_evidence(self) -> None:
        fake = _UninformativeEngine()
        runner, orchestration, mission_id = _runner(fake)

        runner.run(mission_id, max_cycles=8)

        mission = orchestration.get(mission_id)
        coverage = mission.coverage.get(mission.context.target_id or "target", {})
        executed = {call.tool_id for call in fake.calls}
        assert executed, "tools must have run"
        for tool_id in executed:
            capability = next(
                (cell.capability for cell in coverage.values() if cell.tool_id == tool_id),
                None,
            )
            if capability:
                cell = coverage[capability]
                assert cell.state.value == "not_assessed", (
                    f"empty success must not be TESTED (capability {capability})"
                )
                assert "no meaningful evidence" in cell.notes
        assert not mission.negative_evidence, "empty stdout must never manufacture negative evidence"

    def test_explicit_empty_json_result_is_a_validated_negative(self) -> None:
        # A tool that ran and reported a structured empty result (JSON) is an
        # explicit negative: TESTED coverage + a bounded negative record.
        outputs = dict(_EMPTY_OUTPUTS)
        fake = FakeExecutionEngine(outputs=outputs)
        runner, orchestration, mission_id = _runner(fake)

        runner.run(mission_id, max_cycles=8)

        mission = orchestration.get(mission_id)
        tested_negatives = [record for record in mission.negative_evidence if record.kind.value == "tested"]
        assert tested_negatives, "an explicit empty result must record bounded negative evidence"
        assert mission.coverage_ratio() > 0.0


class TestDefect3ReplanRechecksReadiness:
    # The pentest objective chain starts with asset_discovery but omits
    # port_discovery/service_detection: an asset observation replans them in
    # AFTER the preflight gate vetted the initial plan. This mirrors the live
    # failure where nuclei was scheduled after preflight and never re-checked.
    _OBJECTIVE = "pentest_assessment"

    def test_replanned_capability_without_provider_is_not_assessed_with_reason(self) -> None:
        fake = FakeExecutionEngine(outputs=dict(_MEANINGFUL_OUTPUTS))
        # Initial-plan providers are available; the replanned port scanners are not.
        available = {"subfinder", "httpx", "arjun", "nuclei"}
        readiness = _ReadinessService(available)
        runner, orchestration, mission_id = _runner(
            fake,
            readiness=readiness,
            objective=self._OBJECTIVE,
        )

        runner.run(mission_id, max_cycles=16)

        mission = orchestration.get(mission_id)
        executed = {call.tool_id for call in fake.calls}
        assert "nmap" not in executed, "an unready replanned provider must never execute"
        assert "nmap" in readiness.checked, "the replanned provider must have been re-probed"
        cell = _coverage_cell(mission, "port_discovery")
        assert cell.state == CoverageState.NOT_ASSESSED.value, "replanned gap must stay NOT_ASSESSED"
        assert "no available provider" in cell.notes

    def test_replanned_capability_with_provider_executes(self) -> None:
        fake = FakeExecutionEngine(outputs=dict(_MEANINGFUL_OUTPUTS))
        available = {"subfinder", "httpx", "arjun", "nuclei", "nmap"}
        readiness = _ReadinessService(available)
        runner, orchestration, mission_id = _runner(
            fake,
            readiness=readiness,
            objective=self._OBJECTIVE,
        )

        runner.run(mission_id, max_cycles=16)

        executed = {call.tool_id for call in fake.calls}
        assert "nmap" in executed, "a replanned capability with an available provider must execute"
        cell = _coverage_cell(orchestration.get(mission_id), "port_discovery")
        assert cell.state == CoverageState.TESTED.value


class TestDefect5NoPhantomEntities:
    def test_empty_observation_never_creates_target_model_entities(self) -> None:
        fake = _UninformativeEngine()
        runner, orchestration, mission_id = _runner(fake)

        runner.run(mission_id, max_cycles=8)

        mission = orchestration.get(mission_id)
        # The target's root asset is a legitimate entity (Target → Asset); an
        # empty/uninformative observation must never fabricate phantom
        # *discovered* child assets, services, endpoints or technologies.
        assert mission.context.assets, "the URL target must register a root asset"
        assert set(mission.context.assets) == {f"asset:{_TARGET}"}, "no phantom discovered assets"
        assert mission.context.services == {}
        assert mission.context.endpoints == {}
        assert mission.context.technologies == {}
        assert mission.context.technologies == {}
        assert mission.context.services == {}
        assert mission.context.endpoints == {}

    def test_meaningful_observation_creates_entities(self) -> None:
        fake = FakeExecutionEngine(outputs=dict(_MEANINGFUL_OUTPUTS))
        runner, orchestration, mission_id = _runner(fake)

        runner.run(mission_id, max_cycles=8)

        mission = orchestration.get(mission_id)
        assert mission.context.assets
        assert mission.context.technologies
        assert mission.context.services


class TestDefect5EntityExtractionFidelity:
    def test_nested_technology_observations_register_each_technology(self) -> None:
        outputs = dict(_MEANINGFUL_OUTPUTS)
        outputs["whatweb"] = {
            "technologies": [
                {"canonical_name": "Html5", "raw_name": "HTML5", "confidence": 0.1},
                {"canonical_name": "Country", "raw_name": "Country", "confidence": 0.1},
            ]
        }
        fake = FakeExecutionEngine(outputs=outputs)
        runner, orchestration, mission_id = _runner(fake)

        runner.run(mission_id, max_cycles=16)

        technologies = orchestration.get(mission_id).context.technologies
        assert any("Html5" in key for key in technologies), "each reported technology becomes an entity"
        assert any("Country" in key for key in technologies)

    def test_service_observation_registers_named_services_only(self) -> None:
        outputs = dict(_MEANINGFUL_OUTPUTS)
        outputs["nmap"] = {
            "observations": [
                {"type": "host", "address": "127.0.0.1", "state": "reachable"},
                {"type": "port", "protocol": "tcp", "port": 22, "state": "closed", "reason": "conn-refused"},
                {"type": "port", "protocol": "tcp", "port": 135, "state": "open", "reason": "syn-ack"},
                {"type": "service", "protocol": "tcp", "port": 135, "service": "msrpc"},
                {"type": "port", "protocol": "tcp", "port": 445, "state": "open"},
                {"type": "service", "protocol": "tcp", "port": 445, "service": "microsoft-ds"},
            ]
        }
        fake = FakeExecutionEngine(outputs=outputs)
        runner, orchestration, mission_id = _runner(fake)

        runner.run(mission_id, max_cycles=16)

        services = orchestration.get(mission_id).context.services
        assert any("msrpc" in key for key in services)
        assert any("microsoft-ds" in key for key in services)
        assert not any(":22" in key for key in services), "closed ports never become services"
        assert not any(":135" in key for key in services if "msrpc" not in key), (
            "a named fingerprint supersedes its bare open-port entry"
        )

    def test_open_port_without_fingerprint_is_registered(self) -> None:
        outputs = dict(_MEANINGFUL_OUTPUTS)
        outputs["nmap"] = {
            "observations": [{"type": "port", "protocol": "tcp", "port": 8080, "state": "open"}]
        }
        fake = FakeExecutionEngine(outputs=outputs)
        runner, orchestration, mission_id = _runner(fake)

        runner.run(mission_id, max_cycles=16)

        services = orchestration.get(mission_id).context.services
        assert any("8080" in key for key in services), "an open port without a fingerprint is still a service"

    def test_plain_port_list_registers_open_services(self) -> None:
        outputs = dict(_MEANINGFUL_OUTPUTS)
        outputs["nmap"] = {"ports": [80, 3010]}
        fake = FakeExecutionEngine(outputs=outputs)
        runner, orchestration, mission_id = _runner(fake)

        runner.run(mission_id, max_cycles=16)

        services = orchestration.get(mission_id).context.services
        assert any("80" in key for key in services)
        assert any("3010" in key for key in services)

    def test_live_url_without_fingerprint_becomes_endpoint_evidence(self) -> None:
        outputs = dict(_MEANINGFUL_OUTPUTS)
        outputs["httpx"] = {
            "technologies": [
                {
                    "asset": "http://localhost:3010",
                    "asset_type": "url",
                    "raw_name": "http://localhost:3010",
                    "canonical_name": "http://localhost:3010",
                    "confidence": 0.4,
                }
            ],
            "count": 1,
        }
        fake = FakeExecutionEngine(outputs=outputs)
        runner, orchestration, mission_id = _runner(fake)

        runner.run(mission_id, max_cycles=16)

        endpoints = orchestration.get(mission_id).context.endpoints
        assert any("http://localhost:3010" in key for key in endpoints), (
            "a live URL reported without a fingerprint is an endpoint, not an empty result"
        )

    def test_empty_endpoint_result_never_registers_the_target_as_endpoint(self) -> None:
        outputs = dict(_MEANINGFUL_OUTPUTS)
        outputs["httpx"] = {"technologies": [], "count": 0}
        fake = FakeExecutionEngine(outputs=outputs)
        runner, orchestration, mission_id = _runner(fake)

        runner.run(mission_id, max_cycles=16)

        endpoints = orchestration.get(mission_id).context.endpoints
        assert not any("localhost:3010" in key for key in endpoints), (
            "an empty endpoint result must not fabricate the target as an endpoint"
        )


class TestDefect6ObservationToHypothesis:
    def test_meaningful_observations_create_hypotheses(self) -> None:
        fake = FakeExecutionEngine(outputs=dict(_MEANINGFUL_OUTPUTS))
        runner, orchestration, mission_id = _runner(fake)

        runner.run(mission_id, max_cycles=16)

        mission = orchestration.get(mission_id)
        assert mission.hypotheses, "meaningful observations must produce hypotheses"
        statements = [hypothesis.statement for hypothesis in mission.hypotheses]
        assert any("may be affected by" in statement for statement in statements), "vulnerability evidence must hypothesize"

    def test_empty_observations_create_no_hypotheses(self) -> None:
        fake = _UninformativeEngine()
        runner, orchestration, mission_id = _runner(fake)

        runner.run(mission_id, max_cycles=8)

        assert orchestration.get(mission_id).hypotheses == []

    def test_vulnerability_observation_produces_candidate_finding(self) -> None:
        fake = FakeExecutionEngine(outputs=dict(_MEANINGFUL_OUTPUTS))
        runner, orchestration, mission_id = _runner(fake)

        runner.run(mission_id, max_cycles=16)

        findings = orchestration.get(mission_id).context.findings
        assert findings, "a vulnerability observation must record a finding"
        # Finding honesty: a finding is never report-ready merely because a tool
        # ran once. It may only reach ``verified`` when its explaining
        # hypothesis was validated by an independent confirmation probe.
        assert all(finding.get("stage") in ("candidate", "verified") for finding in findings)
        assert not any(finding.get("stage") in ("proven", "report_ready") for finding in findings)
        verified = [finding for finding in findings if finding.get("stage") == "verified"]
        if verified:
            validated = [
                hypothesis
                for hypothesis in orchestration.get(mission_id).hypotheses
                if hypothesis.state.value == "validated"
            ]
            assert validated, "verified findings must be backed by a validated hypothesis"


class TestDefect7PhaseAdvancement:
    def test_phase_advances_past_target_modeling_after_observation(self) -> None:
        fake = FakeExecutionEngine(outputs=dict(_MEANINGFUL_OUTPUTS))
        runner, orchestration, mission_id = _runner(fake)

        mission = orchestration.get(mission_id)
        assert mission.current_phase is MissionPhase.TARGET_MODELING or mission.current_phase.value == "target_modeling"

        runner.run(mission_id, max_cycles=16)

        mission = orchestration.get(mission_id)
        # The phase reflects the workflow state — it is never stuck at
        # target_modeling after meaningful discovery. An assessment that cannot
        # discharge its actionable hypotheses stops at the last genuine phase
        # (blocked), never a false reporting.
        assert mission.current_phase.value != "target_modeling"
        assert mission.outcome is not None

    def test_phase_tracks_planning_state_during_execution(self) -> None:
        fake = FakeExecutionEngine(outputs=dict(_MEANINGFUL_OUTPUTS))
        runner, orchestration, mission_id = _runner(fake)

        runner.execute_cycle(mission_id)

        mission = orchestration.get(mission_id)
        expected = "reconnaissance"  # DISCOVERY state -> RECONNAISSANCE phase
        assert mission.current_phase.value == expected


class TestDefect8RunFinalization:
    def test_run_is_finalized_and_idempotent(self) -> None:
        fake = FakeExecutionEngine(outputs=dict(_MEANINGFUL_OUTPUTS))
        runner, orchestration, mission_id = _runner(fake)

        first = runner.run(mission_id, max_cycles=16)
        mission = orchestration.get(mission_id)

        # The runner finalizes every terminal exit: a run record, an outcome and
        # a finished timestamp. On a non-loopback target with unprobeable
        # actionable hypotheses the planning state is the honest BLOCKED, never
        # a false coverage-complete.
        assert first["planning_state"] in ("completed", "blocked")
        assert mission.outcome is not None
        assert mission.runs[-1].status.value == "completed"
        assert mission.runs[-1].finished_at

        # Idempotent: a second run must not raise or corrupt the outcome.
        second = runner.run(mission_id, max_cycles=16)
        mission = orchestration.get(mission_id)
        assert second["planning_state"] in ("completed", "blocked")
        assert mission.outcome is not None

    def test_idle_cycle_termination_finalizes(self) -> None:
        fake = FakeExecutionEngine(outputs=dict(_MEANINGFUL_OUTPUTS))
        runner, orchestration, mission_id = _runner(fake)

        result = runner.run(mission_id, max_cycles=4, max_idle_cycles=2)

        mission = orchestration.get(mission_id)
        # The run finalizes deterministically, but with the objectives still
        # incomplete the truthful terminal is BLOCKED — never "completed".
        assert result["status"] == "blocked"
        assert mission.outcome is not None
        assert mission.outcome.objectives_complete is False
        assert mission.mission.state.value == "blocked"
        assert mission.runs[-1].finished_at

    def test_finalize_after_unrecoverable_failure(self) -> None:
        fake = FakeExecutionEngine(
            outputs=dict(_MEANINGFUL_OUTPUTS),
            fail_tools=("subfinder",),
            error="Failed to start tool binary 'subfinder'",
        )
        runner, orchestration, mission_id = _runner(fake)

        runner.run(mission_id, max_cycles=4)

        mission = orchestration.get(mission_id)
        assert mission.mission.state.value == "blocked", "even a failing mission finalizes to an honest blocked terminal"
        assert mission.runs[-1].finished_at
