# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Phase 13 deep coverage regression tests.

A validated finding is an OUTPUT, never a stop: the mission must continue
assessing the remaining high-value hypotheses and attack paths until the
assessment is genuinely complete (all high-value hypotheses resolved/refuted,
plan discharged, or budget exhausted). These tests prove, end-to-end against
the loopback vulnerable fixture:

    1. The first validated finding does not terminate the mission while
       unresolved high-value hypotheses remain (policy gate + run loop).
    2. The planner continues after a validated finding: unrelated hypotheses
       remain schedulable and are probed (honest negative, never skipped).
    3. Refuted hypotheses are never reprobed (one bound validation action,
       one tested action).
    4. The mission terminates honestly when work is exhausted.
    5. A zero-finding mission also terminates honestly (no hang, and
       FINDINGS_VALIDATED can never fire with zero findings).
    6. Duplicate hypotheses are idempotent by statement (merged evidence,
       one hypothesis).
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


def _runner(
    app: VulnerableApp,
    payload: dict,
) -> tuple[MissionExecutionService, MissionOrchestrationService, AdaptiveMissionPlanningEngine, str]:
    """Assemble a real runner over real planning/orchestration/finding service."""
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
    return runner, orchestration, planning, mission.mission_id


def _candidate(endpoint: str, class_id: str, parameter: str) -> dict:
    return {
        "vulnerability_class": class_id,
        "endpoint": endpoint,
        "parameter": parameter,
        "severity": "medium",
    }


class TestFindingsNeverStopTheHunt:
    def test_mission_continues_assessment_after_first_validated_finding(self, app: VulnerableApp) -> None:
        payload = {
            "candidates": [
                _candidate(f"{app.base_url}/vuln/search", "sql-injection", "q"),
                _candidate(f"{app.base_url}/safe/search", "sql-injection", "q"),
            ],
            "count": 2,
        }
        runner, orchestration, _, mission_id = _runner(app, payload)
        runner.run(mission_id, max_cycles=16)
        mission = orchestration.get(mission_id)

        assert mission.outcome is not None
        assert mission.outcome.findings_validated == 1
        validated = [
            finding
            for finding in mission.context.findings
            if finding.get("stage") in ("verified", "proven", "report_ready")
        ]
        assert len(validated) == 1
        assert any("/vuln/search" in str(finding.get("asset_key", "")) for finding in validated)
        refuted = [h for h in mission.hypotheses if h.state.value == "refuted"]
        assert any("/safe/search" in h.statement for h in refuted), mission.hypotheses
        assert all(h.state.is_terminal for h in mission.hypotheses)
        terminal = [
            finding
            for finding in mission.context.findings
            if finding.get("stage") in ("verified", "proven", "report_ready")
        ]
        assert len(terminal) == 1

    def test_zero_finding_mission_terminates_honestly(self, app: VulnerableApp) -> None:
        payload = {
            "candidates": [_candidate(f"{app.base_url}/safe/search", "sql-injection", "q")],
            "count": 1,
        }
        runner, orchestration, _, mission_id = _runner(app, payload)
        summary = runner.run(mission_id, max_cycles=16)
        mission = orchestration.get(mission_id)

        assert mission.outcome is not None
        assert mission.outcome.findings_validated == 0
        assert summary["status"] == "completed"
        assert all(h.state.is_terminal for h in mission.hypotheses)

    def test_refuted_hypothesis_is_not_reprobed(self, app: VulnerableApp) -> None:
        payload = {
            "candidates": [_candidate(f"{app.base_url}/safe/search", "sql-injection", "q")],
            "count": 1,
        }
        runner, orchestration, planning, mission_id = _runner(app, payload)
        runner.run(mission_id, max_cycles=16)
        mission = orchestration.get(mission_id)

        refuted = [h for h in mission.hypotheses if h.state.value == "refuted"]
        assert len(refuted) == 1
        hypothesis = refuted[0]
        assert len(hypothesis.tested_actions) == 1
        plan = planning.get_plan(mission_id)
        bound = [action for action in plan.actions.values() if action.hypothesis_id == hypothesis.hypothesis_id]
        assert len(bound) == 1

    def test_duplicate_hypotheses_idempotent_by_statement(self) -> None:
        stores = InMemoryTidbRepositoryFactory()
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
        mission = orchestration.create_mission(objective="bug_bounty_assessment", target="http://localhost:3010")
        statement = "The /vuln/search q parameter may be susceptible to SQL injection"
        first = orchestration.add_hypothesis(mission.mission_id, statement=statement, category="injection", supporting=("ev1",))
        second = orchestration.add_hypothesis(mission.mission_id, statement=statement, category="injection", supporting=("ev2",))

        assert first["hypothesis_id"] == second["hypothesis_id"]
        mission = orchestration.get(mission.mission_id)
        matching = [h for h in mission.hypotheses if h.statement == statement]
        assert len(matching) == 1
        assert "ev1" in matching[0].supporting_evidence
        assert "ev2" in matching[0].supporting_evidence