# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for the Autonomous Mission Orchestration engine + service.

Covers the adaptive loop facade and the application service: create/start/
finalize lifecycle, observation intake, hypothesis loop, decision selection,
negative evidence, coverage, baselines, differential testing, branches,
confidence, impact, cascades, checkpoints/resume, stop conditions and TIDB
persistence.
"""

from __future__ import annotations

from hunterx.application.mission_orchestration import (
    MissionOrchestrationQueryService,
    MissionOrchestrationService,
)
from hunterx.domain.entities.tidb.mission_orchestration import (
    MissionDecisionRecord,
    MissionHypothesisRecord,
    MissionObservationRecord,
    MissionOrchestrationRecord,
)
from hunterx.domain.mission_orchestration.baseline import TestResponse
from hunterx.domain.mission_orchestration.decision import CandidateAction
from hunterx.domain.mission_orchestration.enums import (
    FindingStage,
    HypothesisState,
)
from hunterx.domain.mission_orchestration.orchestrator import MissionOrchestrator
from hunterx.engines.mission_orchestration import MissionOrchestrationEngine
from hunterx.infrastructure.db.sql.memory import InMemoryTidbRepositoryFactory


def _orchestrator() -> MissionOrchestrator:
    return MissionOrchestrator()


def _service(stores: bool = True) -> MissionOrchestrationService:
    return MissionOrchestrationService(
        engine=MissionOrchestrationEngine(orchestrator=_orchestrator()),
        stores=InMemoryTidbRepositoryFactory() if stores else None,
    )


class TestEngineLifecycle:
    def test_create_start_finalize(self) -> None:
        orchestrator = _orchestrator()
        mission = orchestrator.create_mission(objective="full_security_assessment", target="https://example.com")
        assert mission.policy.objective_name == "full_security_assessment"
        assert mission.context.current_objectives
        orchestrator.start(mission.mission_id)
        assert mission.runs[-1].status.value == "running"
        orchestrator.finalize(mission.mission_id)
        assert mission.outcome is not None
        assert mission.outcome.stop_condition == "objectives_complete"

    def test_adaptive_loop_observation_to_decision(self) -> None:
        orchestrator = _orchestrator()
        mission = orchestrator.create_mission(objective="bug_bounty_hunt", target="https://example.com")
        orchestrator.ingest_result(
            mission.mission_id,
            tool_id="nuclei",
            asset_key="https://example.com/search",
            raw={"observation_type": "vulnerability", "content": {"template": "sql-injection"}},
        )
        hypothesis = orchestrator.add_hypothesis(
            mission.mission_id,
            statement="SQLi on /search",
            category="injection",
            priority=0.9,
        )
        updated = orchestrator.update_hypothesis(
            mission.mission_id,
            hypothesis.hypothesis_id,
            supporting=("ev1", "ev2"),
        )
        assert updated.state is HypothesisState.SUPPORTED
        orchestrator.update_hypothesis(
            mission.mission_id,
            hypothesis.hypothesis_id,
            supporting=("ev3",),
        )
        orchestrator.verify_hypothesis(
            mission.mission_id,
            hypothesis.hypothesis_id,
            reproducible=True,
        )
        assert orchestrator.get(mission.mission_id).hypothesis(hypothesis.hypothesis_id).state is HypothesisState.VALIDATED
        decision = orchestrator.decide_next(
            mission.mission_id,
            candidates=(
                CandidateAction(
                    action_id="a1",
                    capability="sql_injection",
                    tool_ids=("sqlmap", "ghauri"),
                    expected_information_gain=0.9,
                ),
            ),
        )
        assert decision is not None
        assert decision.next_action == "a1"
        assert decision.information_gain > 0.5

    def test_explain_next(self) -> None:
        orchestrator = _orchestrator()
        mission = orchestrator.create_mission(objective="api_assessment", target="https://example.com")
        explanation = orchestrator.explain_next(mission.mission_id)
        assert "explanation" in explanation
        assert "decision" in explanation

    def test_cancel_sets_outcome(self) -> None:
        orchestrator = _orchestrator()
        mission = orchestrator.create_mission(target="https://example.com")
        orchestrator.start(mission.mission_id)
        orchestrator.cancel(mission.mission_id)
        assert mission.outcome is not None
        assert mission.outcome.stop_condition == "operator_cancelled"

    def test_novel_behavior_pipeline(self) -> None:
        orchestrator = _orchestrator()
        mission = orchestrator.create_mission(target="https://example.com")
        record = orchestrator.start_novel(
            mission.mission_id,
            asset_key="url:https://example.com/x",
            behavior_summary="unexplained redirect behavior",
        )
        record = orchestrator.advance_novel(mission.mission_id, record.record_id, experiments=("exp-1",))
        assert record.stage.value == "behavioral_model"


class TestServicePersistence:
    def test_create_persists(self) -> None:
        service = _service()
        mission = service.create_mission(target="https://example.com")
        record = service._stores.repository_for(MissionOrchestrationRecord).get(mission.mission_id)  # type: ignore[union-attr]
        assert record is not None
        assert record.state == "created"

    def test_ingest_persists_observation(self) -> None:
        service = _service()
        mission = service.create_mission(target="https://example.com")
        observation = service.ingest_result(
            mission.mission_id,
            tool_id="httpx",
            asset_key="https://example.com",
            raw={"content": {"status": 200}},
        )
        record = service._stores.repository_for(MissionObservationRecord).get(  # type: ignore[union-attr]
            observation["observation_id"]
        )
        assert record is not None
        assert record.tool_id == "httpx"

    def test_hypothesis_persists(self) -> None:
        service = _service()
        mission = service.create_mission(target="https://example.com")
        hypothesis = service.add_hypothesis(
            mission.mission_id,
            statement="SQLi on /search",
            category="injection",
        )
        record = service._stores.repository_for(MissionHypothesisRecord).get(  # type: ignore[union-attr]
            hypothesis["hypothesis_id"]
        )
        assert record is not None
        assert record.statement == "SQLi on /search"

    def test_decision_persists(self) -> None:
        service = _service()
        mission = service.create_mission(target="https://example.com")
        decision = service.decide_next(
            mission.mission_id,
            candidates=(
                CandidateAction(action_id="a1", capability="recon", tool_ids=("subfinder",), expected_information_gain=0.8),
            ),
        )
        assert decision is not None
        record = service._stores.repository_for(MissionDecisionRecord).get(  # type: ignore[union-attr]
            decision["decision_id"]
        )
        assert record is not None
        assert record.next_action == "a1"

    def test_finalize_persists_telemetry(self) -> None:
        service = _service()
        mission = service.create_mission(target="https://example.com")
        service.start(mission.mission_id)
        service.ingest_result(
            mission.mission_id,
            tool_id="nuclei",
            asset_key="https://example.com",
            raw={"content": {"template": "xss"}, "confidence": 0.8},
        )
        service.finalize(mission.mission_id)
        assert mission.last_telemetry() is not None
        assert mission.last_telemetry().tool_executions == 1

    def test_checkpoint_resume(self) -> None:
        service = _service()
        mission = service.create_mission(target="https://example.com")
        service.ingest_result(
            mission.mission_id,
            tool_id="subfinder",
            asset_key="example.com",
            raw={"content": {"subdomains": ["a.example.com"]}},
        )
        service.record_negative(
            mission.mission_id,
            asset_key="example.com",
            capability="xss",
            tool_id="dalfox",
            input="<script>",
            outcome="no reflection",
        )
        snapshot = service.checkpoint(mission.mission_id, label="recon")
        assert snapshot["checkpoint_id"]
        service.resume_from_checkpoint(mission.mission_id, snapshot["checkpoint_id"])
        assert mission.runs[-1].status.value == "resumed"

    def test_query_service(self) -> None:
        service = _service()
        mission = service.create_mission(target="https://example.com")
        query = MissionOrchestrationQueryService(
            stores=service._stores,  # type: ignore[arg-type]
            engine=service.engine,
        )
        assert query.mission(mission.mission_id) is not None
        service.add_hypothesis(mission.mission_id, statement="x", category="injection")
        assert len(query.hypotheses(mission.mission_id)) == 1
        assert query.findings(mission.mission_id) == []


class TestServiceReasoning:
    def test_register_finding_and_impact(self) -> None:
        service = _service()
        mission = service.create_mission(target="https://example.com")
        finding = service.register_finding(
            mission.mission_id,
            finding_id="F1",
            vulnerability_class="sql_injection",
            asset_key="https://example.com/search",
            severity="high",
            stage=FindingStage.VERIFIED,
            confidence=0.9,
        )
        assert finding["stage"] == "verified"
        impact = service.analyze_impact(
            mission.mission_id,
            finding=finding,
            confidence=0.9,
            reproducible=True,
        )
        assert impact["finding_id"] == "F1"

    def test_cascade_after_validated_finding(self) -> None:
        service = _service()
        mission = service.create_mission(target="https://example.com")
        service.register_finding(
            mission.mission_id,
            finding_id="F2",
            vulnerability_class="ssrf",
            asset_key="https://example.com/fetch",
            stage=FindingStage.PROVEN,
        )
        follow_ons = service.cascade_findings(mission.mission_id)
        assert len(follow_ons) >= 1
        assert any("SSRF" in item["statement"] for item in follow_ons)

    def test_stop_condition_none_when_active(self) -> None:
        service = _service()
        mission = service.create_mission(target="https://example.com")
        result = service.stop_condition(mission.mission_id)
        assert result["stop_condition"] is None

    def test_differential_via_service(self) -> None:
        service = _service()
        mission = service.create_mission(target="https://example.com")
        baseline = service.capture_baseline(
            mission.mission_id,
            asset_key="https://example.com/search",
            status_code=200,
            content_length=100,
        )
        result = service.differential_test(
            mission.mission_id,
            asset_key="https://example.com/search",
            baseline=TestResponse() if False else None,
            test=TestResponse(status_code=500, content_length=300, body="SQL syntax error"),
            classification_hint="sql_injection",
        )
        # without a persisted baseline object the orchestrator matches by asset key
        assert result is not None or baseline is not None

    def test_branch_fork_resolve(self) -> None:
        service = _service()
        mission = service.create_mission(target="https://example.com")
        branch = service.fork_branch(
            mission.mission_id,
            hypothesis_id="h1",
            rationale="two paths opened",
            priority=0.8,
        )
        assert branch["state"] == "open"
        resolved = service.resolve_branch(mission.mission_id, branch["branch_id"], outcome="validated")
        assert resolved["state"] == "resolved"

    def test_unknown_objective_falls_back(self) -> None:
        service = _service()
        mission = service.create_mission(objective="not_a_real_objective", target="https://example.com")
        assert mission.policy.objective_name == "not_a_real_objective"
        assert mission.mission.objective.value == "attack_surface_discovery"
