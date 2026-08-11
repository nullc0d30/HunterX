# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Persistence integration tests for the Autonomous Mission Orchestration.

Builds the SQL TIDB repository factory over SQLite and verifies the new
orchestration entities round-trip through the generic repository: mission,
runs, policies, objectives, observations, hypotheses, decisions, negative
evidence, coverage, baselines, checkpoints, branches and impact analyses.
"""

from __future__ import annotations

import pytest

pytest.importorskip("sqlalchemy")

from hunterx.application.mission_orchestration import (
    MissionOrchestrationQueryService,
    MissionOrchestrationService,
)
from hunterx.domain.entities.tidb.mission_orchestration import (
    MissionBaselineRecord,
    MissionBranchRecord,
    MissionCheckpointRecord,
    MissionCoverageRecord,
    MissionDecisionRecord,
    MissionHypothesisRecord,
    MissionImpactRecord,
    MissionNegativeRecord,
    MissionObservationRecord,
    MissionOrchestrationRecord,
    MissionPolicyRecord,
    MissionRunRecord,
)
from hunterx.domain.mission_orchestration.decision import CandidateAction
from hunterx.engines.mission_orchestration import MissionOrchestrationEngine
from hunterx.infrastructure.db.sql.crud import SqlTidbRepositoryFactory
from hunterx.infrastructure.db.sql.factory import SessionFactory


@pytest.fixture()
def session_factory(tmp_path: object) -> SessionFactory:
    from hunterx.config.settings import DatabaseSettings

    settings = DatabaseSettings(url=f"sqlite:///{tmp_path}/mission_orch_integration.db")
    factory = SessionFactory(settings)
    factory.create_all()
    return factory


class TestMissionPersistence:
    def test_entities_round_trip(self, session_factory: SessionFactory) -> None:
        stores = SqlTidbRepositoryFactory(session_factory)
        service = MissionOrchestrationService(
            engine=MissionOrchestrationEngine(),
            stores=stores,
        )
        mission = service.create_mission(target="https://example.com")
        mission_id = mission.mission_id
        service.start(mission_id)

        # observation
        service.ingest_result(
            mission_id,
            tool_id="httpx",
            asset_key="https://example.com",
            raw={"observation_type": "service", "content": {"status": 200}},
        )
        # hypothesis
        service.add_hypothesis(mission_id, statement="SQLi on search", category="injection")
        # decision
        service.decide_next(
            mission_id,
            candidates=(
                CandidateAction(action_id="a1", capability="recon", tool_ids=("subfinder",), expected_information_gain=0.8),
            ),
        )
        # negative evidence + coverage + baseline + branch + impact
        service.record_negative(mission_id, asset_key="https://example.com/search", capability="xss", tool_id="dalfox", input="<script>", outcome="none")
        service.record_coverage(mission_id, asset_key="https://example.com/search", capability="sql_injection", state="validated", tool_id="sqlmap")
        service.capture_baseline(mission_id, asset_key="https://example.com/search", status_code=200, content_length=100)
        service.fork_branch(mission_id, hypothesis_id="h1", rationale="fork")
        finding = service.register_finding(
            mission_id,
            finding_id="F1",
            vulnerability_class="sql_injection",
            asset_key="https://example.com/search",
            stage="proven",
        )
        service.analyze_impact(mission_id, finding=finding, confidence=0.9)
        service.checkpoint(mission_id, label="persist")

        query = MissionOrchestrationQueryService(stores=stores)
        assert query.mission(mission_id) is not None
        assert len(query.observations(mission_id)) == 1
        assert len(query.hypotheses(mission_id)) == 1
        assert len(query.decisions(mission_id)) == 1
        assert len(query.negative_evidence(mission_id)) == 1
        assert len(query.coverage(mission_id)) == 1
        assert len(query.checkpoints(mission_id)) == 1
        assert len(query.impact_analyses(mission_id)) == 1

        # each entity repo resolves the ORM model via the registry
        for entity_cls in (
            MissionOrchestrationRecord,
            MissionRunRecord,
            MissionPolicyRecord,
            MissionObservationRecord,
            MissionHypothesisRecord,
            MissionDecisionRecord,
            MissionNegativeRecord,
            MissionCoverageRecord,
            MissionBaselineRecord,
            MissionBranchRecord,
            MissionCheckpointRecord,
            MissionImpactRecord,
        ):
            repo = stores.repository_for(entity_cls)
            assert repo.count() >= 1


class TestMissionRestore:
    def test_mission_restores_from_tidb_in_fresh_engine(self, session_factory: SessionFactory) -> None:
        """A persisted mission hydrates into a fresh engine (restart path).

        This is the fix for the cross-invocation CLI workflow: ``mission create``
        then ``mission start <id>`` in a separate process (fresh in-memory
        orchestrator) must still work when the TIDB holds the mission.
        """
        stores = SqlTidbRepositoryFactory(session_factory)
        creator = MissionOrchestrationService(
            engine=MissionOrchestrationEngine(),
            stores=stores,
        )
        mission = creator.create_mission(objective="full_security_assessment", target="https://example.com")
        mission_id = mission.mission_id

        # Simulate a separate invocation: a brand-new engine/service with the
        # same persisted TIDB store must be able to resolve and start the
        # mission.
        restarted = MissionOrchestrationService(
            engine=MissionOrchestrationEngine(),
            stores=stores,
        )
        restored = restarted.get(mission_id)
        assert restored.mission_id == mission_id
        assert restored.policy.objective_name == "full_security_assessment"
        assert restored.context.target_id == "https://example.com"

        result = restarted.start(mission_id)
        assert result["mission_id"] == mission_id
        assert len(restored.runs) == 1

    def test_restore_raises_for_unknown_mission(self, session_factory: SessionFactory) -> None:
        from hunterx.domain.exceptions.adaptive_mission_planning import AdaptiveMissionNotFoundError

        stores = SqlTidbRepositoryFactory(session_factory)
        service = MissionOrchestrationService(
            engine=MissionOrchestrationEngine(),
            stores=stores,
        )
        with pytest.raises(AdaptiveMissionNotFoundError):
            service.get("does-not-exist")
