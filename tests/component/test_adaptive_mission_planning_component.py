# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Component tests for the Adaptive Mission & Attack-Path Planning subsystem.

Exercises the full service flow with in-memory TIDB stores: create → plan →
candidates → replan → attack paths → gaps → checkpoints, verifying events are
published and persisted records round-trip.
"""

from __future__ import annotations

from hunterx.application.adaptive_mission_planning import (
    AdaptiveMissionPlanningQueryService,
    AdaptiveMissionPlanningService,
)
from hunterx.domain.adaptive_mission_planning.enums import (
    ReplanTrigger,
)
from hunterx.engines.adaptive_mission_planning.engine import AdaptiveMissionPlanningEngine
from hunterx.infrastructure.db.sql.memory import InMemoryTidbRepositoryFactory
from hunterx.infrastructure.event_bus import InMemoryEventBus


def _build() -> tuple[AdaptiveMissionPlanningService, AdaptiveMissionPlanningQueryService, InMemoryEventBus, object]:
    from hunterx.infrastructure.event_bus.store import InMemoryEventStore

    stores = InMemoryTidbRepositoryFactory()
    bus = InMemoryEventBus()
    event_store = InMemoryEventStore()
    bus.attach_store(event_store)
    service = AdaptiveMissionPlanningService(engine=AdaptiveMissionPlanningEngine(), stores=stores, event_bus=bus)
    query = AdaptiveMissionPlanningQueryService(stores=stores)
    return service, query, bus, event_store


class TestAdaptiveMissionComponent:
    def test_full_lifecycle(self) -> None:
        service, query, bus, events = _build()
        mission = service.create_mission(objective="pentest_assessment", target="example.com")

        # events published
        assert "mission.plan.created" in {e["event_type"] for e in events.list()}

        # persisted
        assert query.mission(mission.mission_id) is not None
        assert query.actions(mission.mission_id)

        # replan on new asset
        delta = service.replan(
            mission.mission_id,
            trigger=ReplanTrigger.NEW_ASSET_DISCOVERED,
            asset_key="host:api.example.com",
            reason="found api subdomain",
        )
        assert delta.plan_version == 2
        assert len(query.actions(mission.mission_id)) == len(service.graph(mission.mission_id))

        # decision + proposal + approval
        result = service.candidate_actions(mission.mission_id)
        assert result.proposals
        scheduled = service.propose_actions(mission.mission_id, result)
        assert scheduled
        service.approve_action(mission.mission_id, scheduled[0].action.action_id)

        # checkpoint + resume
        checkpoint = service.checkpoint_create(mission.mission_id)
        service.resume_from_checkpoint(mission.mission_id, checkpoint.checkpoint_id)

        # coverage + gaps
        coverage = service.coverage(mission.mission_id)
        assert coverage["action_count"] > 0
        assert service.evidence_gaps(mission.mission_id) == []
        assert service.proof_gaps(mission.mission_id) == []

    def test_attack_paths_persist(self) -> None:
        from hunterx.domain.target_intelligence.graph import AttackSurfaceGraph
        from hunterx.domain.target_intelligence.models import IntelligenceAsset
        from hunterx.domain.topology.enums import EntityKind

        service, query, _, _ = _build()
        mission = service.create_mission()
        surface = AttackSurfaceGraph()
        for kind, key in (
            (EntityKind.URL, "url:http://app.example.com"),
            (EntityKind.IP, "ip:203.0.113.5"),
        ):
            surface.upsert_asset(
                IntelligenceAsset(
                    asset_id=key,
                    target_id="t1",
                    mission_id=mission.mission_id,
                    kind=kind,
                    name=key.split(":", 1)[1],
                    key=key,
                    in_scope=True,
                )
            )
        paths = service.discover_attack_paths(mission.mission_id, surface)
        # attack paths are intelligence; they never trigger execution
        assert isinstance(paths, list)
        assert query.attack_paths(mission.mission_id) is not None

    def test_query_service_reads_persisted_state(self) -> None:
        service, query, _, _ = _build()
        mission = service.create_mission(objective="api_security_assessment")
        assert query.actions(mission.mission_id)
        assert query.plan_versions(mission.mission_id)
        assert query.checkpoints(mission.mission_id) == []
