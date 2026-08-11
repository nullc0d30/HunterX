# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Component tests for the TargetMemoryService application layer.

Exercises the service against the in-memory TIDB repository factory and the
event bus: observation history persistence with first/last seen merge,
snapshot reproduction and deterministic diffing, mission/hypothesis/tool/risk/
finding memory, campaigns, revalidation, coverage gaps, recommendations,
planner context and typed event publishing.
"""

from __future__ import annotations

from hunterx.application.target_memory import TargetMemoryQueryService, TargetMemoryService
from hunterx.domain.target_memory.enums import (
    DiffChangeKind,
    HypothesisOutcome,
)
from hunterx.domain.target_memory.models import (
    FindingMemory,
    HypothesisMemory,
    MissionMemory,
    ToolObservation,
)
from hunterx.infrastructure.db.sql.memory import InMemoryTidbRepositoryFactory

NOW = "2026-08-10T00:00:00+00:00"


def _obs(**overrides: object) -> dict[str, object]:
    values: dict[str, object] = {
        "target_id": "t1",
        "mission_id": "m1",
        "tool": "nmap",
        "observation_type": "port",
        "value": "80/tcp",
        "normalized_value": "80/tcp",
        "asset_key": "hostname:www.example.com",
        "source": "nmap-parser",
        "confidence": 1.0,
        "timestamp": "2026-08-01T00:00:00+00:00",
        "expires_at": None,
    }
    values.update(overrides)
    return values


def _make_service() -> tuple[TargetMemoryService, TargetMemoryQueryService, InMemoryTidbRepositoryFactory]:
    stores = InMemoryTidbRepositoryFactory()
    from hunterx.infrastructure.event_bus import InMemoryEventBus

    bus = InMemoryEventBus()
    service = TargetMemoryService(stores=stores, event_bus=bus, tenant="tenant-a", now=NOW)
    query = TargetMemoryQueryService(stores=stores)
    service.authorize(tenant="tenant-a", target_id="t1")
    return service, query, stores


class TestObservationHistory:
    def test_first_seen_survives_across_missions(self) -> None:
        service, query, _ = _make_service()
        service.record_observations("t1", [_obs(timestamp="2026-08-01T00:00:00+00:00")], mission_id="m1", tenant="tenant-a")
        service.record_observations(
            "t1", [_obs(timestamp="2026-08-05T00:00:00+00:00", mission_id="m2")], mission_id="m2", tenant="tenant-a"
        )
        memory = query.memory("t1")
        observation = memory.observations["port:80/tcp"]
        assert observation.observation_count == 2
        assert observation.first_seen == "2026-08-01T00:00:00+00:00"
        assert observation.last_seen == "2026-08-05T00:00:00+00:00"
        assert observation.first_mission == "m1"
        assert observation.last_mission == "m2"
        assert len(query.observation_history("t1")) == 1

    def test_snapshot_diff_detects_changes(self) -> None:
        service, query, _ = _make_service()
        service.record_observations("t1", [_obs(value="80/tcp", normalized_value="80/tcp")], mission_id="m1", tenant="tenant-a")
        snap_a = service.create_snapshot("t1", mission_id="m1", tenant="tenant-a")
        service.record_observations(
            "t1",
            [_obs(value="443/tcp", normalized_value="443/tcp", mission_id="m2")],
            mission_id="m2",
            tenant="tenant-a",
        )
        snap_b = service.create_snapshot("t1", mission_id="m2", tenant="tenant-a")
        diff = service.diff_snapshots(snap_a.snapshot_id, snap_b.snapshot_id, tenant="tenant-a")
        added = [change for change in diff.changes if change.kind == DiffChangeKind.ADDED]
        assert any(change.key == "port:443/tcp" for change in added)
        assert query.diffs("t1")
        assert query.changes("t1")

    def test_snapshot_is_reproducible(self) -> None:
        service, query, _ = _make_service()
        service.record_observations("t1", [_obs()], mission_id="m1", tenant="tenant-a")
        first = service.create_snapshot("t1", mission_id="m1", tenant="tenant-a")
        second = service.create_snapshot("t1", mission_id="m1", tenant="tenant-a")
        assert first.state_hash == second.state_hash


class TestMissionHypothesisToolMemory:
    def test_mission_memory_persists(self) -> None:
        service, query, _ = _make_service()
        service.record_mission_memory(
            MissionMemory(
                mission_id="m1",
                target_id="t1",
                scope="example.com",
                tools_used=["nmap", "httpx"],
                assets_discovered=["hostname:www.example.com"],
                findings_discovered=["f1"],
                failed_hypotheses=["h1"],
                successful_hypotheses=["h2"],
                coverage_achieved={"port_discovery": 1.0},
            ),
            tenant="tenant-a",
        )
        memories = query.mission_memories("t1")
        assert memories
        assert memories[0].tools_used == ["nmap", "httpx"]
        assert memories[0].coverage_achieved["port_discovery"] == 1.0

    def test_hypothesis_history_by_outcome(self) -> None:
        service, query, _ = _make_service()
        service.record_hypothesis(
            HypothesisMemory(hypothesis_id="h1", target_id="t1", outcome=HypothesisOutcome.FAILED, tool="sqlmap"),
            tenant="tenant-a",
        )
        service.record_hypothesis(
            HypothesisMemory(hypothesis_id="h2", target_id="t1", outcome=HypothesisOutcome.SUCCEEDED, tool="safe-validation", validation_strategy="safe_boolean"),
            tenant="tenant-a",
        )
        assert len(query.hypothesis_history("t1", outcome="failed")) == 1
        assert len(query.hypothesis_history("t1", outcome="succeeded")) == 1

    def test_tool_observation_provenance(self) -> None:
        service, query, _ = _make_service()
        service.record_tool_observation(
            ToolObservation(tool="nmap", tool_version="7.94", execution_id="ex-9", target_id="t1", normalized_result={"hosts": ["www.example.com"]}, evidence_refs=["evidence/e1"], tenant="tenant-a"),
            tenant="tenant-a",
        )
        records = query.tool_observations("t1", tool="nmap")
        assert records and records[0].execution_id == "ex-9"
        assert records[0].normalized_result["hosts"] == ["www.example.com"]


class TestRiskAndFindingMemory:
    def test_risk_history_is_append_only(self) -> None:
        service, query, _ = _make_service()
        service.evaluate_risk(target_id="t1", campaign_id="c1", mission_id="m1", tenant="tenant-a")
        service.evaluate_risk(
            target_id="t1",
            campaign_id="c1",
            mission_id="m2",
            findings=[FindingMemory(finding_id="f1", target_id="t1", severity="critical", remediation_state="open")],
            tenant="tenant-a",
        )
        history = query.risk_history("t1")
        assert len(history) == 2
        assert history[-1].risk_level.value == "critical"
        assert history[-1].previous_risk_level.value == "low"
        assert history[0].risk_level.value == "low"  # historical entry untouched

    def test_finding_history_and_recurrence(self) -> None:
        service, query, _ = _make_service()
        service.record_finding(FindingMemory(finding_id="f1", target_id="t1", vulnerability_class="sqli", remediation_state="closed", root_cause="unsafe query", affected_endpoints=["/api/a"]), tenant="tenant-a")
        service.record_finding(FindingMemory(finding_id="f2", target_id="t1", vulnerability_class="sqli", remediation_state="open", root_cause="unsafe query", affected_endpoints=["/api/b"]), tenant="tenant-a")
        recurrences = service.detect_recurrences("t1", tenant="tenant-a")
        assert recurrences
        assert len(query.recurrences("t1")) == 1
        assert len(query.finding_history("t1")) == 2


class TestRevalidationAndCoverage:
    def test_revalidation_plan(self) -> None:
        service, query, _ = _make_service()
        service.record_observations("t1", [_obs(timestamp="2020-01-01T00:00:00+00:00")], mission_id="m1", tenant="tenant-a")
        plan = service.build_revalidation_plan("t1", tenant="tenant-a")
        assert plan.items
        stored = query.revalidation_plan("t1")
        assert stored.items
        assert stored.items[0].observation_key == "port:80/tcp"

    def test_coverage_gaps(self) -> None:
        service, query, _ = _make_service()
        service.record_observations(
            "t1", [_obs(observation_type="endpoint", value="/login", normalized_value="/login", asset_key="url:https://www.example.com/login")], mission_id="m1", tenant="tenant-a"
        )
        gaps = service.detect_coverage_gaps("t1", tenant="tenant-a")
        assert gaps
        stored = query.coverage_gaps("t1")
        assert stored
        assert any(gap.kind.value == "discovered_untested" for gap in stored)


class TestRecommendationsAndPlanner:
    def test_next_action_recommendations(self) -> None:
        service, query, _ = _make_service()
        service.record_observations("t1", [_obs(timestamp="2020-01-01T00:00:00+00:00")], mission_id="m1", tenant="tenant-a")
        recommendations = service.recommend("t1", tenant="tenant-a")
        assert any(rec.action == "revalidate" for rec in recommendations)
        assert query.recommendations("t1")

    def test_planner_context(self) -> None:
        service, query, _ = _make_service()
        service.record_observations("t1", [_obs(timestamp="2020-01-01T00:00:00+00:00")], mission_id="m1", tenant="tenant-a")
        context = service.build_planner_context("t1")
        assert context.target_id == "t1"
        assert context.stale_state or context.risk_priorities
        assert context.to_dict()["target_id"] == "t1"


class TestCampaigns:
    def test_campaign_lifecycle_and_intelligence(self) -> None:
        service, query, _ = _make_service()
        campaign = service.create_campaign(name="Q3", objective="assess", scope="example.com", target_ids=["t1"], tenant="tenant-a")
        campaign.add_mission("m1")
        service.update_campaign(campaign)
        loaded = query.campaign(campaign.campaign_id)
        assert loaded is not None
        assert loaded.mission_ids == ["m1"]
        completed = service.complete_campaign(campaign.campaign_id, tenant="tenant-a")
        assert completed.status.value == "completed"
        assert query.campaigns()
        intelligence = query.campaign_intelligence(campaign.campaign_id)
        assert intelligence.campaign_id == campaign.campaign_id

    def test_campaign_intelligence_aggregates_changes(self) -> None:
        service, query, _ = _make_service()
        service.record_observations("t1", [_obs(value="80/tcp", normalized_value="80/tcp")], mission_id="m1", tenant="tenant-a")
        snap_a = service.create_snapshot("t1", mission_id="m1", tenant="tenant-a")
        service.record_observations(
            "t1",
            [_obs(value="8080/tcp", normalized_value="8080/tcp", mission_id="m2")],
            mission_id="m2",
            tenant="tenant-a",
        )
        snap_b = service.create_snapshot("t1", mission_id="m2", tenant="tenant-a")
        service.diff_snapshots(snap_a.snapshot_id, snap_b.snapshot_id, tenant="tenant-a")
        campaign = service.create_campaign(name="C", target_ids=["t1"], tenant="tenant-a")
        intelligence = query.campaign_intelligence(campaign.campaign_id)
        assert any(change["key"] == "port:8080/tcp" for change in intelligence.changed)


class TestEvents:
    def test_typed_events_published(self) -> None:
        from hunterx.infrastructure.event_bus import InMemoryEventBus

        bus = InMemoryEventBus()
        collected: list[str] = []
        bus.subscribe("target.#", lambda event: collected.append(event.event_type))  # type: ignore[arg-type]
        service = TargetMemoryService(stores=InMemoryTidbRepositoryFactory(), event_bus=bus, tenant="tenant-a", now=NOW)
        service.authorize(tenant="tenant-a", target_id="t1")
        service.record_observations("t1", [_obs()], mission_id="m1", tenant="tenant-a")
        service.create_snapshot("t1", mission_id="m1", tenant="tenant-a")
        assert "target.memory.updated" in collected
        assert "target.snapshot.created" in collected
