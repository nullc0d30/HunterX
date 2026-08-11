# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Unit tests: mission checkpoints, memory, replanning, coverage and quality."""

from __future__ import annotations

from hunterx.domain.orchestration.enums import MissionType
from hunterx.domain.orchestration.models import MissionScope
from hunterx.engines.orchestration.checkpoints import MissionCheckpointManager
from hunterx.engines.orchestration.coverage import CoverageModel
from hunterx.engines.orchestration.memory import MissionMemoryStore
from hunterx.engines.orchestration.planner import IntelligenceSummary, MissionPlanner
from hunterx.engines.orchestration.quality import MissionQualityScorer
from hunterx.engines.orchestration.replan import (
    DiscoveredAsset,
    ReplanningEngine,
    ReplanRequest,
)
from hunterx.engines.orchestration.scope import MissionScopeGuard


def test_checkpoint_create_and_restore() -> None:
    manager = MissionCheckpointManager()
    checkpoint = manager.create(
        mission_id="m1",
        plan_id="p1",
        completed_steps=["s1", "s2"],
        pending_steps=["s3"],
        failed_steps=[],
    )
    assert manager.latest("p1").checkpoint_id == checkpoint.checkpoint_id
    state = manager.resume_state(checkpoint)
    assert state["completed"] == ["s1", "s2"]
    assert state["pending"] == ["s3"]


def test_checkpoint_latest_ordering() -> None:
    manager = MissionCheckpointManager()
    first = manager.create(mission_id="m1", plan_id="p1")
    second = manager.create(mission_id="m1", plan_id="p1")
    assert manager.latest("p1").checkpoint_id == second.checkpoint_id
    assert manager.list("p1")[0].checkpoint_id == second.checkpoint_id
    assert first.checkpoint_version == 1


def test_memory_is_target_scoped() -> None:
    store = MissionMemoryStore()
    store.memory(target="a.com").add_asset("sub.a.com")
    store.memory(target="b.com").add_asset("sub.b.com")
    assert len(store.memory(target="a.com").discovered_assets) == 1
    assert len(store.memory(target="b.com").discovered_assets) == 1


def test_memory_deduplicates() -> None:
    store = MissionMemoryStore()
    memory = store.memory(target="a.com")
    memory.add_asset("sub.a.com")
    memory.add_asset("sub.a.com")
    memory.add_technology("nginx:1.24")
    assert memory.discovered_assets == ["sub.a.com"]
    assert memory.technologies == ["nginx:1.24"]


def test_memory_cross_mission_isolation() -> None:
    store = MissionMemoryStore()
    store.memory(mission_id="m1", target="a.com").add_asset("sub.a.com")
    store.memory(mission_id="m2", target="a.com").add_asset("other")
    assert store.memory(mission_id="m1", target="a.com").discovered_assets == ["sub.a.com"]
    assert store.memory(mission_id="m2", target="a.com").discovered_assets == ["other"]


def test_replan_blocks_out_of_scope_assets() -> None:
    guard = MissionScopeGuard(MissionScope(roots=("example.com",)))
    engine = ReplanningEngine(guard)
    decision = engine.evaluate(
        ReplanRequest(
            mission_id="m1",
            plan_id="p1",
            reason="new assets",
            discovered_assets=[
                DiscoveredAsset(identifier="sub.example.com"),
                DiscoveredAsset(identifier="evil.org"),
            ],
        )
    )
    assert decision.replan_needed
    assert "sub.example.com" in decision.in_scope_assets
    assert "evil.org" in decision.blocked_assets
    assert decision.classifications["evil.org"] == "out-of-scope"


def test_replan_no_replan_without_new_surface() -> None:
    engine = ReplanningEngine()
    decision = engine.evaluate(ReplanRequest(mission_id="m1", plan_id="p1", reason="noop"))
    assert not decision.replan_needed


def test_coverage_metrics() -> None:
    model = CoverageModel()
    report = model.compute(
        mission_id="m1",
        plan_id="p1",
        targets=["a.com", "b.com"],
        planned_capabilities=["web-crawling", "api-discovery"],
        executed_capabilities=["web-crawling"],
        executed_targets=["a.com"],
        technologies=["nginx"],
        planned_technologies=2,
    )
    assert report.overall() > 0
    asset = report.metric(__import__("hunterx.domain.orchestration.enums", fromlist=["CoverageKind"]).CoverageKind.ASSET)
    assert asset.fraction == 0.5
    assert report.blind_spots


def test_coverage_never_reports_tool_count_as_coverage() -> None:
    model = CoverageModel()
    report = model.compute(
        mission_id="m1",
        plan_id="p1",
        targets=["a.com"],
        planned_capabilities=["web-crawling", "api-discovery"],
        executed_capabilities=[],
        executed_targets=[],
    )
    tool = report.metric(__import__("hunterx.domain.orchestration.enums", fromlist=["CoverageKind"]).CoverageKind.TOOL)
    assert tool.fraction == 0.0


def test_quality_score_explainable() -> None:
    model = CoverageModel()
    report = model.compute(
        mission_id="m1",
        plan_id="p1",
        targets=["a.com"],
        planned_capabilities=["web-crawling"],
        executed_capabilities=["web-crawling"],
        executed_targets=["a.com"],
    )
    scorer = MissionQualityScorer()
    quality = scorer.score(
        mission_id="m1",
        plan_id="p1",
        coverage=report,
        executed_steps=5,
        total_steps=5,
        tool_successes=4,
        tool_attempts=5,
    )
    assert 0.0 <= quality.score <= 1.0
    assert quality.factor("execution_completeness").score == 1.0
    assert quality.factor("tool_reliability").score == 0.8
    assert quality.explainability["formula"]


def test_planner_full_pipeline_coverage() -> None:
    planner = MissionPlanner()
    intelligence = IntelligenceSummary(
        mission_type=MissionType.WEB_PENTEST,
        targets=("example.com",),
        endpoints=("web", "api"),
    )
    plan = planner.plan(mission_id="m1", objective="assess", intelligence=intelligence)
    assert plan.total_steps() > 0
    assert plan.scope is not None
