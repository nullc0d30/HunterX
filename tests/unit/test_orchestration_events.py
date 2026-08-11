# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Unit tests: mission orchestration event emitter."""

from __future__ import annotations

from hunterx.engines.orchestration.events import MissionEventEmitter
from hunterx.infrastructure.event_bus import InMemoryEventBus


def _make_emitter():
    bus = InMemoryEventBus()
    seen: list[str] = []
    bus.subscribe("mission.*", lambda event: seen.append(event.event_type))
    return MissionEventEmitter(bus), seen


def test_scoping_events() -> None:
    emitter, seen = _make_emitter()
    emitter.scoping_started("m1", mission_type="web-pentest")
    emitter.scoping_completed("m1", roots=["example.com"])
    assert "mission.scoping.started" in seen
    assert "mission.scoping.completed" in seen


def test_plan_and_step_events() -> None:
    emitter, seen = _make_emitter()
    emitter.planning_started("m1", objective="assess")
    emitter.plan_created("m1", "p1", phases=3, steps=10)
    emitter.phase_started("m1", "p1", "ph1", phase_kind="reconnaissance")
    emitter.step_started("m1", "p1", "s1", capability="web-crawling", target="example.com")
    emitter.step_completed("m1", "p1", "s1", tool_id="katana", execution_id="e1", duration_ms=10)
    assert "mission.planning.started" in seen
    assert "mission.plan.created" in seen
    assert "mission.phase.started" in seen
    assert "mission.step.started" in seen
    assert "mission.step.completed" in seen


def test_tool_events() -> None:
    emitter, seen = _make_emitter()
    emitter.tool_selected("m1", "p1", "s1", "katana", capability="web-crawling", score=0.9)
    emitter.tool_started("m1", "p1", "s1", "katana", execution_id="e1")
    emitter.tool_completed("m1", "p1", "s1", "katana", execution_id="e1", duration_ms=5)
    emitter.tool_fallback("m1", "p1", "s1", "katana", "gau", reason="unavailable")
    assert "mission.tool.selected" in seen
    assert "mission.tool.started" in seen
    assert "mission.tool.completed" in seen
    assert "mission.tool.fallback" in seen


def test_failure_and_block_events() -> None:
    emitter, seen = _make_emitter()
    emitter.step_failed("m1", "p1", "s1", "boom", tool_id="katana", failure_class="permanent")
    emitter.step_blocked("m1", "p1", "s1", kind="scope", reason="out of scope", target="evil.org")
    assert "mission.step.failed" in seen
    assert "mission.step.blocked" in seen


def test_replan_and_checkpoint_events() -> None:
    emitter, seen = _make_emitter()
    emitter.replanning_started("m1", "p1", reason="new assets")
    emitter.replanned("m1", "p1", previous_version=1, new_version=2, added_steps=["s9"])
    emitter.checkpoint_created("m1", "p1", "ck1", label="auto", completed_steps=["s1"])
    emitter.resumed("m1", "p1", checkpoint_id="ck1")
    assert "mission.replanning.started" in seen
    assert "mission.replanned" in seen
    assert "mission.checkpoint.created" in seen
    assert "mission.resumed" in seen


def test_coverage_and_quality_events() -> None:
    emitter, seen = _make_emitter()
    emitter.quality_computed("m1", "p1", score=0.85)
    emitter.coverage_computed("m1", "p1", coverage={"asset": 0.8})
    emitter.blocked("m1", "p1", "blocked")
    emitter.partial("m1", "p1", gaps=["s3"])
    assert "mission.quality.computed" in seen
    assert "mission.coverage.computed" in seen
    assert "mission.blocked" in seen
    assert "mission.partial" in seen


def test_emitter_is_noop_without_bus() -> None:
    emitter = MissionEventEmitter(None)
    emitter.plan_created("m1", "p1")
    emitter.step_started("m1", "p1", "s1")
    # No exception raised.
