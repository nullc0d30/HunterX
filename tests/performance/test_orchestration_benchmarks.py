# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Performance benchmarks: offensive tool orchestration.

Benchmarks mission planning, dependency-graph construction, tool selection,
execution (deterministic), coverage computation, quality scoring and
deduplication. These are micro-benchmarks over in-memory components.
"""

from __future__ import annotations

from hunterx.domain.orchestration.enums import MissionType
from hunterx.domain.orchestration.models import MissionScope
from hunterx.engines.orchestration.coverage import CoverageModel
from hunterx.engines.orchestration.dedup import (
    ExecutionDeduplicator,
    ExecutionRecord,
    execution_hash,
)
from hunterx.engines.orchestration.executor import MissionExecutor
from hunterx.engines.orchestration.graph import MissionDependencyGraph
from hunterx.engines.orchestration.planner import IntelligenceSummary, MissionPlanner
from hunterx.engines.orchestration.quality import MissionQualityScorer
from hunterx.engines.orchestration.selector import MissionToolSelector
from tests.framework.orchestration import FakeExecutionEngine


def _plan(targets):
    planner = MissionPlanner()
    intelligence = IntelligenceSummary(
        mission_type=MissionType.EXTERNAL_ASSESSMENT,
        targets=tuple(targets),
        endpoints=("web", "api"),
    )
    return planner.plan(
        mission_id="m1",
        objective="assess",
        intelligence=intelligence,
        scope=MissionScope(roots=tuple(targets)),
    )


def test_planning_100_targets(benchmark) -> None:
    planner = MissionPlanner()
    targets = tuple(f"t{i}.example.com" for i in range(100))
    intelligence = IntelligenceSummary(
        mission_type=MissionType.EXTERNAL_ASSESSMENT,
        targets=targets,
        endpoints=("web",),
    )

    def run():
        return planner.plan(mission_id="m1", objective="assess", intelligence=intelligence)

    plan = benchmark(run)
    assert plan.total_steps() > 0


def test_graph_build_and_waves(benchmark) -> None:
    plan = _plan(tuple(f"t{i}.example.com" for i in range(50)))

    def run():
        graph = MissionDependencyGraph(plan)
        return graph.parallel_waves()

    waves = benchmark(run)
    assert waves


def test_tool_selection(benchmark) -> None:
    from hunterx.domain.orchestration.selection import CapabilityNeed

    engine = FakeExecutionEngine()
    selector = MissionToolSelector(engine=engine)
    need = CapabilityNeed(capability="web-crawling", target_type="url")

    def run():
        return selector.select_primary(need, mission_type=MissionType.WEB_PENTEST)

    result = benchmark(run)
    assert result.tool_id


def test_execution_100_steps(benchmark) -> None:
    plan = _plan(tuple(f"t{i}.example.com" for i in range(20)))
    outputs = {
        step.step_id: {"findings": [{"title": "x"}], "evidence": [{"content": "y"}]}
        for phase in plan.phases
        for step in phase.steps
    }
    engine = FakeExecutionEngine()
    executor = MissionExecutor(engine=engine, selector=MissionToolSelector(engine=engine))

    def run():
        return executor.run(mission_id="m1", plan=plan, tool_outputs=outputs)

    result = benchmark(run)
    assert result.all_completed


def test_coverage_and_quality(benchmark) -> None:
    plan = _plan(("a.example.com", "b.example.com"))
    outputs = {
        step.step_id: {"findings": [{"title": "x"}], "evidence": [{"content": "y"}]}
        for phase in plan.phases
        for step in phase.steps
    }
    engine = FakeExecutionEngine()
    run = MissionExecutor(engine=engine, selector=MissionToolSelector(engine=engine)).run(
        mission_id="m1", plan=plan, tool_outputs=outputs
    )
    model = CoverageModel()
    scorer = MissionQualityScorer()

    def compute():
        coverage = model.from_run(mission_id="m1", plan=plan, run=run)
        quality = scorer.score(mission_id="m1", plan_id=plan.plan_id, coverage=coverage)
        return coverage, quality

    coverage, quality = benchmark(compute)
    assert coverage.overall() > 0
    assert 0.0 <= quality.score <= 1.0


def test_dedup_lookup_1k(benchmark) -> None:
    dedup = ExecutionDeduplicator(freshness_window_seconds=3600)
    hashes = []
    for i in range(1000):
        h = execution_hash(tool_id="subfinder", target=f"t{i}.example.com")
        hashes.append(h)
        dedup.record(ExecutionRecord(execution_id=f"e{i}", input_hash=h, tool_id="subfinder", target=f"t{i}.example.com"))

    def run():
        hits = sum(1 for h in hashes if dedup.is_duplicate(h))
        return hits

    hits = benchmark(run)
    assert hits == 1000
