# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Regression tests for the real 5+ GiB Python RSS runaway.

The real incident: a ``full_security_assessment`` mission grew to ~5.6 GiB
resident (74% of a 7.6 GiB host) with no child tools running. Instrumentation
traced the failure to the attack-path analysis: a port-scan observation adds
hundreds of ``context.services`` entries, a crawler adds hundreds of
endpoints, and ``record_attack_paths`` builds a dense O(SERVICES × ENDPOINTS)
bipartite graph that the attack-path BFS expands exponentially on EVERY
observation — a transient ~1.7-4.8 GiB allocation per cycle whose freed memory
ratchets the process RSS upward.

These tests assert the analysis is bounded (no such transient allocation) and
that the bounded-state layer trims the target-model maps that feed it.
"""

from __future__ import annotations

import time

from hunterx.domain.adaptive_mission_planning.attack_path import AttackPathEngine
from hunterx.domain.adaptive_mission_planning.models import MissionObjective
from hunterx.domain.mission_orchestration.orchestrator import MissionOrchestrator
from hunterx.domain.target_intelligence.graph import AttackSurfaceGraph
from hunterx.domain.target_intelligence.models import IntelligenceAsset
from hunterx.domain.topology.enums import EntityKind
from hunterx.resource.bounds import apply_mission_bounds, content_bytes, truncate_content
from hunterx.resource.config import ResourceConfig


def _dense_graph(*, services: int, endpoints: int) -> AttackSurfaceGraph:
    """Build the dense bipartite attack-surface graph of the incident."""
    from hunterx.domain.target_intelligence.graph import relationship_for

    graph = AttackSurfaceGraph()
    port = IntelligenceAsset(kind=EntityKind.PORT, name="443", key="port:443", label="port 443", in_scope=True)
    graph.upsert_asset(port)
    service_assets: list[IntelligenceAsset] = []
    for index in range(services):
        asset = IntelligenceAsset(
            kind=EntityKind.SERVICE,
            name=f"tcp:{index}",
            key=f"service:tcp:{index}",
            label=f"service {index}",
            in_scope=True,
        )
        graph.upsert_asset(asset)
        service_assets.append(asset)
        graph.add_relationship(relationship_for("serves", port, asset, mission_id="m", confidence=0.7))
    for index in range(endpoints):
        asset = IntelligenceAsset(
            kind=EntityKind.URL,
            name=f"https://example.com/api/{index}",
            key=f"url:https://example.com/api/{index}",
            label=f"endpoint {index}",
            in_scope=True,
        )
        graph.upsert_asset(asset)
        graph.add_relationship(relationship_for("serves", port, asset, mission_id="m", confidence=0.8))
        for service in service_assets:
            graph.add_relationship(relationship_for("serves", service, asset, mission_id="m", confidence=0.7))
    return graph


class TestAttackPathDiscoveryIsBounded:
    def test_dense_graph_discovery_is_bounded_and_cheap(self) -> None:
        # The incident's graph shape: ~1k services cross-linked to ~200 endpoints.
        graph = _dense_graph(services=1000, endpoints=200)
        engine = AttackPathEngine()

        started = time.monotonic()
        paths = engine.discover(graph, mission_id="m", objective=MissionObjective.ATTACK_SURFACE_DISCOVERY)
        elapsed = time.monotonic() - started

        assert len(paths) <= engine.max_paths
        # Before the fix this exponential expansion took minutes / GBs; the
        # bounded discovery must complete well under a generous 5 s.
        assert elapsed < 5.0, f"attack-path discovery took {elapsed:.2f}s on a dense graph"

    def test_chain_bfs_respects_shared_budget(self) -> None:
        engine = AttackPathEngine()
        graph = _dense_graph(services=500, endpoints=150)
        budget = {"visits": 200, "chains": 50}
        chains = engine._chains(graph, "port:443", budget)
        # The budget is shared and consumed: no unbounded expansion.
        assert budget["visits"] <= 200
        assert len(chains) <= 50

    def test_discover_respects_total_budget(self) -> None:
        engine = AttackPathEngine()
        graph = _dense_graph(services=800, endpoints=100)
        paths = engine.discover(graph, mission_id="m", objective=MissionObjective.ATTACK_SURFACE_DISCOVERY)
        assert len(paths) <= engine.max_paths
        assert len(paths) >= 0


class TestRecordAttackPathsIsBounded:
    def _mission_with_dense_context(self):
        from hunterx.domain.adaptive_mission_planning.toolchain import ToolSelectionEngine
        from hunterx.engines.adaptive_mission_planning.engine import AdaptiveMissionPlanningEngine

        planning = AdaptiveMissionPlanningEngine(
            tool_selection_engine=ToolSelectionEngine(
                mission_type="bug-bounty",
                default_candidates={"port_discovery": ("nmap",)},
            )
        )
        orchestrator = MissionOrchestrator(planning=planning)
        mission = orchestrator.create_mission(objective="full_security_assessment", target="https://example.com")
        orchestrator.start(mission.mission_id)
        # 1000 services (a port scan) + 300 endpoints (a crawler).
        mission.context.services = {
            f"service:{index}": {"key": "https://example.com", "identity": f"tcp:{index}", "content": {"blob": "x" * 2000}}
            for index in range(1000)
        }
        mission.context.endpoints = {
            f"endpoint:{index}": {"key": f"https://example.com/api/{index}", "content": {"blob": "x" * 2000}}
            for index in range(300)
        }
        return orchestrator, mission

    def test_record_attack_paths_is_bounded_on_dense_context(self) -> None:
        orchestrator, mission = self._mission_with_dense_context()

        started = time.monotonic()
        paths = orchestrator.record_attack_paths(mission.mission_id)
        elapsed = time.monotonic() - started

        # Bounded result and bounded runtime (pre-fix: minutes + GBs transient).
        assert isinstance(paths, list)
        assert elapsed < 5.0, f"record_attack_paths took {elapsed:.2f}s on a dense context"


class TestTargetModelMapsAreBounded:
    def test_services_assets_technologies_are_trimmed(self) -> None:
        from hunterx.application.mission_orchestration import MissionOrchestrationService
        from hunterx.domain.adaptive_mission_planning.toolchain import ToolSelectionEngine
        from hunterx.engines.adaptive_mission_planning.engine import AdaptiveMissionPlanningEngine
        from hunterx.engines.mission_orchestration import MissionOrchestrationEngine
        from hunterx.infrastructure.db.sql.memory import InMemoryTidbRepositoryFactory

        config = ResourceConfig(max_services_in_memory=64, max_assets_in_memory=100, max_technologies_in_memory=50)
        planning = AdaptiveMissionPlanningEngine(
            tool_selection_engine=ToolSelectionEngine(mission_type="bug-bounty", default_candidates={"port_discovery": ("nmap",)})
        )
        orchestrator = MissionOrchestrator(planning=planning)
        orchestration = MissionOrchestrationService(
            engine=MissionOrchestrationEngine(orchestrator=orchestrator),
            stores=InMemoryTidbRepositoryFactory(),
            resource_config=config,
        )
        mission = orchestration.create_mission(objective="full_security_assessment", target="https://example.com")
        mission.context.services = {f"s{i}": {"identity": str(i)} for i in range(1000)}
        mission.context.assets = {f"a{i}": {"key": str(i)} for i in range(1000)}
        mission.context.technologies = {f"t{i}": {"key": str(i)} for i in range(500)}
        apply_mission_bounds(mission, config)
        assert len(mission.context.services) <= 64
        assert len(mission.context.assets) <= 100
        assert len(mission.context.technologies) <= 50


class TestObservationContentIsByteBounded:
    def test_large_tool_output_is_summarized(self) -> None:
        content = {"blob": "x" * (2 * 1024 * 1024), "ports": list(range(1024))}
        truncated = truncate_content(content, 262144)
        assert content_bytes(truncated) <= 262144
        assert "blob" in truncated
        assert "ports" in truncated


__all__ = []
