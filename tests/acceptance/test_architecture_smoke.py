# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""V7 architecture certification — end-to-end smoke mission.

Sprint 034.2 (Final Release Gate). This test drives one minimal mission
through the approved interfaces only:

    target -> mission -> planning -> execution -> persistence -> retrieval

Every subsystem participates through the composition root
(``hunterx.platform.build_platform``) and the platform's dependency
container — no subsystem is constructed directly. It certifies that:

- the composition root assembles the full platform (Core Engine, TIP,
  Execution Engine, Tool Factory, Mission Planning, Event Bus, TIDB, config);
- the dependency container resolves every port and service;
- the mission lifecycle persists normalized records through the TIDB and
  reads them back through the query services;
- the API and CLI entry points share the same wiring.
"""

from __future__ import annotations

from hunterx.engines.core import CoreEngine
from hunterx.engines.mission import MissionEngine
from hunterx.engines.mission_planning.api import MissionPlanningAPI
from hunterx.engines.workflow import WorkflowEngine
from hunterx.platform import Platform, build_platform
from hunterx.tools.factory.api import ToolIntegrationFactory
from hunterx.tools.intelligence.api import ToolIntelligenceAPI
from hunterx.tools.mastery.api import ToolMasteryAPI
from hunterx.tools.sdk.engine import ExecutionEngine


class TestArchitectureSmokeMission:
    def test_minimal_mission_through_approved_interfaces(self) -> None:
        platform = build_platform()

        # -- composition root ------------------------------------------------
        assert isinstance(platform, Platform)
        assert isinstance(platform.core, CoreEngine)
        assert isinstance(platform.tip, ToolIntelligenceAPI)
        assert isinstance(platform.execution_engine, ExecutionEngine)
        assert isinstance(platform.tool_factory, ToolIntegrationFactory)
        assert isinstance(platform.mission_planning, MissionPlanningAPI)
        assert isinstance(platform.mastery, ToolMasteryAPI)

        # the Core Engine aggregates every engine facade
        assert platform.core.tip is platform.tip
        assert platform.core.execution_engine is platform.execution_engine
        assert platform.core.tool_factory is platform.tool_factory
        assert platform.core.mission_planning is platform.mission_planning
        assert isinstance(platform.core.mission_engine, MissionEngine)
        assert isinstance(platform.core.workflow_engine, WorkflowEngine)

        # -- dependency resolution through the container --------------------
        assert platform.container.resolve(CoreEngine) is platform.core
        assert platform.has(ToolIntelligenceAPI)
        assert platform.has(ExecutionEngine)

        # -- target -> mission ----------------------------------------------
        service = platform.mission_orchestration_service
        mission = service.create_mission(
            objective="full_security_assessment",
            target="shop.example.com",
            strategy="adaptive",
        )
        mission_id = mission.mission_id
        assert mission.mission_id

        # -- planning --------------------------------------------------------
        # the adaptive planning surface produces a deterministic action graph
        planning = platform.adaptive_mission_planning_service
        planned = planning.create_mission(objective="bug_bounty_assessment", target="shop.example.com")
        graph = planning.current_plan(planned.mission_id)
        assert graph["plan_version"] == 1
        assert graph["actions"], "planning produced no actions"
        assert graph["topological_order"]
        candidates = planning.candidate_actions(planned.mission_id)
        assert candidates.proposals, "no ranked candidate actions"

        # -- execution -------------------------------------------------------
        started = service.start(mission_id)
        assert started["mission_id"] == mission_id
        observation = service.ingest_result(
            mission_id,
            tool_id="nuclei",
            asset_key="https://shop.example.com/search",
            raw={
                "observation_type": "vulnerability",
                "content": [{"template": "sql-injection", "parameter": "q", "severity": "high"}],
                "confidence": 0.6,
            },
        )
        assert observation["observation_id"]
        hypothesis = service.add_hypothesis(
            mission_id,
            statement="SQL injection on /search",
            category="injection",
            priority=0.8,
        )
        service.update_hypothesis(mission_id, hypothesis["hypothesis_id"], supporting=("ev-sqli-1", "ev-sqli-2"))
        service.verify_hypothesis(mission_id, hypothesis["hypothesis_id"], reproducible=True)
        service.register_finding(
            mission_id,
            finding_id="F-SMOKE-1",
            vulnerability_class="sql_injection",
            asset_key="https://shop.example.com/search",
            severity="high",
            tool="nuclei",
            confidence=0.93,
            evidence_refs=("ev-sqli-1", "ev-sqli-2"),
        )
        service.record_coverage(
            mission_id,
            asset_key="https://shop.example.com/search",
            capability="sql_injection",
            state="proved",
            tool_id="nuclei",
            confidence=0.93,
            evidence_refs=("ev-sqli-1", "ev-sqli-2"),
        )

        # -- persistence ------------------------------------------------------
        query = platform.mission_orchestration_query_service
        record = query.mission(mission_id)
        assert record is not None and record.mission_id == mission_id
        assert query.hypotheses(mission_id), "hypotheses not persisted"
        assert query.coverage(mission_id), "coverage not persisted"
        assert query.observations(mission_id), "observations not persisted"

        # -- retrieval --------------------------------------------------------
        retrieved = service.get(mission_id)
        assert retrieved.mission_id == mission_id
        status = service.status(mission_id)
        assert status["mission_id"] == mission_id
        assert status["coverage_ratio"] > 0

        # -- event bus participation -----------------------------------------
        # the mission lifecycle publishes mission.* events through the bus;
        # the attached event store persists every published event
        assert platform.event_store is not None
        events = platform.event_store.replay(event_type="mission.*")
        assert events, "no mission.* events persisted to the event store"
        assert any(event.event_type.startswith("mission.") for event in events)

    def test_api_and_cli_share_the_same_wiring(self) -> None:
        platform = build_platform()

        # API: create_app(platform=...) shares the platform container
        from hunterx.application.mission_orchestration import MissionOrchestrationService

        try:
            from hunterx.api.app import create_app
            from hunterx.api.deps import get_container
        except ImportError:
            return  # api extra not installed

        create_app(platform=platform)
        assert get_container().resolve(MissionOrchestrationService) is platform.mission_orchestration_service

        # CLI: register_default_commands(app, platform=...) uses the same platform
        from hunterx.cli.app import CliApplication
        from hunterx.cli.commands import register_default_commands

        app = CliApplication()
        register_default_commands(app, platform=platform)
        assert app.run(["platform"]) == 0
