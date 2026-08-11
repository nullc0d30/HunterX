# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tests for the platform composition root.

Covers platform assembly (``hunterx.platform.assembler.build_platform``),
container wiring of every port and service, adapter selection from settings,
the four v7 facades and their Core Engine integration, and the API/CLI entry
points that consume a composed platform.
"""

from __future__ import annotations

import pytest

from hunterx.application.findings import FindingService
from hunterx.application.livehost import LiveHostService
from hunterx.application.mission_planning import MissionPlanningService
from hunterx.application.missions import MissionService
from hunterx.application.recon import ReconService
from hunterx.application.reports import ReportService
from hunterx.application.technology import FingerprintService, TechnologyQueryService
from hunterx.application.tool_factory import ToolFactoryService
from hunterx.config.settings import CacheSettings, DatabaseSettings, QueueSettings, Settings
from hunterx.domain.exceptions import RegistrationNotFoundError
from hunterx.domain.ports.messaging import CachePort, EventBusPort, QueuePort
from hunterx.domain.ports.mission_planning import (
    CheckpointRepository,
    MissionPlanRepository,
    MissionProfileRepository,
    MissionTemplateRepository,
    MissionTimelineRepository,
)
from hunterx.domain.ports.repositories import (
    AssetRepository,
    FindingRepository,
    MissionRepository,
    ReportRepository,
    ScanRepository,
    TargetRepository,
)
from hunterx.domain.ports.services import AIPort, SecretsPort, TelemetryPort
from hunterx.domain.ports.stores import KnowledgeGraphPort
from hunterx.domain.ports.tidb_repositories import TidbRepositoryFactory
from hunterx.domain.ports.tool_factory import PackTemplateRepository, ToolPackRepository
from hunterx.domain.ports.tool_intelligence import ToolIntelligencePort
from hunterx.engines.core import CoreEngine
from hunterx.engines.mission_planning.api import MissionPlanningAPI
from hunterx.infrastructure.cache import MemoryCache, NullCache
from hunterx.infrastructure.queue import MemoryQueue, NullQueue
from hunterx.managers import CacheManager, DependencyManager, EventBus, QueueManager
from hunterx.platform import Platform, build_platform
from hunterx.platform.assembler import _MEMORY_REPOSITORIES
from hunterx.shared.di import Container
from hunterx.tools.dns import DNS_TOOL_IDS
from hunterx.tools.factory.api import ToolIntegrationFactory
from hunterx.tools.intelligence.api import ToolIntelligenceAPI
from hunterx.tools.intelligence.registry import ToolIntelligenceRegistry
from hunterx.tools.livehost import LIVE_TOOL_IDS
from hunterx.tools.recon import RECON_TOOL_IDS
from hunterx.tools.sdk.engine import ExecutionEngine


def _settings(**overrides: object) -> Settings:
    database = overrides.pop("database", DatabaseSettings())
    cache = overrides.pop("cache", CacheSettings())
    queue = overrides.pop("queue", QueueSettings())
    base: dict[str, object] = {"database": database, "cache": cache, "queue": queue}
    base.update(overrides)
    return Settings(**base)  # type: ignore[arg-type]


class TestAssembly:
    def test_build_returns_platform(self) -> None:
        platform = build_platform(_settings())
        assert isinstance(platform, Platform)

    def test_facades_are_wired(self) -> None:
        platform = build_platform(_settings())
        assert isinstance(platform.tip, ToolIntelligenceAPI)
        assert isinstance(platform.execution_engine, ExecutionEngine)
        assert isinstance(platform.tool_factory, ToolIntegrationFactory)
        assert isinstance(platform.mission_planning, MissionPlanningAPI)

    def test_core_engine_receives_facades(self) -> None:
        platform = build_platform(_settings())
        assert isinstance(platform.core, CoreEngine)
        assert platform.core.tip is platform.tip
        assert platform.core.execution_engine is platform.execution_engine
        assert platform.core.tool_factory is platform.tool_factory
        assert platform.core.mission_planning is platform.mission_planning

    def test_application_services_are_wired(self) -> None:
        platform = build_platform(_settings())
        assert isinstance(platform.mission_service, MissionService)
        assert isinstance(platform.finding_service, FindingService)
        assert isinstance(platform.report_service, ReportService)
        assert isinstance(platform.tool_factory_service, ToolFactoryService)
        assert isinstance(platform.mission_planning_service, MissionPlanningService)
        assert isinstance(platform.recon_service, ReconService)
        assert isinstance(platform.livehost_service, LiveHostService)
        assert isinstance(platform.technology_service, FingerprintService)
        assert isinstance(platform.technology_query_service, TechnologyQueryService)

    def test_recon_capability_is_wired(self) -> None:
        platform = build_platform(_settings())
        assert platform.recon_service.engine is platform.execution_engine
        assert isinstance(platform.tidb, TidbRepositoryFactory)
        registered = {
            tool_id for tool_id in RECON_TOOL_IDS if platform.execution_engine.adapter_for(tool_id) is not None
        }
        assert registered == set(RECON_TOOL_IDS)

    def test_livehost_capability_is_wired(self) -> None:
        platform = build_platform(_settings())
        assert platform.livehost_service.engine is platform.execution_engine
        assert isinstance(platform.tidb, TidbRepositoryFactory)
        registered = {
            tool_id for tool_id in LIVE_TOOL_IDS if platform.execution_engine.adapter_for(tool_id) is not None
        }
        assert registered == set(LIVE_TOOL_IDS)

    def test_technology_capability_is_wired(self) -> None:
        from hunterx.tools.tech import TECH_TOOL_IDS

        platform = build_platform(_settings())
        assert platform.technology_service.engine is platform.execution_engine
        assert isinstance(platform.tidb, TidbRepositoryFactory)
        registered = {
            tool_id for tool_id in TECH_TOOL_IDS if platform.execution_engine.adapter_for(tool_id) is not None
        }
        assert registered == set(TECH_TOOL_IDS)
        assert platform.container.resolve(FingerprintService) is platform.technology_service
        assert platform.container.resolve(TechnologyQueryService) is platform.technology_query_service

    def test_all_repository_roles_present(self) -> None:
        platform = build_platform(_settings())
        for role in _MEMORY_REPOSITORIES:
            assert role in platform.repositories, role

    def test_adapters_present(self) -> None:
        platform = build_platform(_settings())
        assert isinstance(platform.event_bus, EventBusPort)
        assert isinstance(platform.cache, CachePort)
        assert isinstance(platform.queue, QueuePort)
        assert isinstance(platform.secrets, SecretsPort)
        assert isinstance(platform.ai, AIPort)
        assert isinstance(platform.telemetry, TelemetryPort)
        assert isinstance(platform.knowledge_graph, KnowledgeGraphPort)

    def test_memory_backends_selected_by_default(self) -> None:
        platform = build_platform(_settings())
        assert isinstance(platform.cache, MemoryCache)
        assert isinstance(platform.queue, MemoryQueue)

    def test_null_backends_selected_when_configured(self) -> None:
        settings = _settings(
            cache=CacheSettings(backend="redis"),
            queue=QueueSettings(backend="redis"),
        )
        platform = build_platform(settings)
        assert isinstance(platform.cache, NullCache)
        assert isinstance(platform.queue, NullQueue)


class TestContainer:
    def test_ports_resolve(self) -> None:
        platform = build_platform(_settings())
        assert platform.container.resolve(EventBusPort) is platform.event_bus
        assert platform.container.resolve(CachePort) is platform.cache
        assert platform.container.resolve(QueuePort) is platform.queue
        assert platform.container.resolve(SecretsPort) is platform.secrets
        assert platform.container.resolve(AIPort) is platform.ai
        assert platform.container.resolve(TelemetryPort) is platform.telemetry
        assert platform.container.resolve(KnowledgeGraphPort) is platform.knowledge_graph

    def test_tool_intelligence_ports_resolve(self) -> None:
        platform = build_platform(_settings())
        assert platform.container.resolve(ToolIntelligencePort) is platform.tip
        assert platform.container.resolve(ToolIntelligenceRegistry) is platform.tip.registry

    def test_repository_ports_resolve(self) -> None:
        platform = build_platform(_settings())
        for port in (
            MissionRepository,
            FindingRepository,
            TargetRepository,
            ScanRepository,
            AssetRepository,
            ReportRepository,
            MissionProfileRepository,
            MissionTemplateRepository,
            MissionPlanRepository,
            CheckpointRepository,
            MissionTimelineRepository,
            PackTemplateRepository,
            ToolPackRepository,
        ):
            assert platform.container.has(port), port
            assert platform.container.resolve(port) is not None

    def test_engines_and_managers_resolve(self) -> None:
        platform = build_platform(_settings())
        assert platform.container.resolve(CoreEngine) is platform.core
        assert platform.container.resolve(ToolIntelligenceAPI) is platform.tip
        assert platform.container.resolve(ExecutionEngine) is platform.execution_engine
        assert platform.container.resolve(ToolIntegrationFactory) is platform.tool_factory
        assert platform.container.resolve(MissionPlanningAPI) is platform.mission_planning
        assert isinstance(platform.container.resolve(CacheManager), CacheManager)
        assert isinstance(platform.container.resolve(QueueManager), QueueManager)
        assert isinstance(platform.container.resolve(EventBus), EventBus)
        assert isinstance(platform.container.resolve(DependencyManager), DependencyManager)

    def test_services_resolve(self) -> None:
        platform = build_platform(_settings())
        assert platform.container.resolve(MissionService) is platform.mission_service
        assert platform.container.resolve(FindingService) is platform.finding_service
        assert platform.container.resolve(ReportService) is platform.report_service
        assert platform.container.resolve(ToolFactoryService) is platform.tool_factory_service
        assert platform.container.resolve(MissionPlanningService) is platform.mission_planning_service
        assert platform.container.resolve(ReconService) is platform.recon_service
        assert platform.container.resolve(LiveHostService) is platform.livehost_service
        assert platform.container.resolve(TidbRepositoryFactory) is platform.tidb

    def test_unregistered_key_raises(self) -> None:
        platform = build_platform(_settings())
        with pytest.raises(RegistrationNotFoundError):
            platform.container.resolve(Container)

    def test_platform_helpers_delegate_to_container(self) -> None:
        platform = build_platform(_settings())
        assert platform.has(CoreEngine)
        assert platform.resolve(CoreEngine) is platform.core
        assert not platform.has(Container)


class TestSqlSwitching:
    def test_non_default_sql_url_switches_entity_repos(self) -> None:
        settings = _settings(database=DatabaseSettings(url="sqlite:///:memory:"))
        platform = build_platform(settings)
        assert "session_factory" in platform.repositories
        for role in ("missions", "findings", "targets", "scans", "assets", "reports"):
            assert type(platform.repositories[role]).__name__.startswith("Sql"), role
        for role in ("mission_plans", "mission_profiles", "mission_templates", "checkpoints"):
            assert "InMemory" in type(platform.repositories[role]).__name__, role

    def test_default_sqlite_url_keeps_memory(self) -> None:
        platform = build_platform(_settings(database=DatabaseSettings(url="sqlite:///hunterx.db")))
        assert "session_factory" not in platform.repositories
        assert type(platform.repositories["missions"]).__name__ == "InMemoryMissionRepository"


class TestEndToEnd:
    def test_platform_facades_work_together(self) -> None:
        platform = build_platform(_settings())
        registered = {tool.tool_id for tool in platform.tip.registry.list_metadata()}
        assert set(RECON_TOOL_IDS) <= registered
        assert set(DNS_TOOL_IDS) <= registered
        assert set(LIVE_TOOL_IDS) <= registered
        assert platform.mission_planning is not None
        assert platform.core.mission_engine is not None


class TestApiWiring:
    def test_create_app_accepts_platform(self) -> None:
        fastapi = pytest.importorskip("fastapi")
        platform = build_platform(_settings())
        from hunterx.api.app import create_app

        app = create_app(platform=platform)
        assert isinstance(app, fastapi.FastAPI)


class TestCliWiring:
    def test_register_default_commands_with_platform(self, capsys: pytest.CaptureFixture[str]) -> None:
        from hunterx.cli.app import CliApplication
        from hunterx.cli.commands import register_default_commands

        platform = build_platform(_settings())
        app = CliApplication()
        register_default_commands(app, platform=platform)
        assert app.run(["platform"]) == 0
        out = capsys.readouterr().out
        assert '"environment": "production"' in out
        assert '"repositories"' in out
        assert '"facades"' in out
        assert '"services"' in out

    def test_register_default_commands_builds_platform(self, capsys: pytest.CaptureFixture[str]) -> None:
        from hunterx.cli.app import CliApplication
        from hunterx.cli.commands import register_default_commands

        app = CliApplication()
        register_default_commands(app)
        assert app.run(["platform"]) == 0
        out = capsys.readouterr().out
        assert '"repositories"' in out
