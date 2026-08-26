# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Platform composition root.

The Platform is the runtime aggregate of HunterX v7. It owns the dependency
container and holds typed references to every facade, engine, application
service and infrastructure adapter the platform is composed of. It is the
single place where concrete implementations are wired together (Clean
Architecture's composition root); domain, application and engine layers
never construct their collaborators directly.

Build one with :func:`hunterx.platform.assembler.build_platform`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, TypeVar

from hunterx.application.adaptive_mission_planning import (
    AdaptiveMissionPlanningQueryService,
    AdaptiveMissionPlanningService,
)
from hunterx.application.auth import AuthQueryService, AuthService
from hunterx.application.authorization import (
    AuthorizationQueryService,
    AuthorizationService,
)
from hunterx.application.cloud import CloudQueryService, CloudService
from hunterx.application.crawl import CrawlQueryService, CrawlService
from hunterx.application.dns import DnsService
from hunterx.application.findings import FindingService
from hunterx.application.javascript import JavaScriptQueryService, JavaScriptService
from hunterx.application.livehost import LiveHostService
from hunterx.application.mission_dashboard import MissionDashboardService
from hunterx.application.mission_execution import MissionExecutionService
from hunterx.application.mission_orchestration import (
    MissionOrchestrationQueryService,
    MissionOrchestrationService,
)
from hunterx.application.mission_planning import MissionPlanningService
from hunterx.application.missions import MissionService
from hunterx.application.observability import ObservabilityService
from hunterx.application.orchestration import OffensiveOrchestrationService
from hunterx.application.professional_reporting import ProfessionalReportingService
from hunterx.application.recon import ReconService
from hunterx.application.reports import ReportService
from hunterx.application.target_intelligence import (
    TargetIntelligenceQueryService,
    TargetIntelligenceService,
)
from hunterx.application.target_memory import TargetMemoryQueryService, TargetMemoryService
from hunterx.application.technology import FingerprintService, TechnologyQueryService
from hunterx.application.tool_factory import ToolFactoryService
from hunterx.application.toolchain import ToolchainService
from hunterx.application.topology import TopologyQueryService, TopologyService
from hunterx.application.vulnerability import (
    VulnerabilityCorrelationService,
    VulnerabilityKnowledgeService,
    VulnerabilityQueryService,
)
from hunterx.application.vulnerability_finding import VulnerabilityFindingService
from hunterx.application.vulnerability_proof import VulnerabilityProofService
from hunterx.application.vulnerability_proof_strategy import VulnerabilityProofStrategyService
from hunterx.application.vulnerability_validation import VulnerabilityValidationService
from hunterx.config.settings import AISettings, Settings
from hunterx.domain.events.spec import EventRegistry
from hunterx.domain.ports.messaging import CachePort, EventBusPort, QueuePort
from hunterx.domain.ports.observability import (
    DeadLetterQueuePort,
    EventStorePort,
    HealthRegistryPort,
    MetricsPort,
    TracerPort,
)
from hunterx.domain.ports.services import AIPort, SecretsPort, TelemetryPort
from hunterx.domain.ports.stores import KnowledgeGraphPort
from hunterx.domain.ports.tidb_repositories import TidbRepositoryFactory
from hunterx.engines.adaptive_mission_planning.engine import AdaptiveMissionPlanningEngine
from hunterx.engines.core import CoreEngine
from hunterx.engines.mission_orchestration import MissionOrchestrationEngine
from hunterx.engines.mission_planning.api import MissionPlanningAPI
from hunterx.engines.orchestration.api import OffensiveOrchestrationAPI
from hunterx.engines.target_intelligence.engine import TargetIntelligenceEngine
from hunterx.resource import ResourceGovernor
from hunterx.shared.di import Container
from hunterx.tools.factory.api import ToolIntegrationFactory
from hunterx.tools.intelligence.api import ToolIntelligenceAPI
from hunterx.tools.mastery.api import ToolMasteryAPI
from hunterx.tools.readiness.service import ToolReadinessService
from hunterx.tools.sdk.engine import ExecutionEngine

T = TypeVar("T")


@dataclass(slots=True)
class Platform:
    """The fully wired HunterX v7 runtime aggregate.

    Attributes:
        settings: resolved typed configuration.
        ai_settings: AI provider configuration (provider/model/keys) for
            status, health checks and the guided configuration flow.
        container: dependency container holding every port and service.
        core: the :class:`CoreEngine` aggregating all engines and v7 facades.
        tip: Tool Intelligence Platform facade.
        execution_engine: Tool Integration SDK execution engine.
        tool_factory: Tool Integration Factory facade.
        mission_planning: mission planning engine facade.
        mission_service: mission use-case service.
        finding_service: finding use-case service.
        report_service: report use-case service.
        tool_factory_service: Tool Integration Factory use-case service.
        mission_planning_service: mission planning use-case service.
        offensive_orchestration: offensive tool orchestration engine facade.
        offensive_orchestration_service: offensive orchestration use-case service.
        recon_service: reconnaissance use-case service.
        dns_service: DNS intelligence use-case service.
        livehost_service: live host & service discovery use-case service.
        topology_service: network-mapping topology build use-case service.
        topology_query_service: attack-surface topology query use-case service.
        technology_service: technology fingerprinting use-case service.
        technology_query_service: technology intelligence query use-case service.
        crawl_service: web crawling use-case service.
        crawl_query_service: web crawl intelligence query use-case service.
        javascript_service: JavaScript intelligence use-case service.
        javascript_query_service: JavaScript intelligence query use-case service.
        auth_service: authentication intelligence use-case service.
        auth_query_service: authentication intelligence query use-case service.
        authorization_service: authorization & access-control intelligence use-case service.
        authorization_query_service: authorization intelligence query use-case service.
        cloud_service: cloud & SaaS attack-surface intelligence use-case service.
        cloud_query_service: cloud intelligence query use-case service.
        vulnerability_knowledge_service: vulnerability knowledge refresh use-case service.
        vulnerability_correlation_service: technology→vulnerability correlation use-case service.
        vulnerability_query_service: vulnerability intelligence query use-case service.
        vulnerability_validation_service: safe vulnerability discovery & validation use-case service.
        vulnerability_proof_service: vulnerability proof & PoC validation use-case service.
        vulnerability_proof_strategy_service: vulnerability proof strategy library & validator use-case service.
        vulnerability_finding_service: vulnerability validation & proof orchestration use-case service.
        professional_reporting_service: professional finding intelligence & reporting use-case service.
        event_bus: event bus adapter (``EventBusPort``).
        cache: cache adapter (``CachePort``).
        queue: work-queue adapter (``QueuePort``).
        secrets: secrets adapter (``SecretsPort``).
        ai: AI provider adapter (``AIPort``).
        telemetry: telemetry adapter (``TelemetryPort``).
        knowledge_graph: knowledge graph adapter (``KnowledgeGraphPort``).
        observability: unified observability service.
        event_registry: canonical event catalog.
        metrics: metrics collector.
        tracer: distributed tracer.
        health: health probe registry.
        tidb: TIDB repository factory for system-of-record entities.
        event_store: event persistence (``None`` when disabled).
        dead_letter: dead-letter queue (``None`` when disabled).
        repositories: concrete repositories keyed by role name.

    """

    settings: Settings
    container: Container[Any]
    core: CoreEngine
    ai_settings: AISettings
    tip: ToolIntelligenceAPI
    execution_engine: ExecutionEngine
    tool_factory: ToolIntegrationFactory
    mission_planning: MissionPlanningAPI
    mastery: ToolMasteryAPI
    mission_service: MissionService
    finding_service: FindingService
    report_service: ReportService
    tool_factory_service: ToolFactoryService
    toolchain_service: ToolchainService
    mission_planning_service: MissionPlanningService
    offensive_orchestration: OffensiveOrchestrationAPI
    offensive_orchestration_service: OffensiveOrchestrationService
    recon_service: ReconService
    dns_service: DnsService
    livehost_service: LiveHostService
    topology_service: TopologyService
    topology_query_service: TopologyQueryService
    technology_service: FingerprintService
    technology_query_service: TechnologyQueryService
    crawl_service: CrawlService
    crawl_query_service: CrawlQueryService
    javascript_service: JavaScriptService
    javascript_query_service: JavaScriptQueryService
    auth_service: AuthService
    auth_query_service: AuthQueryService
    authorization_service: AuthorizationService
    authorization_query_service: AuthorizationQueryService
    cloud_service: CloudService
    cloud_query_service: CloudQueryService
    vulnerability_knowledge_service: VulnerabilityKnowledgeService
    vulnerability_correlation_service: VulnerabilityCorrelationService
    vulnerability_query_service: VulnerabilityQueryService
    vulnerability_validation_service: VulnerabilityValidationService
    vulnerability_proof_service: VulnerabilityProofService
    vulnerability_proof_strategy_service: VulnerabilityProofStrategyService
    vulnerability_finding_service: VulnerabilityFindingService
    professional_reporting_service: ProfessionalReportingService
    target_intelligence: TargetIntelligenceEngine
    target_intelligence_service: TargetIntelligenceService
    target_intelligence_query_service: TargetIntelligenceQueryService
    target_memory_service: TargetMemoryService
    target_memory_query_service: TargetMemoryQueryService
    adaptive_mission_planning: AdaptiveMissionPlanningEngine
    adaptive_mission_planning_service: AdaptiveMissionPlanningService
    adaptive_mission_planning_query_service: AdaptiveMissionPlanningQueryService
    mission_orchestration: MissionOrchestrationEngine
    mission_orchestration_service: MissionOrchestrationService
    mission_orchestration_query_service: MissionOrchestrationQueryService
    mission_dashboard_service: MissionDashboardService
    mission_execution_service: MissionExecutionService
    tool_readiness_service: ToolReadinessService
    event_bus: EventBusPort
    cache: CachePort
    queue: QueuePort
    secrets: SecretsPort
    ai: AIPort
    telemetry: TelemetryPort
    knowledge_graph: KnowledgeGraphPort
    observability: ObservabilityService
    event_registry: EventRegistry
    metrics: MetricsPort
    tracer: TracerPort
    health: HealthRegistryPort
    tidb: TidbRepositoryFactory
    event_store: EventStorePort | None = None
    dead_letter: DeadLetterQueuePort | None = None
    repositories: dict[str, object] = field(default_factory=dict)
    resource_governor: ResourceGovernor | None = None

    def resolve(self, key: type[T]) -> T:
        """Resolve a service from the platform's container."""
        return self.container.resolve(key)  # type: ignore[no-any-return]  # container resolves by key type

    def has(self, key: type[T]) -> bool:
        """Return ``True`` when ``key`` is resolvable in the container."""
        return self.container.has(key)
