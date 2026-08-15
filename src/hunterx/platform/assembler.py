# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Platform assembler.

Builds a fully wired :class:`~hunterx.platform.platform.Platform` — the
composition root of HunterX v7. The assembler is the only place in the system
that knows concrete implementations: it picks infrastructure adapters from
settings, constructs the four v7 facades (TIP, Tool Integration SDK, Tool
Integration Factory, Mission Planning), assembles the Core Engine and
application services, and registers every port and service in a dependency
container.
"""

from __future__ import annotations

from typing import Any

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
from hunterx.config.loader import load_default_settings
from hunterx.config.paths import DEFAULT_DATABASE_URL
from hunterx.config.settings import Settings
from hunterx.domain.adaptive_mission_planning.toolchain import ToolSelectionEngine
from hunterx.domain.events.catalog import build_registry
from hunterx.domain.mission_orchestration.orchestrator import MissionOrchestrator
from hunterx.domain.ports.messaging import CachePort, EventBusPort, QueuePort
from hunterx.domain.ports.mission_planning import (
    CheckpointRepository,
    MissionPlanRepository,
    MissionProfileRepository,
    MissionTemplateRepository,
    MissionTimelineRepository,
)
from hunterx.domain.ports.observability import (
    DeadLetterQueuePort,
    EventStorePort,
    HealthRegistryPort,
    MetricsPort,
    ObservabilityEventBusPort,
    TelemetryProviderPort,
    TracerPort,
)
from hunterx.domain.ports.orchestration import (
    ExecutionPlanRepository,
    OffensiveMissionRepository,
    ToolSelectionRepository,
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
from hunterx.domain.ports.tool_mastery import ToolMasteryPort
from hunterx.domain.vulnerability.knowledge import VulnerabilityKnowledgeStore
from hunterx.engines.adaptive_mission_planning.engine import AdaptiveMissionPlanningEngine
from hunterx.engines.core import CoreEngine
from hunterx.engines.correlation import TargetCorrelator
from hunterx.engines.mission import MissionEngine
from hunterx.engines.mission_orchestration import MissionOrchestrationEngine
from hunterx.engines.mission_planning.api import MissionPlanningAPI
from hunterx.engines.orchestration.api import OffensiveOrchestrationAPI
from hunterx.engines.planner import DeterministicPlanner
from hunterx.engines.reasoning import ReasoningEngine
from hunterx.engines.report import ReportEngine
from hunterx.engines.risk import DefaultRiskScorer
from hunterx.engines.target_intelligence.engine import TargetIntelligenceEngine
from hunterx.engines.workflow import WorkflowEngine
from hunterx.infrastructure.ai import build_ai_client
from hunterx.infrastructure.cache import MemoryCache, NullCache
from hunterx.infrastructure.db.graph import InMemoryKnowledgeGraph
from hunterx.infrastructure.db.sql.memory import InMemoryTidbRepositoryFactory
from hunterx.infrastructure.event_bus import InMemoryEventBus
from hunterx.infrastructure.event_bus.store import (
    InMemoryDeadLetterQueue,
    InMemoryEventStore,
)
from hunterx.infrastructure.health import HealthRegistry
from hunterx.infrastructure.memory import (
    InMemoryAssetRepository,
    InMemoryCheckpointRepository,
    InMemoryFindingRepository,
    InMemoryMissionPlanRepository,
    InMemoryMissionProfileRepository,
    InMemoryMissionRepository,
    InMemoryMissionTemplateRepository,
    InMemoryMissionTimelineRepository,
    InMemoryPackTemplateRepository,
    InMemoryReportRepository,
    InMemoryScanRepository,
    InMemoryTargetRepository,
    InMemoryToolPackRepository,
)
from hunterx.infrastructure.memory.orchestration import (
    InMemoryExecutionPlanRepository,
    InMemoryOffensiveMissionRepository,
    InMemoryToolSelectionRepository,
)
from hunterx.infrastructure.metrics import InMemoryMetrics
from hunterx.infrastructure.queue import MemoryQueue, NullQueue
from hunterx.infrastructure.secrets import EnvironmentSecrets
from hunterx.infrastructure.telemetry import MemoryTelemetry
from hunterx.infrastructure.telemetry.providers import build_provider
from hunterx.infrastructure.tracing import InMemoryTracer
from hunterx.managers import CacheManager, DependencyManager, EventBus, QueueManager
from hunterx.platform.platform import Platform
from hunterx.reporting.exporter import ReportExporter
from hunterx.reporting.renderers import JsonRenderer, MarkdownRenderer
from hunterx.shared.di import Container
from hunterx.tools.api import register_api_adapters
from hunterx.tools.auth import register_auth_adapters, register_auth_tools
from hunterx.tools.authorization import (
    register_authorization_adapters,
    register_authorization_tools,
)
from hunterx.tools.cloud import register_cloud_adapters, register_cloud_tools
from hunterx.tools.content import register_content_adapters, register_content_tools
from hunterx.tools.dns import register_dns_adapters, register_dns_tools
from hunterx.tools.exploit import register_exploit_adapters
from hunterx.tools.factory.api import ToolIntegrationFactory
from hunterx.tools.intelligence.api import ToolIntelligenceAPI
from hunterx.tools.intelligence.registry import ToolIntelligenceRegistry
from hunterx.tools.javascript import register_javascript_adapters, register_javascript_tools
from hunterx.tools.knowledge import register_knowledge_adapters
from hunterx.tools.livehost import register_live_adapters, register_live_tools
from hunterx.tools.mastery.api import ToolMasteryAPI
from hunterx.tools.parameter import register_parameter_adapters, register_parameter_tools
from hunterx.tools.proof_replay import register_proof_replay_adapters
from hunterx.tools.proxy import register_proxy_adapters
from hunterx.tools.readiness.manifest import CAPABILITY_PROVIDERS
from hunterx.tools.readiness.platform import PlatformDetector
from hunterx.tools.readiness.service import ToolReadinessService
from hunterx.tools.recon import register_recon_adapters, register_recon_tools
from hunterx.tools.registry import ToolRegistry
from hunterx.tools.safe_validation import (
    register_validation_adapters,
)
from hunterx.tools.sast import register_sast_adapters
from hunterx.tools.sdk.engine import ExecutionEngine
from hunterx.tools.secrets import register_secrets_adapters, register_secrets_tools
from hunterx.tools.tech import register_tech_adapters, register_tech_tools
from hunterx.tools.topology import register_topology_adapters, register_topology_tools
from hunterx.tools.vuln import (
    register_vulnerability_providers,
    register_vulnerability_scanner_tools,
    register_vulnerability_scanners,
    register_vulnerability_tools,
)
from hunterx.tools.web import register_web_adapters, register_web_tools

#: Concrete repository constructors keyed by role name (in-memory defaults).
_MEMORY_REPOSITORIES: dict[str, type[object]] = {    "missions": InMemoryMissionRepository,
    "findings": InMemoryFindingRepository,
    "targets": InMemoryTargetRepository,
    "scans": InMemoryScanRepository,
    "assets": InMemoryAssetRepository,
    "reports": InMemoryReportRepository,
    "mission_profiles": InMemoryMissionProfileRepository,
    "mission_templates": InMemoryMissionTemplateRepository,
    "mission_plans": InMemoryMissionPlanRepository,
    "checkpoints": InMemoryCheckpointRepository,
    "mission_timeline": InMemoryMissionTimelineRepository,
    "pack_templates": InMemoryPackTemplateRepository,
    "tool_packs": InMemoryToolPackRepository,
    "offensive_missions": InMemoryOffensiveMissionRepository,
    "execution_plans": InMemoryExecutionPlanRepository,
    "tool_selections": InMemoryToolSelectionRepository,
}

#: Deterministic tool fallback families per capability (used when the Sprint
#: 025 selector yields nothing, keeping the planner functional without a tool
#: catalog). The single source of truth is the Tool Readiness manifest — the
#: planner never hardcodes tool facts.
_TOOL_DEFAULT_CANDIDATES: dict[str, tuple[str, ...]] = CAPABILITY_PROVIDERS


def _build_repositories(settings: Settings, *, force_sql: bool = False) -> dict[str, object]:
    """Build the persistence layer, preferring SQL when configured.

    The default (in-memory) backend keeps the platform runnable with zero
    external services and keeps ``build_platform()`` side-effect free for tests.
    When ``settings.database.url`` is set to a non-default value and SQLAlchemy
    is importable, the six entity repositories are swapped for their SQL-backed
    implementations; mission planning and factory repositories remain in-memory
    (no SQL adapters exist for them yet). ``force_sql`` additionally enables the
    SQL layer for the default SQLite URL (used by the CLI so missions persist
    across invocations).
    """
    repositories: dict[str, object] = {role: constructor() for role, constructor in _MEMORY_REPOSITORIES.items()}
    use_sql = settings.database.url and (
        force_sql or settings.database.url != DEFAULT_DATABASE_URL
    )
    if use_sql:
        try:  # pragma: no cover - depends on optional `db` extra
            from hunterx.infrastructure.db.sql.factory import SessionFactory
            from hunterx.infrastructure.db.sql.repositories import (
                SqlAssetRepository,
                SqlFindingRepository,
                SqlMissionRepository,
                SqlReportRepository,
                SqlScanRepository,
                SqlTargetRepository,
            )
        except ImportError:
            return repositories
        session_factory = SessionFactory(settings.database)
        session_factory.create_all()
        # Attach the append-only audit/version-history listener so every TIDB
        # write in a production build records AuditLog / VersionHistory /
        # ChangeHistory / TimelineEvent rows (Sprint 034.3 §21).
        try:  # pragma: no cover - depends on optional `db` extra
            from hunterx.infrastructure.db.sql.versioning import install_versioning

            install_versioning(session_factory, source="hunterx")
        except ImportError:  # pragma: no cover
            pass
        repositories.update(
            {
                "missions": SqlMissionRepository(session_factory),
                "findings": SqlFindingRepository(session_factory),
                "targets": SqlTargetRepository(session_factory),
                "scans": SqlScanRepository(session_factory),
                "assets": SqlAssetRepository(session_factory),
                "reports": SqlReportRepository(session_factory),
            }
        )
        repositories["session_factory"] = session_factory
    return repositories


def _build_observability(settings: Settings, event_bus: InMemoryEventBus) -> ObservabilityService:
    """Build the observability stack: registry, store, DLQ, metrics, tracing, health."""
    registry = build_registry()
    store = InMemoryEventStore()
    dead_letter = InMemoryDeadLetterQueue()
    event_bus.attach_store(store)
    event_bus.attach_dead_letter(dead_letter)

    metrics = InMemoryMetrics()
    tracer = InMemoryTracer()
    health = HealthRegistry()

    telemetry_kind = getattr(settings, "telemetry", None)
    kind = getattr(telemetry_kind, "provider", "memory") if telemetry_kind else "memory"
    telemetry = build_provider(kind, metrics=metrics, tracer=tracer)

    service = ObservabilityService(
        bus=event_bus,
        registry=registry,
        metrics=metrics,
        tracer=tracer,
        health=health,
        store=store,
        dead_letter=dead_letter,
        telemetry=telemetry,
    )
    return service


def _register_health_probes(
    health: HealthRegistry,
    *,
    core: CoreEngine,
    mission_engine: MissionEngine,
    database: Any | None,
    tool_sdk: ExecutionEngine | None,
    plugin_manager: Any | None,
    knowledge: Any | None,
    ai: Any | None,
    cache: Any | None,
    queue: Any | None,
    scheduler: Any | None,
) -> None:
    """Register the ten canonical component health probes."""
    probes: dict[str, Any] = {
        "core_engine": (lambda: ("ok", "CoreEngine operational")),
        "mission_engine": (lambda: ("ok", "MissionEngine operational")),
        "database": (
            (lambda: ("ok", "Database operational")) if database is None else (lambda db=database: _probe_database(db))
        ),
        "tool_sdk": (
            (lambda: ("ok", "Tool SDK operational"))
            if tool_sdk is None
            else (lambda sdk=tool_sdk: _probe_checkable(sdk, "Tool SDK"))
        ),
        "plugin_manager": (
            (lambda: ("ok", "Plugin manager operational"))
            if plugin_manager is None
            else (lambda pm=plugin_manager: _probe_checkable(pm, "Plugin manager"))
        ),
        "knowledge_engine": (
            (lambda: ("ok", "Knowledge engine operational"))
            if knowledge is None
            else (lambda k=knowledge: _probe_checkable(k, "Knowledge engine"))
        ),
        "ai_engine": (
            (lambda: ("ok", "AI engine operational"))
            if ai is None
            else (lambda provider=ai: _probe_checkable(provider, "AI engine"))
        ),
        "cache": (
            (lambda: ("ok", "Cache operational")) if cache is None else (lambda c=cache: _probe_checkable(c, "Cache"))
        ),
        "queue": (
            (lambda: ("ok", "Queue operational")) if queue is None else (lambda q=queue: _probe_checkable(q, "Queue"))
        ),
        "scheduler": (
            (lambda: ("ok", "Scheduler operational"))
            if scheduler is None
            else (lambda s=scheduler: _probe_checkable(s, "Scheduler"))
        ),
    }
    for name, check in probes.items():
        health.register_callable(name, check)


def _probe_database(db: Any) -> tuple[str, str]:
    """Probe a database session factory via ``check`` or a ping query."""
    check = getattr(db, "check", None)
    if callable(check):
        try:
            return ("ok", "Database operational") if check() else ("down", "Database check failed")
        except Exception as exc:  # noqa: BLE001 - probes must never raise
            return ("down", str(exc))
    return ("ok", "Database operational")


def _probe_checkable(component: Any, label: str) -> tuple[str, str]:
    """Probe a component exposing an optional ``check()`` method."""
    check = getattr(component, "check", None)
    if callable(check):
        try:
            return ("ok", f"{label} operational") if check() else ("down", f"{label} check failed")
        except Exception as exc:  # noqa: BLE001 - probes must never raise
            return ("down", str(exc))
    return ("ok", f"{label} operational")


def _build_adapters(settings: Settings) -> dict[str, object]:
    """Build the infrastructure adapters selected by ``settings``."""
    cache: CachePort = MemoryCache() if settings.cache.backend == "memory" else NullCache()
    queue: QueuePort = MemoryQueue() if settings.queue.backend == "memory" else NullQueue()
    return {
        "event_bus": InMemoryEventBus(),
        "cache": cache,
        "queue": queue,
        "secrets": EnvironmentSecrets(),
        "ai": build_ai_client(settings.ai),
        "telemetry": MemoryTelemetry(),
        "knowledge_graph": InMemoryKnowledgeGraph(),
    }


def _resolve_repository(repositories: dict[str, object], role: str) -> Any:
    """Return a repository by role, substituting defaults when absent."""
    repository = repositories.get(role)
    if repository is not None:
        return repository
    constructor = _MEMORY_REPOSITORIES[role]
    return constructor()


def _build_tidb_stores(repositories: dict[str, object]) -> TidbRepositoryFactory:
    """Build the TIDB repository factory, preferring SQL when configured.

    The recon capability persists discovery records into the TIDB network
    entity set. Without a configured SQL session the platform falls back to the
    in-memory factory so the capability is usable out of the box.
    """
    session_factory = repositories.get("session_factory")
    if session_factory is not None:
        from hunterx.infrastructure.db.sql.crud import SqlTidbRepositoryFactory

        return SqlTidbRepositoryFactory(session_factory)  # type: ignore[arg-type]
    return InMemoryTidbRepositoryFactory()


def _register_ports(
    container: Container[Any],
    *,
    adapters: dict[str, object],
    repositories: dict[str, object],
    tip: ToolIntelligenceAPI,
    observability: ObservabilityService | None = None,
) -> None:
    """Register port implementations and concrete services in the container."""
    container.register_instance(EventBusPort, adapters["event_bus"])  # type: ignore[type-abstract]
    container.register_instance(CachePort, adapters["cache"])  # type: ignore[type-abstract]
    container.register_instance(QueuePort, adapters["queue"])  # type: ignore[type-abstract]
    container.register_instance(SecretsPort, adapters["secrets"])  # type: ignore[type-abstract]
    container.register_instance(AIPort, adapters["ai"])  # type: ignore[type-abstract]
    container.register_instance(TelemetryPort, adapters["telemetry"])  # type: ignore[type-abstract]
    container.register_instance(KnowledgeGraphPort, adapters["knowledge_graph"])  # type: ignore[type-abstract]
    container.register_instance(ToolIntelligencePort, tip)  # type: ignore[type-abstract]
    container.register_instance(ToolIntelligenceRegistry, tip.registry)
    if observability is not None:
        container.register_instance(ObservabilityEventBusPort, adapters["event_bus"])  # type: ignore[type-abstract]
        container.register_instance(MetricsPort, observability.metrics)  # type: ignore[type-abstract]
        container.register_instance(TracerPort, observability.tracer)  # type: ignore[type-abstract]
        container.register_instance(HealthRegistryPort, observability.health)  # type: ignore[type-abstract]
        container.register_instance(EventStorePort, observability.store)  # type: ignore[type-abstract]
        container.register_instance(DeadLetterQueuePort, observability.dead_letter)  # type: ignore[type-abstract]
        container.register_instance(TelemetryProviderPort, observability._telemetry)  # type: ignore[type-abstract]
        container.register_instance(ObservabilityService, observability)

    role_to_port: dict[str, type[object]] = {
        "missions": MissionRepository,
        "findings": FindingRepository,
        "targets": TargetRepository,
        "scans": ScanRepository,
        "assets": AssetRepository,
        "reports": ReportRepository,
        "mission_profiles": MissionProfileRepository,
        "mission_templates": MissionTemplateRepository,
        "mission_plans": MissionPlanRepository,
        "checkpoints": CheckpointRepository,
        "mission_timeline": MissionTimelineRepository,
        "pack_templates": PackTemplateRepository,
        "tool_packs": ToolPackRepository,
        "offensive_missions": OffensiveMissionRepository,
        "execution_plans": ExecutionPlanRepository,
        "tool_selections": ToolSelectionRepository,
    }
    for role, port in role_to_port.items():
        container.register_instance(port, _resolve_repository(repositories, role))  # type: ignore[type-abstract]


def build_platform(settings: Settings | None = None, *, persistence: bool = False) -> Platform:
    """Assemble and return a fully wired :class:`Platform`.

    Args:
        settings: optional typed settings; defaults are loaded when omitted.
        persistence: when ``True``, force the SQL persistence layer even for the
            default SQLite URL so missions survive across CLI invocations and
            process restarts. When ``False`` (default), the platform stays
            in-memory unless a non-default database URL is configured — this
            keeps ``build_platform()`` side-effect free for tests.

    Returns:
        A composed :class:`Platform` with every port, facade, engine, service
        and adapter registered in its dependency container.

    """
    if settings is None:
        settings = load_default_settings()

    container: Container[Any] = Container()
    adapters = _build_adapters(settings)
    repositories = _build_repositories(settings, force_sql=persistence)

    # -- v7 facades --------------------------------------------------------
    tip = ToolIntelligenceAPI()
    register_recon_tools(tip)
    register_dns_tools(tip)
    register_live_tools(tip)
    register_topology_tools(tip)
    register_tech_tools(tip)
    register_web_tools(tip)
    register_content_tools(tip)
    register_javascript_tools(tip)
    register_parameter_tools(tip)
    register_auth_tools(tip)
    register_authorization_tools(tip)
    register_cloud_tools(tip)
    register_vulnerability_tools(tip)
    register_vulnerability_scanner_tools(tip)
    register_secrets_tools(tip)
    mastery = ToolMasteryAPI(tip=tip)
    from hunterx.tools.readiness.knowledge import register_command_knowledge

    register_command_knowledge(tip)
    execution_engine = ExecutionEngine(intelligence=tip.registry)
    tool_readiness = ToolReadinessService(
        tip=tip,
        engine=execution_engine,
        platform=PlatformDetector().detect(),
    )
    register_recon_adapters(execution_engine)
    register_dns_adapters(execution_engine)
    register_live_adapters(execution_engine)
    register_topology_adapters(execution_engine)
    register_tech_adapters(execution_engine, cache=adapters["cache"])  # type: ignore[arg-type]
    register_web_adapters(execution_engine)
    register_content_adapters(execution_engine)
    register_javascript_adapters(execution_engine)
    register_parameter_adapters(execution_engine)
    register_api_adapters(execution_engine)
    register_auth_adapters(execution_engine)
    register_authorization_adapters(execution_engine)
    register_cloud_adapters(execution_engine)
    register_vulnerability_providers(execution_engine)
    register_vulnerability_scanners(execution_engine)
    register_sast_adapters(execution_engine)
    register_secrets_adapters(execution_engine)
    register_proxy_adapters(execution_engine)
    register_exploit_adapters(execution_engine)
    register_knowledge_adapters(execution_engine)
    _validation_adapters = register_validation_adapters(execution_engine)
    for tool_id in _validation_adapters:
        execution_engine.install_hook(tool_id, lambda tool_id, version: "1.0.0")
        execution_engine.install(tool_id, version="1.0.0")
    _proof_adapters = register_proof_replay_adapters(execution_engine)
    for tool_id in _proof_adapters:
        execution_engine.install_hook(tool_id, lambda tool_id, version: "1.0.0")
        execution_engine.install(tool_id, version="1.0.0")
    tool_factory = ToolIntegrationFactory(
        pack_repository=_resolve_repository(repositories, "tool_packs"),  # type: ignore[arg-type]
        template_repository=_resolve_repository(repositories, "pack_templates"),  # type: ignore[arg-type]
    )
    mission_planning = MissionPlanningAPI(
        plans=_resolve_repository(repositories, "mission_plans"),  # type: ignore[arg-type]
        profiles=_resolve_repository(repositories, "mission_profiles"),  # type: ignore[arg-type]
        templates=_resolve_repository(repositories, "mission_templates"),  # type: ignore[arg-type]
        checkpoints=_resolve_repository(repositories, "checkpoints"),  # type: ignore[arg-type]
        timeline=_resolve_repository(repositories, "mission_timeline"),  # type: ignore[arg-type]
        event_bus=adapters["event_bus"],  # type: ignore[arg-type]
    )

    # -- core engines --------------------------------------------------------
    tool_registry = ToolRegistry()
    from hunterx.tools.executor import ToolExecutor

    executor = ToolExecutor(tool_registry)
    workflow_engine = WorkflowEngine(executor)
    planner = DeterministicPlanner()
    correlator = TargetCorrelator()
    risk_scorer = DefaultRiskScorer()
    reasoning_engine = ReasoningEngine(adapters["ai"])  # type: ignore[arg-type]
    renderers = [JsonRenderer(), MarkdownRenderer()]
    report_engine = ReportEngine(
        reports=_resolve_repository(repositories, "reports"),  # type: ignore[arg-type]
        missions=_resolve_repository(repositories, "missions"),  # type: ignore[arg-type]
        findings=_resolve_repository(repositories, "findings"),  # type: ignore[arg-type]
        renderers=renderers,
    )
    mission_engine = MissionEngine(
        missions=_resolve_repository(repositories, "missions"),  # type: ignore[arg-type]
        findings=_resolve_repository(repositories, "findings"),  # type: ignore[arg-type]
        planner=planner,
        workflows=workflow_engine,
        correlator=correlator,
        event_bus=adapters["event_bus"],  # type: ignore[arg-type]
    )
    core = CoreEngine(
        mission_engine=mission_engine,
        workflow_engine=workflow_engine,
        planner=planner,
        correlator=correlator,
        risk_scorer=risk_scorer,
        reasoning_engine=reasoning_engine,
        report_engine=report_engine,
        renderers=renderers,
        tip=tip,
        execution_engine=execution_engine,
        tool_factory=tool_factory,
        mission_planning=mission_planning,
    )

    # -- application services ------------------------------------------------
    mission_service = MissionService(_resolve_repository(repositories, "missions"))  # type: ignore[arg-type]
    finding_service = FindingService(_resolve_repository(repositories, "findings"))  # type: ignore[arg-type]
    report_service = ReportService(
        _resolve_repository(repositories, "reports"),  # type: ignore[arg-type]
        _resolve_repository(repositories, "missions"),  # type: ignore[arg-type]
    )
    tool_factory_service = ToolFactoryService(tool_factory)
    toolchain_service = ToolchainService(
        tip=tip,
        engine=execution_engine,
        event_bus=adapters["event_bus"],  # type: ignore[arg-type]
        mastery=mastery,
    )
    mission_planning_service = MissionPlanningService(
        plans=_resolve_repository(repositories, "mission_plans"),  # type: ignore[arg-type]
        profiles=_resolve_repository(repositories, "mission_profiles"),  # type: ignore[arg-type]
        templates=_resolve_repository(repositories, "mission_templates"),  # type: ignore[arg-type]
        checkpoints=_resolve_repository(repositories, "checkpoints"),  # type: ignore[arg-type]
        timeline=_resolve_repository(repositories, "mission_timeline"),  # type: ignore[arg-type]
        api=mission_planning,
    )
    offensive_orchestration = OffensiveOrchestrationAPI(
        missions=_resolve_repository(repositories, "offensive_missions"),  # type: ignore[arg-type]
        plans=_resolve_repository(repositories, "execution_plans"),  # type: ignore[arg-type]
        execution_engine=execution_engine,
        tip=tip,
        event_bus=adapters["event_bus"],  # type: ignore[arg-type]
        knowledge_graph=adapters["knowledge_graph"],  # type: ignore[arg-type]
    )
    offensive_orchestration_service = OffensiveOrchestrationService(
        missions=_resolve_repository(repositories, "offensive_missions"),  # type: ignore[arg-type]
        plans=_resolve_repository(repositories, "execution_plans"),  # type: ignore[arg-type]
        api=offensive_orchestration,
    )
    tidb_stores = _build_tidb_stores(repositories)
    recon_service = ReconService(
        engine=execution_engine,
        stores=tidb_stores,
        event_bus=adapters["event_bus"],  # type: ignore[arg-type]
    )
    dns_service = DnsService(
        engine=execution_engine,
        stores=tidb_stores,
        event_bus=adapters["event_bus"],  # type: ignore[arg-type]
        cache=adapters["cache"],  # type: ignore[arg-type]
    )
    livehost_service = LiveHostService(
        engine=execution_engine,
        stores=tidb_stores,
        event_bus=adapters["event_bus"],  # type: ignore[arg-type]
        cache=adapters["cache"],  # type: ignore[arg-type]
    )
    topology_service = TopologyService(
        engine=execution_engine,
        stores=tidb_stores,
        event_bus=adapters["event_bus"],  # type: ignore[arg-type]
        cache=adapters["cache"],  # type: ignore[arg-type]
    )
    topology_query_service = TopologyQueryService(
        stores=tidb_stores,
        cache=adapters["cache"],  # type: ignore[arg-type]
    )
    technology_service = FingerprintService(
        engine=execution_engine,
        stores=tidb_stores,
        event_bus=adapters["event_bus"],  # type: ignore[arg-type]
        cache=adapters["cache"],  # type: ignore[arg-type]
    )
    technology_query_service = TechnologyQueryService(
        stores=tidb_stores,
        cache=adapters["cache"],  # type: ignore[arg-type]
    )
    crawl_service = CrawlService(
        engine=execution_engine,
        stores=tidb_stores,
        event_bus=adapters["event_bus"],  # type: ignore[arg-type]
        cache=adapters["cache"],  # type: ignore[arg-type]
    )
    crawl_query_service = CrawlQueryService(
        stores=tidb_stores,
        cache=adapters["cache"],  # type: ignore[arg-type]
    )
    javascript_service = JavaScriptService(
        engine=execution_engine,
        stores=tidb_stores,
        event_bus=adapters["event_bus"],  # type: ignore[arg-type]
        cache=adapters["cache"],  # type: ignore[arg-type]
    )
    javascript_query_service = JavaScriptQueryService(
        stores=tidb_stores,
        cache=adapters["cache"],  # type: ignore[arg-type]
    )
    auth_service = AuthService(
        engine=execution_engine,
        stores=tidb_stores,
        event_bus=adapters["event_bus"],  # type: ignore[arg-type]
        cache=adapters["cache"],  # type: ignore[arg-type]
    )
    auth_query_service = AuthQueryService(
        stores=tidb_stores,
        cache=adapters["cache"],  # type: ignore[arg-type]
    )
    authorization_service = AuthorizationService(
        engine=execution_engine,
        stores=tidb_stores,
        event_bus=adapters["event_bus"],  # type: ignore[arg-type]
        cache=adapters["cache"],  # type: ignore[arg-type]
    )
    authorization_query_service = AuthorizationQueryService(
        stores=tidb_stores,
        cache=adapters["cache"],  # type: ignore[arg-type]
    )
    cloud_service = CloudService(
        engine=execution_engine,
        stores=tidb_stores,
        event_bus=adapters["event_bus"],  # type: ignore[arg-type]
        cache=adapters["cache"],  # type: ignore[arg-type]
    )
    cloud_query_service = CloudQueryService(
        stores=tidb_stores,
        cache=adapters["cache"],  # type: ignore[arg-type]
    )
    vulnerability_knowledge_service = VulnerabilityKnowledgeService(
        engine=execution_engine,
        stores=tidb_stores,
        event_bus=adapters["event_bus"],  # type: ignore[arg-type]
        cache=adapters["cache"],  # type: ignore[arg-type]
        store=VulnerabilityKnowledgeStore(
            cache=adapters["cache"],  # type: ignore[arg-type]
            analysis_version="1.0.0",
        ),
    )
    vulnerability_correlation_service = VulnerabilityCorrelationService(
        store=vulnerability_knowledge_service.store,
        stores=tidb_stores,
        event_bus=adapters["event_bus"],  # type: ignore[arg-type]
    )
    vulnerability_query_service = VulnerabilityQueryService(
        stores=tidb_stores,
        cache=adapters["cache"],  # type: ignore[arg-type]
    )
    vulnerability_validation_service = VulnerabilityValidationService(
        engine=execution_engine,
        stores=tidb_stores,
        event_bus=adapters["event_bus"],  # type: ignore[arg-type]
        knowledge_graph=adapters["knowledge_graph"],  # type: ignore[arg-type]
        tip=tip,
    )
    vulnerability_proof_service = VulnerabilityProofService(
        engine=execution_engine,
        stores=tidb_stores,
        event_bus=adapters["event_bus"],  # type: ignore[arg-type]
        knowledge_graph=adapters["knowledge_graph"],  # type: ignore[arg-type]
        tip=tip,
    )
    vulnerability_proof_strategy_service = VulnerabilityProofStrategyService(
        stores=tidb_stores,
        event_bus=adapters["event_bus"],  # type: ignore[arg-type]
        knowledge_graph=adapters["knowledge_graph"],  # type: ignore[arg-type]
        tip=tip,
    )
    vulnerability_finding_service = VulnerabilityFindingService(
        engine=execution_engine,
        stores=tidb_stores,
        event_bus=adapters["event_bus"],  # type: ignore[arg-type]
        knowledge_graph=adapters["knowledge_graph"],  # type: ignore[arg-type]
        tip=tip,
        findings=_resolve_repository(repositories, "findings"),  # type: ignore[arg-type]
    )

    # -- professional finding intelligence & reporting (Sprint 029) -----------
    professional_reporting_service = ProfessionalReportingService(
        stores=tidb_stores,
        event_bus=adapters["event_bus"],  # type: ignore[arg-type]
        exporter=ReportExporter(),
    )

    # -- adaptive target intelligence (Sprint 026) ---------------------------
    target_intelligence_engine = TargetIntelligenceEngine()
    target_intelligence_service = TargetIntelligenceService(
        engine=target_intelligence_engine,
        stores=tidb_stores,
        event_bus=adapters["event_bus"],  # type: ignore[arg-type]
        cache=adapters["cache"],  # type: ignore[arg-type]
        mastery=mastery,
        mission_type="bug-bounty",
    )
    target_intelligence_query_service = TargetIntelligenceQueryService(
        stores=tidb_stores,
        cache=adapters["cache"],  # type: ignore[arg-type]
    )
    core.target_intelligence = target_intelligence_engine

    # -- target memory & campaign intelligence (Sprint 030) -----------------
    target_memory_service = TargetMemoryService(
        stores=tidb_stores,
        event_bus=adapters["event_bus"],  # type: ignore[arg-type]
        cache=adapters["cache"],  # type: ignore[arg-type]
        tenant="default",
    )
    target_memory_query_service = TargetMemoryQueryService(
        stores=tidb_stores,
        cache=adapters["cache"],  # type: ignore[arg-type]
    )

    # -- adaptive mission & attack-path planning (Sprint 027) ----------------
    adaptive_mission_engine = AdaptiveMissionPlanningEngine(
        tool_selection_engine=ToolSelectionEngine(
            selector=mastery,
            mission_type="bug-bounty",
            default_candidates=_TOOL_DEFAULT_CANDIDATES,
        ),
    )
    adaptive_mission_service = AdaptiveMissionPlanningService(
        engine=adaptive_mission_engine,
        stores=tidb_stores,
        event_bus=adapters["event_bus"],  # type: ignore[arg-type]
        cache=adapters["cache"],  # type: ignore[arg-type]
    )
    adaptive_mission_query_service = AdaptiveMissionPlanningQueryService(
        stores=tidb_stores,
        cache=adapters["cache"],  # type: ignore[arg-type]
    )

    # -- autonomous mission orchestration (Sprint 032) ----------------------
    mission_orchestrator = MissionOrchestrator(planning=adaptive_mission_engine)
    mission_orchestration_engine = MissionOrchestrationEngine(orchestrator=mission_orchestrator)
    mission_orchestration_service = MissionOrchestrationService(
        engine=mission_orchestration_engine,
        stores=tidb_stores,
        event_bus=adapters["event_bus"],  # type: ignore[arg-type]
    )
    mission_orchestration_query_service = MissionOrchestrationQueryService(
        stores=tidb_stores,
        engine=mission_orchestration_engine,
    )
    mission_dashboard_service = MissionDashboardService(
        service=mission_orchestration_service,
        query=mission_orchestration_query_service,
    )
    mission_execution_service = MissionExecutionService(
        orchestration=mission_orchestration_service,
        planning=adaptive_mission_engine,
        execution_engine=execution_engine,
        event_bus=adapters["event_bus"],  # type: ignore[arg-type]
        readiness=tool_readiness,
    )

    # -- observability -------------------------------------------------------
    observability = _build_observability(settings, adapters["event_bus"])  # type: ignore[arg-type]
    _register_health_probes(
        observability.health,
        core=core,
        mission_engine=mission_engine,
        database=repositories.get("session_factory"),
        tool_sdk=execution_engine,
        plugin_manager=None,
        knowledge=None,
        ai=adapters["ai"],  # type: ignore[arg-type]
        cache=adapters["cache"],  # type: ignore[arg-type]
        queue=adapters["queue"],  # type: ignore[arg-type]
        scheduler=None,
    )

    # -- container registration ----------------------------------------------
    _register_ports(
        container,
        adapters=adapters,
        repositories=repositories,
        tip=tip,
        observability=observability,
    )
    container.register_instance(CacheManager, CacheManager(adapters["cache"]))  # type: ignore[arg-type]
    container.register_instance(QueueManager, QueueManager(adapters["queue"]))  # type: ignore[arg-type]
    container.register_instance(EventBus, EventBus(adapters["event_bus"]))  # type: ignore[arg-type]
    container.register_instance(DependencyManager, DependencyManager(container))
    container.register_instance(ToolIntegrationFactory, tool_factory)
    container.register_instance(ExecutionEngine, execution_engine)
    container.register_instance(MissionPlanningAPI, mission_planning)
    container.register_instance(OffensiveOrchestrationAPI, offensive_orchestration)
    container.register_instance(OffensiveOrchestrationService, offensive_orchestration_service)
    container.register_instance(ToolIntelligenceAPI, tip)
    container.register_instance(ToolMasteryAPI, mastery)
    container.register_instance(ToolMasteryPort, mastery)  # type: ignore[type-abstract]
    container.register_instance(CoreEngine, core)
    container.register_instance(MissionEngine, mission_engine)
    container.register_instance(WorkflowEngine, workflow_engine)
    container.register_instance(ReportEngine, report_engine)
    container.register_instance(MissionService, mission_service)
    container.register_instance(FindingService, finding_service)
    container.register_instance(ReportService, report_service)
    container.register_instance(ToolFactoryService, tool_factory_service)
    container.register_instance(ToolchainService, toolchain_service)
    container.register_instance(MissionPlanningService, mission_planning_service)
    container.register_instance(TidbRepositoryFactory, tidb_stores)  # type: ignore[type-abstract]
    container.register_instance(ReconService, recon_service)
    container.register_instance(DnsService, dns_service)
    container.register_instance(LiveHostService, livehost_service)
    container.register_instance(TopologyService, topology_service)
    container.register_instance(TopologyQueryService, topology_query_service)
    container.register_instance(FingerprintService, technology_service)
    container.register_instance(TechnologyQueryService, technology_query_service)
    container.register_instance(CrawlService, crawl_service)
    container.register_instance(CrawlQueryService, crawl_query_service)
    container.register_instance(JavaScriptService, javascript_service)
    container.register_instance(JavaScriptQueryService, javascript_query_service)
    container.register_instance(AuthService, auth_service)
    container.register_instance(AuthQueryService, auth_query_service)
    container.register_instance(AuthorizationService, authorization_service)
    container.register_instance(AuthorizationQueryService, authorization_query_service)
    container.register_instance(CloudService, cloud_service)
    container.register_instance(CloudQueryService, cloud_query_service)
    container.register_instance(VulnerabilityKnowledgeService, vulnerability_knowledge_service)
    container.register_instance(VulnerabilityCorrelationService, vulnerability_correlation_service)
    container.register_instance(VulnerabilityQueryService, vulnerability_query_service)
    container.register_instance(VulnerabilityValidationService, vulnerability_validation_service)
    container.register_instance(VulnerabilityProofService, vulnerability_proof_service)
    container.register_instance(VulnerabilityProofStrategyService, vulnerability_proof_strategy_service)
    container.register_instance(VulnerabilityFindingService, vulnerability_finding_service)
    container.register_instance(ProfessionalReportingService, professional_reporting_service)
    container.register_instance(VulnerabilityKnowledgeStore, vulnerability_knowledge_service.store)
    container.register_instance(TargetIntelligenceEngine, target_intelligence_engine)
    container.register_instance(TargetIntelligenceService, target_intelligence_service)
    container.register_instance(TargetIntelligenceQueryService, target_intelligence_query_service)
    container.register_instance(TargetMemoryService, target_memory_service)
    container.register_instance(TargetMemoryQueryService, target_memory_query_service)
    container.register_instance(AdaptiveMissionPlanningEngine, adaptive_mission_engine)
    container.register_instance(AdaptiveMissionPlanningService, adaptive_mission_service)
    container.register_instance(AdaptiveMissionPlanningQueryService, adaptive_mission_query_service)
    container.register_instance(MissionOrchestrator, mission_orchestrator)
    container.register_instance(MissionOrchestrationEngine, mission_orchestration_engine)
    container.register_instance(MissionOrchestrationService, mission_orchestration_service)
    container.register_instance(MissionOrchestrationQueryService, mission_orchestration_query_service)
    container.register_instance(MissionDashboardService, mission_dashboard_service)
    container.register_instance(MissionExecutionService, mission_execution_service)
    container.register_instance(ToolReadinessService, tool_readiness)

    return Platform(
        settings=settings,
        container=container,
        core=core,
        tip=tip,
        execution_engine=execution_engine,
        tool_factory=tool_factory,
        mission_planning=mission_planning,
        mastery=mastery,
        mission_service=mission_service,
        finding_service=finding_service,
        report_service=report_service,
        tool_factory_service=tool_factory_service,
        toolchain_service=toolchain_service,
        mission_planning_service=mission_planning_service,
        offensive_orchestration=offensive_orchestration,
        offensive_orchestration_service=offensive_orchestration_service,
        recon_service=recon_service,
        dns_service=dns_service,
        livehost_service=livehost_service,
        topology_service=topology_service,
        topology_query_service=topology_query_service,
        technology_service=technology_service,
        technology_query_service=technology_query_service,
        crawl_service=crawl_service,
        crawl_query_service=crawl_query_service,
        javascript_service=javascript_service,
        javascript_query_service=javascript_query_service,
        auth_service=auth_service,
        auth_query_service=auth_query_service,
        authorization_service=authorization_service,
        authorization_query_service=authorization_query_service,
        cloud_service=cloud_service,
        cloud_query_service=cloud_query_service,
        vulnerability_knowledge_service=vulnerability_knowledge_service,
        vulnerability_correlation_service=vulnerability_correlation_service,
        vulnerability_query_service=vulnerability_query_service,
        vulnerability_validation_service=vulnerability_validation_service,
        vulnerability_proof_service=vulnerability_proof_service,
        vulnerability_proof_strategy_service=vulnerability_proof_strategy_service,
        vulnerability_finding_service=vulnerability_finding_service,
        professional_reporting_service=professional_reporting_service,
        target_intelligence=target_intelligence_engine,
        target_intelligence_service=target_intelligence_service,
        target_intelligence_query_service=target_intelligence_query_service,
        target_memory_service=target_memory_service,
        target_memory_query_service=target_memory_query_service,
        adaptive_mission_planning=adaptive_mission_engine,
        adaptive_mission_planning_service=adaptive_mission_service,
        adaptive_mission_planning_query_service=adaptive_mission_query_service,
        mission_orchestration=mission_orchestration_engine,
        mission_orchestration_service=mission_orchestration_service,
        mission_orchestration_query_service=mission_orchestration_query_service,
        mission_dashboard_service=mission_dashboard_service,
        mission_execution_service=mission_execution_service,
        tool_readiness_service=tool_readiness,
        event_bus=adapters["event_bus"],  # type: ignore[arg-type]
        cache=adapters["cache"],  # type: ignore[arg-type]
        queue=adapters["queue"],  # type: ignore[arg-type]
        secrets=adapters["secrets"],  # type: ignore[arg-type]
        ai=adapters["ai"],  # type: ignore[arg-type]
        telemetry=adapters["telemetry"],  # type: ignore[arg-type]
        knowledge_graph=adapters["knowledge_graph"],  # type: ignore[arg-type]
        observability=observability,
        event_registry=observability.registry,
        metrics=observability.metrics,
        tracer=observability.tracer,
        health=observability.health,
        tidb=tidb_stores,
        event_store=observability.store,
        dead_letter=observability.dead_letter,
        repositories=repositories,
    )
