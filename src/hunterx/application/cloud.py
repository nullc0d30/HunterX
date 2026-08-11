# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Cloud & SaaS attack-surface intelligence use-case services.

``CloudService`` is the orchestrator — the bridge between a mission and the
cloud intelligence tooling. Given a target and an input bundle of already-
acquired static material, it validates scope, builds a :class:`CloudStrategy`,
runs the in-process analyzer through the :class:`ExecutionEngine`, folds in
existing TIDB intelligence, classifies, validates, correlates, confidence-
scores, diffs history, persists everything to the TIDB, updates the attack-
surface topology and publishes ``cloud.*`` events.

``CloudQueryService`` reads persisted cloud intelligence back from the TIDB and
answers the reporting queries (providers, accounts, regions, resources,
services, endpoints, environments, identities, roles, permissions,
integrations, SaaS providers, SaaS integrations, webhooks, dependencies,
storage, compute, containers, Kubernetes, databases, message infrastructure,
API gateways, CDNs, load balancers, CI/CD, secret-management indicators,
exposure indicators, changes and runs). Both services depend on ports only.

Security boundary: intelligence & discovery only. No cloud exploitation, no
credential use, no authentication to cloud accounts, no secret retrieval, no
bucket takeover and no privilege testing.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from hunterx.domain.cloud.classification import CloudClassifier
from hunterx.domain.cloud.confidence import (
    CloudConfidenceEngine,
    CloudConfidencePolicy,
)
from hunterx.domain.cloud.correlator import CloudCorrelator
from hunterx.domain.cloud.history import CloudHistory
from hunterx.domain.cloud.models import (
    ApiGatewayResourceObservation,
    CdnResourceObservation,
    CiCdResourceObservation,
    CloudAccountObservation,
    CloudBatch,
    CloudChange,
    CloudDependencyObservation,
    CloudEndpointObservation,
    CloudEnvironmentObservation,
    CloudEvidence,
    CloudExecutionSummary,
    CloudExposureObservation,
    CloudIdentityObservation,
    CloudIntegrationObservation,
    CloudObservation,
    CloudPermissionObservation,
    CloudProviderObservation,
    CloudRegionObservation,
    CloudResourceObservation,
    CloudRoleObservation,
    CloudServiceObservation,
    CloudTarget,
    ComputeResourceObservation,
    ContainerResourceObservation,
    DatabaseResourceObservation,
    KubernetesResourceObservation,
    LoadBalancerResourceObservation,
    MessageInfrastructureObservation,
    SaaSApplicationObservation,
    SaaSIntegrationObservation,
    SaaSProviderObservation,
    SecretManagementObservation,
    StorageResourceObservation,
    WebhookObservation,
    infer_asset_type,
    observations_from_payload,
)
from hunterx.domain.cloud.scope import (
    CloudScopeEnforcer,
    CloudScopePolicy,
)
from hunterx.domain.cloud.strategy import (
    CloudStrategy,
    CloudStrategyBuilder,
)
from hunterx.domain.cloud.validator import CloudValidator
from hunterx.domain.entities.tidb.cloud_intelligence import (
    ApiGatewayResource as TidbApiGatewayResource,
)
from hunterx.domain.entities.tidb.cloud_intelligence import (
    CdnResource as TidbCdnResource,
)
from hunterx.domain.entities.tidb.cloud_intelligence import (
    CiCdResource as TidbCiCdResource,
)
from hunterx.domain.entities.tidb.cloud_intelligence import (
    CloudAccount as TidbCloudAccount,
)
from hunterx.domain.entities.tidb.cloud_intelligence import (
    CloudChange as TidbCloudChange,
)
from hunterx.domain.entities.tidb.cloud_intelligence import (
    CloudDependency as TidbCloudDependency,
)
from hunterx.domain.entities.tidb.cloud_intelligence import (
    CloudEndpoint as TidbCloudEndpoint,
)
from hunterx.domain.entities.tidb.cloud_intelligence import (
    CloudEnvironment as TidbCloudEnvironment,
)
from hunterx.domain.entities.tidb.cloud_intelligence import (
    CloudEvidence as TidbCloudEvidence,
)
from hunterx.domain.entities.tidb.cloud_intelligence import (
    CloudExposureIndicator as TidbCloudExposureIndicator,
)
from hunterx.domain.entities.tidb.cloud_intelligence import (
    CloudIdentity as TidbCloudIdentity,
)
from hunterx.domain.entities.tidb.cloud_intelligence import (
    CloudIntegration as TidbCloudIntegration,
)
from hunterx.domain.entities.tidb.cloud_intelligence import (
    CloudObservation as TidbCloudObservation,
)
from hunterx.domain.entities.tidb.cloud_intelligence import (
    CloudPermission as TidbCloudPermission,
)
from hunterx.domain.entities.tidb.cloud_intelligence import (
    CloudProvider as TidbCloudProvider,
)
from hunterx.domain.entities.tidb.cloud_intelligence import (
    CloudRegion as TidbCloudRegion,
)
from hunterx.domain.entities.tidb.cloud_intelligence import (
    CloudResource as TidbCloudResource,
)
from hunterx.domain.entities.tidb.cloud_intelligence import (
    CloudRole as TidbCloudRole,
)
from hunterx.domain.entities.tidb.cloud_intelligence import (
    CloudRun as TidbCloudRun,
)
from hunterx.domain.entities.tidb.cloud_intelligence import (
    CloudService as TidbCloudService,
)
from hunterx.domain.entities.tidb.cloud_intelligence import (
    ComputeResource as TidbComputeResource,
)
from hunterx.domain.entities.tidb.cloud_intelligence import (
    ContainerResource as TidbContainerResource,
)
from hunterx.domain.entities.tidb.cloud_intelligence import (
    DatabaseResource as TidbDatabaseResource,
)
from hunterx.domain.entities.tidb.cloud_intelligence import (
    KubernetesResource as TidbKubernetesResource,
)
from hunterx.domain.entities.tidb.cloud_intelligence import (
    LoadBalancerResource as TidbLoadBalancerResource,
)
from hunterx.domain.entities.tidb.cloud_intelligence import (
    MessageInfrastructure as TidbMessageInfrastructure,
)
from hunterx.domain.entities.tidb.cloud_intelligence import (
    SaaSApplication as TidbSaaSApplication,
)
from hunterx.domain.entities.tidb.cloud_intelligence import (
    SaaSIntegration as TidbSaaSIntegration,
)
from hunterx.domain.entities.tidb.cloud_intelligence import (
    SaaSProvider as TidbSaaSProvider,
)
from hunterx.domain.entities.tidb.cloud_intelligence import (
    SecretManagementIndicator as TidbSecretManagementIndicator,
)
from hunterx.domain.entities.tidb.cloud_intelligence import (
    StorageResource as TidbStorageResource,
)
from hunterx.domain.entities.tidb.cloud_intelligence import (
    Webhook as TidbWebhook,
)
from hunterx.domain.entities.tidb.topology import TopologyRelationship as TidbTopologyRelationship
from hunterx.domain.events.types import (
    CloudAccountDiscoveredEvent,
    CloudCdnDiscoveredEvent,
    CloudChangeDetectedEvent,
    CloudComputeDiscoveredEvent,
    CloudConflictDetectedEvent,
    CloudContainerDiscoveredEvent,
    CloudCorrelationCompletedEvent,
    CloudDatabaseDiscoveredEvent,
    CloudDependencyDiscoveredEvent,
    CloudEndpointDiscoveredEvent,
    CloudEnvironmentDiscoveredEvent,
    CloudExposureDiscoveredEvent,
    CloudGatewayDiscoveredEvent,
    CloudIamDiscoveredEvent,
    CloudIdentityDiscoveredEvent,
    CloudIntelligenceCompletedEvent,
    CloudIntelligenceFailedEvent,
    CloudIntelligenceStartedEvent,
    CloudKubernetesDiscoveredEvent,
    CloudLoadBalancerDiscoveredEvent,
    CloudPhaseStartedEvent,
    CloudProviderDiscoveredEvent,
    CloudRegionDiscoveredEvent,
    CloudResourceDiscoveredEvent,
    CloudSaasDiscoveredEvent,
    CloudSaasIntegrationDiscoveredEvent,
    CloudServerlessDiscoveredEvent,
    CloudServiceDiscoveredEvent,
    CloudStorageDiscoveredEvent,
    CloudWebhookDiscoveredEvent,
)
from hunterx.domain.execution import ExecutionContext
from hunterx.domain.ports.messaging import CachePort, EventBusPort
from hunterx.domain.ports.tidb_repositories import TidbRepositoryFactory
from hunterx.domain.recon.models import ReconMode
from hunterx.domain.topology.enums import EntityKind, RelationshipType
from hunterx.domain.topology.models import GraphRelationship, TopologyEntity
from hunterx.shared.ids import generate_id
from hunterx.shared.time import utcnow_iso
from hunterx.tools.cloud.registry import CLOUD_TOOL_IDS
from hunterx.tools.sdk.context import ExecutionContextBuilder
from hunterx.tools.sdk.engine import ExecutionEngine


class CloudService:
    """Run cloud & SaaS intelligence missions through the Tool SDK.

    Usage::

        service = CloudService(engine=engine, stores=stores, event_bus=bus)
        batch = service.run(mission_id="m1", target="example.com",
                            parameters={"cloud_input": {...}})
    """

    def __init__(
        self,
        *,
        engine: ExecutionEngine,
        stores: TidbRepositoryFactory | None = None,
        event_bus: EventBusPort | None = None,
        cache: CachePort | None = None,
        scope: CloudScopePolicy | None = None,
        strategy_builder: CloudStrategyBuilder | None = None,
        classifier: CloudClassifier | None = None,
        confidence: CloudConfidencePolicy | None = None,
        correlator: CloudCorrelator | None = None,
        validator: CloudValidator | None = None,
        history: CloudHistory | None = None,
    ) -> None:
        self._engine = engine
        self._stores = stores
        self._event_bus = event_bus
        self._cache = cache
        self._scope = scope or CloudScopePolicy()
        self._strategy_builder = strategy_builder or CloudStrategyBuilder()
        self._classifier = classifier or CloudClassifier()
        self._confidence = CloudConfidenceEngine(confidence or CloudConfidencePolicy())
        self._validator = validator or CloudValidator()
        self._correlator = correlator or CloudCorrelator(
            scope=self._scope,
            confidence=self._confidence.policy,
        )
        self._history = history or CloudHistory()
        self._scope_enforcer = CloudScopeEnforcer(self._scope)

    @property
    def engine(self) -> ExecutionEngine:
        """Return the execution engine used by this service."""
        return self._engine

    @property
    def correlator(self) -> CloudCorrelator:
        """Return the correlator used to merge cloud observations."""
        return self._correlator

    def run(
        self,
        *,
        mission_id: str = "",
        target: CloudTarget | str,
        mode: ReconMode | str = ReconMode.HYBRID,
        tools: Sequence[str] | None = None,
        parameters: Mapping[str, Any] | None = None,
        with_history: bool = False,
        historical: Sequence[Any] | None = None,
        min_confidence: float | None = None,
        max_concurrency: int = 4,
    ) -> CloudBatch:
        """Execute a cloud intelligence run and return the correlated batch.

        Args:
            mission_id: owning mission id (empty for ad-hoc runs).
            target: the target to analyse (URL, hostname, domain or IP).
            mode: the execution posture (passive, active or hybrid). The
                analyzer is in-process and intelligence-only, so passive
                postures still run it against supplied static material.
            tools: analysis tool ids to run; defaults to every registered cloud
                tool. Requesting an unregistered tool raises :class:`ValueError`.
            parameters: per-tool parameters merged into each execution context
                (typically a ``cloud_input`` bundle).
            with_history: compare current observations against ``historical``.
            historical: historical observations to diff against.
            min_confidence: minimum confidence for a record to be retained.
            max_concurrency: execution concurrency ceiling.

        Returns:
            The :class:`CloudBatch` with correlated records, evidence,
            conflicts, changes and execution summaries.

        Raises:
            ValueError: when the target is out of scope or a requested tool is
                not registered.

        """
        cloud_target = target if isinstance(target, CloudTarget) else _make_target(target)
        decision = self._scope_enforcer.allows_target(cloud_target)
        if not decision.allowed:
            raise ValueError(f"cloud target is out of scope: {decision.reason}")
        recon_mode = _make_mode(mode)
        selected = self._select_tools(tools)
        correlation_id = generate_id()
        parameters = dict(parameters or {})
        parameters["mode"] = recon_mode.value
        if cloud_target.target_id:
            parameters["target_id"] = cloud_target.target_id

        strategy = self._strategy_builder.build(
            cloud_target.value,
            mode=recon_mode,
            target_kind=cloud_target.target_type,
            tools=tuple(selected) if selected else (),
            include_history=with_history,
            min_confidence=min_confidence,
            max_concurrency=max_concurrency,
        )
        runnable = [tool_id for tool_id in strategy.tools if tool_id in selected]

        batch = CloudBatch(
            mission_id=mission_id,
            correlation_id=correlation_id,
            target=cloud_target,
            mode=recon_mode,
        )
        self._publish(
            CloudIntelligenceStartedEvent(
                mission_id,
                correlation_id,
                cloud_target.value,
                mode=recon_mode.value,
                tools=list(runnable),
            )
        )

        raw: list[Any] = []
        try:
            self._publish(CloudPhaseStartedEvent(correlation_id, "collection", mission_id=mission_id))
            for tool_id in runnable:
                context = self._build_context(
                    tool_id,
                    cloud_target,
                    mission_id,
                    correlation_id,
                    parameters,
                    strategy,
                )
                outcome = self._engine.execute(context)
                result = outcome.result
                found = observations_from_payload(result.output.json) if result.status.is_success else []
                raw.extend(found)
                summary = CloudExecutionSummary(
                    tool_id=tool_id,
                    status=result.status.value,
                    observations=len(found),
                    resources=len([obs for obs in found if isinstance(obs, CloudResourceObservation)]),
                    duration_ms=result.duration_ms,
                    error=result.error,
                )
                batch.add_execution(summary)

            if strategy.include_existing and self._stores is not None:
                self._publish(CloudPhaseStartedEvent(correlation_id, "existing-intelligence", mission_id=mission_id))
                raw.extend(self._collect_existing(cloud_target, mission_id, correlation_id))

            self._publish(CloudPhaseStartedEvent(correlation_id, "classification", mission_id=mission_id))
            classified = self._classify(raw)

            self._publish(CloudPhaseStartedEvent(correlation_id, "validation", mission_id=mission_id))
            classified = self._validator.filter_valid(classified)

            self._publish(CloudPhaseStartedEvent(correlation_id, "correlation", mission_id=mission_id))
            correlation = self._correlator.correlate(classified, min_confidence=strategy.min_confidence)
            batch.records = list(correlation.records)
            for conflict in correlation.conflicts:
                batch.add_conflict(conflict)
                self._publish(
                    CloudConflictDetectedEvent(
                        correlation_id,
                        conflict.subject,
                        conflict.conflict_type,
                        selected=conflict.selected,
                        mission_id=mission_id,
                    )
                )
            self._publish(
                CloudCorrelationCompletedEvent(
                    mission_id,
                    correlation_id,
                    raw_observations=len(raw),
                    correlated_observations=len(batch.records),
                    conflicts=len(batch.conflicts),
                )
            )

            self._publish(CloudPhaseStartedEvent(correlation_id, "history", mission_id=mission_id))
            if strategy.include_history and historical is not None:
                comparison = self._history.compare(historical, batch.records)
                for change in comparison.changes:
                    batch.add_change(change)
                    self._publish_change(change, correlation_id, mission_id)

            self._publish_discoveries(batch, correlation_id, mission_id)

            if self._stores is not None:
                self._publish(CloudPhaseStartedEvent(correlation_id, "persistence", mission_id=mission_id))
                self._persist(batch, cloud_target, mission_id, correlation_id)

            self._publish(CloudPhaseStartedEvent(correlation_id, "topology", mission_id=mission_id))
            if self._stores is not None:
                self._update_topology(batch, mission_id, correlation_id)

            self._publish(
                CloudIntelligenceCompletedEvent(
                    mission_id,
                    correlation_id,
                    target=cloud_target.value,
                    providers=batch.provider_count(),
                    accounts=_count_of(batch.records, CloudAccountObservation),
                    regions=_count_of(batch.records, CloudRegionObservation),
                    resources=batch.resource_count(),
                    services=batch.service_count(),
                    endpoints=batch.endpoint_count(),
                    environments=_count_of(batch.records, CloudEnvironmentObservation),
                    identities=_count_of(batch.records, CloudIdentityObservation),
                    saas_providers=_count_of(batch.records, SaaSProviderObservation),
                    saas_integrations=_count_of(batch.records, SaaSIntegrationObservation),
                    webhooks=_count_of(batch.records, WebhookObservation),
                    changes=batch.change_count(),
                    conflicts=batch.conflict_count(),
                )
            )
        except Exception as exc:  # noqa: BLE001 - surfaced as a completion failure
            self._publish(
                CloudIntelligenceFailedEvent(
                    mission_id,
                    correlation_id,
                    cloud_target.value,
                    str(exc),
                )
            )
            raise
        return batch

    # -- pipeline helpers ---------------------------------------------------

    def _select_tools(self, tools: Sequence[str] | None) -> list[str]:
        """Return the registered cloud analysis tools to run."""
        registered = self._engine.adapter_for
        if tools is None:
            return [tool_id for tool_id in CLOUD_TOOL_IDS if registered(tool_id) is not None]
        requested = list(tools)
        missing = [tool_id for tool_id in requested if registered(tool_id) is None]
        if missing:
            raise ValueError(f"requested cloud tools are not registered: {', '.join(missing)}")
        return requested

    def _build_context(
        self,
        tool_id: str,
        target: CloudTarget,
        mission_id: str,
        correlation_id: str,
        parameters: Mapping[str, Any],
        strategy: CloudStrategy,
    ) -> ExecutionContext:
        """Build an execution context for one cloud analysis tool."""
        merged = dict(parameters)
        merged.setdefault("target", target.value)
        merged.setdefault("target_kind", target.target_type)
        return (
            ExecutionContextBuilder(tool_id=tool_id, target=target.value)
            .with_mission(mission_id)
            .with_target_type(target.target_type)
            .with_profile("cloud")
            .with_correlation_id(correlation_id)
            .with_permissions(("network",))
            .with_parameters(merged)
            .build()
        )

    def _classify(self, observations: Sequence[Any]) -> list[Any]:
        """Refine plane/exposure/environment classifications deterministically."""
        classified: list[Any] = []
        for observation in observations:
            if isinstance(observation, CloudEndpointObservation):
                plane = self._classifier.classify_plane(observation.endpoint, observation.service, observation.provider)
                exposure = self._classifier.classify_exposure(
                    observation.endpoint,
                    observation.provider,
                    public_hint=observation.exposure in ("public", "public-indicator"),
                )
                if plane != observation.plane or exposure != observation.exposure:
                    observation = CloudEndpointObservation(
                        endpoint=observation.endpoint,
                        provider=observation.provider,
                        service=observation.service,
                        plane=plane,
                        exposure=exposure,
                        region=observation.region,
                        environment=observation.environment,
                        domain=observation.domain,
                        confidence=observation.confidence,
                        indicators=observation.indicators,
                        evidence=observation.evidence,
                        source=observation.source,
                        tool_id=observation.tool_id,
                        target_key=observation.target_key,
                        correlation_id=observation.correlation_id,
                        mission_id=observation.mission_id,
                        execution_id=observation.execution_id,
                        observed_at=observation.observed_at,
                        record_id=observation.record_id,
                    )
            classified.append(observation)
        return classified

    def _collect_existing(
        self,
        target: CloudTarget,
        mission_id: str,
        correlation_id: str,
    ) -> list[Any]:
        """Fold previously persisted cloud intelligence into the run."""
        stores = self._stores
        if stores is None:
            return []
        records = self._load_persisted(target.value)
        observations: list[Any] = []
        for record in records:
            converted = _from_tidb(record, target.value, mission_id, correlation_id)
            if converted is not None and self._scope_enforcer.allows_observation(converted).allowed:
                observations.append(converted)
        return observations

    def _load_persisted(self, target_key: str) -> list[Any]:
        """Read previously persisted cloud records for ``target_key``."""
        stores = self._stores
        if stores is None:
            return []
        records: list[Any] = []
        for entity in _PERSISTED_ENTITIES:
            repo = stores.repository_for(entity)
            for record in repo.list_by("target_key", target_key, limit=200):
                if record.deleted_at is None:
                    records.append(record)
        return records

    def _persist(
        self,
        batch: CloudBatch,
        target: CloudTarget,
        mission_id: str,
        correlation_id: str,
    ) -> int:
        """Persist correlated cloud intelligence into the TIDB."""
        stores = self._stores
        if stores is None:
            raise RuntimeError("cannot persist cloud intelligence without TIDB stores")
        count = 0
        for record in batch.records:
            entity = _to_entity(record, target, mission_id, correlation_id)
            if entity is None:
                continue
            stores.repository_for(type(entity)).save(entity)
            count += 1
            for evidence in getattr(record, "evidence", ()) or ():
                stores.repository_for(TidbCloudEvidence).save(
                    _to_evidence_entity(record, evidence, entity.id, mission_id, correlation_id)
                )
                count += 1
        for conflict in batch.conflicts:
            stores.repository_for(TidbCloudChange).save(
                TidbCloudChange(
                    subject_type="conflict",
                    subject=conflict.subject,
                    change_type="conflict",
                    previous="",
                    current=conflict.selected,
                    tool_id=conflict.selected_source,
                    confidence=conflict.confidence,
                    mission_id=mission_id,
                    correlation_id=correlation_id,
                )
            )
            count += 1
        for change in batch.changes:
            stores.repository_for(TidbCloudChange).save(_to_change_entity(change, mission_id, correlation_id))
            count += 1
        run = TidbCloudRun(
            mission_id=mission_id,
            target_key=target.value,
            target_id=target.target_id or None,
            status="completed",
            mode=batch.mode.value,
            providers=batch.provider_count(),
            accounts=_count_of(batch.records, CloudAccountObservation),
            regions=_count_of(batch.records, CloudRegionObservation),
            resources=batch.resource_count(),
            services=batch.service_count(),
            endpoints=batch.endpoint_count(),
            environments=_count_of(batch.records, CloudEnvironmentObservation),
            identities=_count_of(batch.records, CloudIdentityObservation),
            saas_providers=_count_of(batch.records, SaaSProviderObservation),
            saas_integrations=_count_of(batch.records, SaaSIntegrationObservation),
            webhooks=_count_of(batch.records, WebhookObservation),
            storage=_count_of(batch.records, StorageResourceObservation),
            compute=_count_of(batch.records, ComputeResourceObservation),
            containers=_count_of(batch.records, ContainerResourceObservation),
            kubernetes=_count_of(batch.records, KubernetesResourceObservation),
            databases=_count_of(batch.records, DatabaseResourceObservation),
            gateways=_count_of(batch.records, ApiGatewayResourceObservation),
            cdns=_count_of(batch.records, CdnResourceObservation),
            load_balancers=_count_of(batch.records, LoadBalancerResourceObservation),
            cicd=_count_of(batch.records, CiCdResourceObservation),
            secrets=_count_of(batch.records, SecretManagementObservation),
            changes=batch.change_count(),
            conflicts=batch.conflict_count(),
            started_at=batch.created_at,
            completed_at=utcnow_iso(),
            summary={
                "observations": batch.total_observations(),
                "records": batch.record_count(),
                "tools": [summary.tool_id for summary in batch.executions],
                "roles": _count_of(batch.records, CloudRoleObservation),
                "permissions": _count_of(batch.records, CloudPermissionObservation),
                "integrations": _count_of(batch.records, CloudIntegrationObservation),
                "saas_applications": _count_of(batch.records, SaaSApplicationObservation),
                "dependencies": _count_of(batch.records, CloudDependencyObservation),
                "message_infrastructure": _count_of(batch.records, MessageInfrastructureObservation),
                "exposures": _count_of(batch.records, CloudExposureObservation),
            },
            correlation_id=correlation_id,
        )
        stores.repository_for(TidbCloudRun).save(run)
        count += 1
        return count

    def _update_topology(self, batch: CloudBatch, mission_id: str, correlation_id: str) -> None:
        """Project cloud records into the attack-surface topology."""
        stores = self._stores
        if stores is None:
            return
        repo = stores.repository_for(TidbTopologyRelationship)
        for edge in _topology_edges(batch, mission_id, correlation_id):
            repo.save(edge.to_tidb())

    # -- events -------------------------------------------------------------

    def _publish_discoveries(self, batch: CloudBatch, correlation_id: str, mission_id: str) -> None:
        """Publish discovery events for the correlated set."""
        for record in batch.records:
            self._publish_record(record, correlation_id, mission_id)

    def _publish_record(self, record: Any, correlation_id: str, mission_id: str) -> None:
        origin = str(getattr(record, "origin", "") or record.target_key or "")
        if isinstance(record, CloudProviderObservation):
            self._publish(
                CloudProviderDiscoveredEvent(
                    correlation_id,
                    origin,
                    record.name,
                    confidence=record.confidence,
                    mission_id=mission_id,
                )
            )
        elif isinstance(record, CloudServiceObservation):
            self._publish(
                CloudServiceDiscoveredEvent(
                    correlation_id,
                    origin,
                    record.provider,
                    record.service,
                    category=record.category,
                    confidence=record.confidence,
                    mission_id=mission_id,
                )
            )
            if record.category in ("serverless", "compute"):
                self._publish(
                    CloudServerlessDiscoveredEvent(
                        correlation_id,
                        origin,
                        record.provider,
                        identifier=record.resource,
                        confidence=record.confidence,
                        mission_id=mission_id,
                    )
                )
        elif isinstance(record, CloudResourceObservation):
            self._publish(
                CloudResourceDiscoveredEvent(
                    correlation_id,
                    origin,
                    record.provider,
                    resource_kind=record.resource_kind,
                    identifier=record.identifier,
                    service=record.service,
                    confidence=record.confidence,
                    mission_id=mission_id,
                )
            )
        elif isinstance(record, CloudEndpointObservation):
            self._publish(
                CloudEndpointDiscoveredEvent(
                    correlation_id,
                    origin,
                    record.endpoint,
                    record.provider,
                    service=record.service,
                    plane=record.plane,
                    exposure=record.exposure,
                    confidence=record.confidence,
                    mission_id=mission_id,
                )
            )
        elif isinstance(record, CloudAccountObservation):
            self._publish(
                CloudAccountDiscoveredEvent(
                    correlation_id,
                    origin,
                    record.provider,
                    kind=record.kind,
                    value=record.value,
                    confidence=record.confidence,
                    mission_id=mission_id,
                )
            )
        elif isinstance(record, CloudRegionObservation):
            self._publish(
                CloudRegionDiscoveredEvent(
                    correlation_id,
                    origin,
                    record.provider,
                    record.region,
                    confidence=record.confidence,
                    mission_id=mission_id,
                )
            )
        elif isinstance(record, CloudEnvironmentObservation):
            self._publish(
                CloudEnvironmentDiscoveredEvent(
                    correlation_id,
                    origin,
                    record.provider,
                    record.environment,
                    confidence=record.confidence,
                    mission_id=mission_id,
                )
            )
        elif isinstance(record, CloudIdentityObservation):
            self._publish(
                CloudIdentityDiscoveredEvent(
                    correlation_id,
                    origin,
                    record.provider,
                    identity_kind=record.identity_kind,
                    name=record.name,
                    confidence=record.confidence,
                    mission_id=mission_id,
                )
            )
        elif isinstance(record, (CloudRoleObservation, CloudPermissionObservation)):
            self._publish(
                CloudIamDiscoveredEvent(
                    correlation_id,
                    origin,
                    record.provider,
                    kind="role" if isinstance(record, CloudRoleObservation) else "permission",
                    name=record.name if isinstance(record, CloudRoleObservation) else record.action,
                    confidence=record.confidence,
                    mission_id=mission_id,
                )
            )
        elif isinstance(record, SaaSProviderObservation):
            self._publish(
                CloudSaasDiscoveredEvent(
                    correlation_id,
                    origin,
                    record.name,
                    confidence=record.confidence,
                    mission_id=mission_id,
                )
            )
        elif isinstance(record, SaaSIntegrationObservation):
            self._publish(
                CloudSaasIntegrationDiscoveredEvent(
                    correlation_id,
                    origin,
                    record.saas_provider,
                    integration_type=record.integration_type,
                    name=record.name,
                    endpoint=record.endpoint,
                    confidence=record.confidence,
                    mission_id=mission_id,
                )
            )
        elif isinstance(record, WebhookObservation):
            self._publish(
                CloudWebhookDiscoveredEvent(
                    correlation_id,
                    origin,
                    record.endpoint,
                    direction=record.direction,
                    provider=record.provider,
                    confidence=record.confidence,
                    mission_id=mission_id,
                )
            )
        elif isinstance(record, CloudDependencyObservation):
            self._publish(
                CloudDependencyDiscoveredEvent(
                    correlation_id,
                    origin,
                    record.name,
                    provider=record.provider,
                    kind=record.kind,
                    confidence=record.confidence,
                    mission_id=mission_id,
                )
            )
        elif isinstance(record, StorageResourceObservation):
            self._publish(
                CloudStorageDiscoveredEvent(
                    correlation_id,
                    origin,
                    record.provider,
                    storage_kind=record.storage_kind,
                    identifier=record.identifier,
                    public=record.public,
                    confidence=record.confidence,
                    mission_id=mission_id,
                )
            )
        elif isinstance(record, ComputeResourceObservation):
            self._publish(
                CloudComputeDiscoveredEvent(
                    correlation_id,
                    origin,
                    record.provider,
                    compute_kind=record.compute_kind,
                    identifier=record.identifier,
                    confidence=record.confidence,
                    mission_id=mission_id,
                )
            )
        elif isinstance(record, ContainerResourceObservation):
            self._publish(
                CloudContainerDiscoveredEvent(
                    correlation_id,
                    origin,
                    record.provider,
                    container_kind=record.container_kind,
                    identifier=record.identifier,
                    confidence=record.confidence,
                    mission_id=mission_id,
                )
            )
        elif isinstance(record, KubernetesResourceObservation):
            self._publish(
                CloudKubernetesDiscoveredEvent(
                    correlation_id,
                    origin,
                    record.provider,
                    cluster=record.cluster,
                    kind=record.kind,
                    name=record.name,
                    confidence=record.confidence,
                    mission_id=mission_id,
                )
            )
        elif isinstance(record, DatabaseResourceObservation):
            self._publish(
                CloudDatabaseDiscoveredEvent(
                    correlation_id,
                    origin,
                    record.provider,
                    database_kind=record.database_kind,
                    identifier=record.identifier,
                    technology=record.technology,
                    confidence=record.confidence,
                    mission_id=mission_id,
                )
            )
        elif isinstance(record, ApiGatewayResourceObservation):
            self._publish(
                CloudGatewayDiscoveredEvent(
                    correlation_id,
                    origin,
                    record.provider,
                    gateway_kind=record.gateway_kind,
                    identifier=record.identifier,
                    confidence=record.confidence,
                    mission_id=mission_id,
                )
            )
        elif isinstance(record, CdnResourceObservation):
            self._publish(
                CloudCdnDiscoveredEvent(
                    correlation_id,
                    origin,
                    record.provider,
                    identifier=record.identifier,
                    confidence=record.confidence,
                    mission_id=mission_id,
                )
            )
        elif isinstance(record, LoadBalancerResourceObservation):
            self._publish(
                CloudLoadBalancerDiscoveredEvent(
                    correlation_id,
                    origin,
                    record.provider,
                    identifier=record.identifier,
                    confidence=record.confidence,
                    mission_id=mission_id,
                )
            )
        elif isinstance(record, CloudExposureObservation):
            self._publish(
                CloudExposureDiscoveredEvent(
                    correlation_id,
                    origin,
                    record.kind,
                    record.subject,
                    confidence=record.confidence,
                    mission_id=mission_id,
                )
            )

    def _publish_change(self, change: CloudChange, correlation_id: str, mission_id: str) -> None:
        """Publish the event for one historical change."""
        self._publish(
            CloudChangeDetectedEvent(
                correlation_id,
                change.subject_type,
                change.subject,
                change.change_type,
                previous=change.previous,
                current=change.current,
                mission_id=mission_id,
            )
        )

    def _publish(self, event: Any) -> None:
        """Publish an event when an event bus is configured."""
        if self._event_bus is not None:
            self._event_bus.publish(event)


# -- TIDB mapping helpers -----------------------------------------------------


_PERSISTED_ENTITIES: tuple[type[Any], ...] = (
    TidbCloudProvider,
    TidbCloudAccount,
    TidbCloudRegion,
    TidbCloudResource,
    TidbCloudService,
    TidbCloudEndpoint,
    TidbCloudEnvironment,
    TidbCloudIdentity,
    TidbCloudRole,
    TidbCloudPermission,
    TidbCloudIntegration,
    TidbSaaSProvider,
    TidbSaaSApplication,
    TidbSaaSIntegration,
    TidbWebhook,
    TidbCloudDependency,
    TidbStorageResource,
    TidbComputeResource,
    TidbContainerResource,
    TidbKubernetesResource,
    TidbDatabaseResource,
    TidbMessageInfrastructure,
    TidbApiGatewayResource,
    TidbCdnResource,
    TidbLoadBalancerResource,
    TidbCiCdResource,
    TidbSecretManagementIndicator,
    TidbCloudExposureIndicator,
    TidbCloudObservation,
)


def _to_entity(record: Any, target: CloudTarget, mission_id: str, correlation_id: str) -> Any | None:
    """Map a canonical observation onto its TIDB entity (None when unknown)."""
    target_key = target.value
    base = {
        "source": record.source,
        "tool_id": record.tool_id,
        "target_key": target_key,
        "correlation_id": correlation_id,
        "mission_id": mission_id,
        "first_seen": record.observed_at,
        "last_seen": record.observed_at,
    }
    if isinstance(record, CloudProviderObservation):
        return TidbCloudProvider(
            name=record.name,
            display_name=record.display_name,
            evidence_indicators=list(record.evidence_indicators),
            confidence=record.confidence,
            **base,
        )
    if isinstance(record, CloudAccountObservation):
        return TidbCloudAccount(
            provider=record.provider,
            kind=record.kind,
            value=record.value,
            name=record.name,
            region=record.region,
            environment=record.environment,
            indicators=list(record.indicators),
            confidence=record.confidence,
            **base,
        )
    if isinstance(record, CloudRegionObservation):
        return TidbCloudRegion(
            provider=record.provider,
            region=record.region,
            resource=record.resource,
            environment=record.environment,
            indicators=list(record.indicators),
            confidence=record.confidence,
            **base,
        )
    if isinstance(record, CloudResourceObservation):
        return TidbCloudResource(
            provider=record.provider,
            resource_kind=record.resource_kind,
            identifier=record.identifier,
            service=record.service,
            region=record.region,
            endpoint=record.endpoint,
            environment=record.environment,
            public=record.public,
            indicators=list(record.indicators),
            confidence=record.confidence,
            **base,
        )
    if isinstance(record, CloudServiceObservation):
        return TidbCloudService(
            provider=record.provider,
            service=record.service,
            category=record.category,
            resource=record.resource,
            region=record.region,
            endpoint=record.endpoint,
            environment=record.environment,
            indicators=list(record.indicators),
            confidence=record.confidence,
            **base,
        )
    if isinstance(record, CloudEndpointObservation):
        return TidbCloudEndpoint(
            endpoint=record.endpoint,
            provider=record.provider,
            service=record.service,
            plane=record.plane,
            exposure=record.exposure,
            region=record.region,
            environment=record.environment,
            domain=record.domain,
            indicators=list(record.indicators),
            confidence=record.confidence,
            **base,
        )
    if isinstance(record, CloudEnvironmentObservation):
        return TidbCloudEnvironment(
            provider=record.provider,
            environment=record.environment,
            subject=record.subject,
            indicators=list(record.indicators),
            confidence=record.confidence,
            **base,
        )
    if isinstance(record, CloudIdentityObservation):
        return TidbCloudIdentity(
            provider=record.provider,
            identity_kind=record.identity_kind,
            name=record.name,
            identifier=record.identifier,
            account=record.account,
            role=record.role,
            permissions=list(record.permissions),
            indicators=list(record.indicators),
            confidence=record.confidence,
            **base,
        )
    if isinstance(record, CloudRoleObservation):
        return TidbCloudRole(
            provider=record.provider,
            name=record.name,
            account=record.account,
            assume_role=record.assume_role,
            indicators=list(record.indicators),
            confidence=record.confidence,
            **base,
        )
    if isinstance(record, CloudPermissionObservation):
        return TidbCloudPermission(
            provider=record.provider,
            name=record.name,
            action=record.action,
            resource=record.resource,
            indicators=list(record.indicators),
            confidence=record.confidence,
            **base,
        )
    if isinstance(record, CloudIntegrationObservation):
        return TidbCloudIntegration(
            provider=record.provider,
            integration_type=record.integration_type,
            name=record.name,
            endpoint=record.endpoint,
            scope=record.scope,
            indicators=list(record.indicators),
            confidence=record.confidence,
            **base,
        )
    if isinstance(record, SaaSProviderObservation):
        return TidbSaaSProvider(
            name=record.name,
            display_name=record.display_name,
            provider_kind=record.provider_kind,
            indicators=list(record.indicators),
            confidence=record.confidence,
            **base,
        )
    if isinstance(record, SaaSApplicationObservation):
        return TidbSaaSApplication(
            name=record.name,
            saas_provider=record.saas_provider,
            url=record.url,
            environment=record.environment,
            indicators=list(record.indicators),
            confidence=record.confidence,
            **base,
        )
    if isinstance(record, SaaSIntegrationObservation):
        return TidbSaaSIntegration(
            saas_provider=record.saas_provider,
            integration_type=record.integration_type,
            name=record.name,
            endpoint=record.endpoint,
            auth_mechanism=record.auth_mechanism,
            scope=record.scope,
            indicators=list(record.indicators),
            confidence=record.confidence,
            **base,
        )
    if isinstance(record, WebhookObservation):
        return TidbWebhook(
            direction=record.direction,
            provider=record.provider,
            endpoint=record.endpoint,
            event_type=record.event_type,
            signing=record.signing,
            indicators=list(record.indicators),
            confidence=record.confidence,
            **base,
        )
    if isinstance(record, CloudDependencyObservation):
        return TidbCloudDependency(
            name=record.name,
            provider=record.provider,
            kind=record.kind,
            endpoint=record.endpoint,
            application=record.application,
            indicators=list(record.indicators),
            confidence=record.confidence,
            **base,
        )
    if isinstance(record, StorageResourceObservation):
        return TidbStorageResource(
            provider=record.provider,
            storage_kind=record.storage_kind,
            identifier=record.identifier,
            endpoint=record.endpoint,
            public=record.public,
            region=record.region,
            environment=record.environment,
            indicators=list(record.indicators),
            confidence=record.confidence,
            **base,
        )
    if isinstance(record, ComputeResourceObservation):
        return TidbComputeResource(
            provider=record.provider,
            compute_kind=record.compute_kind,
            identifier=record.identifier,
            endpoint=record.endpoint,
            region=record.region,
            environment=record.environment,
            indicators=list(record.indicators),
            confidence=record.confidence,
            **base,
        )
    if isinstance(record, ContainerResourceObservation):
        return TidbContainerResource(
            provider=record.provider,
            container_kind=record.container_kind,
            identifier=record.identifier,
            registry=record.registry,
            image=record.image,
            region=record.region,
            environment=record.environment,
            indicators=list(record.indicators),
            confidence=record.confidence,
            **base,
        )
    if isinstance(record, KubernetesResourceObservation):
        return TidbKubernetesResource(
            provider=record.provider,
            cluster=record.cluster,
            kind=record.kind,
            name=record.name,
            endpoint=record.endpoint,
            environment=record.environment,
            indicators=list(record.indicators),
            confidence=record.confidence,
            **base,
        )
    if isinstance(record, DatabaseResourceObservation):
        return TidbDatabaseResource(
            provider=record.provider,
            database_kind=record.database_kind,
            identifier=record.identifier,
            endpoint=record.endpoint,
            technology=record.technology,
            region=record.region,
            public=record.public,
            environment=record.environment,
            indicators=list(record.indicators),
            confidence=record.confidence,
            **base,
        )
    if isinstance(record, MessageInfrastructureObservation):
        return TidbMessageInfrastructure(
            provider=record.provider,
            kind=record.kind,
            identifier=record.identifier,
            service=record.service,
            endpoint=record.endpoint,
            environment=record.environment,
            indicators=list(record.indicators),
            confidence=record.confidence,
            **base,
        )
    if isinstance(record, ApiGatewayResourceObservation):
        return TidbApiGatewayResource(
            provider=record.provider,
            gateway_kind=record.gateway_kind,
            identifier=record.identifier,
            endpoint=record.endpoint,
            backend=record.backend,
            region=record.region,
            environment=record.environment,
            indicators=list(record.indicators),
            confidence=record.confidence,
            **base,
        )
    if isinstance(record, CdnResourceObservation):
        return TidbCdnResource(
            provider=record.provider,
            identifier=record.identifier,
            endpoint=record.endpoint,
            origin=record.origin,
            region=record.region,
            environment=record.environment,
            indicators=list(record.indicators),
            confidence=record.confidence,
            **base,
        )
    if isinstance(record, LoadBalancerResourceObservation):
        return TidbLoadBalancerResource(
            provider=record.provider,
            identifier=record.identifier,
            endpoint=record.endpoint,
            backend=record.backend,
            region=record.region,
            environment=record.environment,
            indicators=list(record.indicators),
            confidence=record.confidence,
            **base,
        )
    if isinstance(record, CiCdResourceObservation):
        return TidbCiCdResource(
            provider=record.provider,
            kind=record.kind,
            name=record.name,
            repository=record.repository,
            endpoint=record.endpoint,
            environment=record.environment,
            indicators=list(record.indicators),
            confidence=record.confidence,
            **base,
        )
    if isinstance(record, SecretManagementObservation):
        return TidbSecretManagementIndicator(
            provider=record.provider,
            kind=record.kind,
            name=record.name,
            reference=record.reference,
            fingerprint=record.fingerprint,
            indicators=list(record.indicators),
            confidence=record.confidence,
            **base,
        )
    if isinstance(record, CloudExposureObservation):
        return TidbCloudExposureIndicator(
            kind=record.kind,
            subject=record.subject,
            detail=record.detail,
            indicators=list(record.indicators),
            confidence=record.confidence,
            **base,
        )
    if isinstance(record, CloudObservation):
        return TidbCloudObservation(
            origin=record.origin,
            kind=record.kind,
            name=record.name,
            value=record.value,
            detail=record.detail,
            indicators=list(record.indicators),
            confidence=record.confidence,
            **base,
        )
    return None


def _to_evidence_entity(
    record: Any,
    evidence: CloudEvidence,
    subject_id: str,
    mission_id: str,
    correlation_id: str,
) -> TidbCloudEvidence:
    """Map an evidence fragment onto the TIDB evidence entity."""
    return TidbCloudEvidence(
        subject_type=_subject_type_of(record),
        subject_id=subject_id,
        evidence_type=_v(evidence.evidence_type),
        value=evidence.value,
        source=evidence.source,
        strength=_v(evidence.strength),
        tool_id=evidence.tool_id,
        detail=evidence.detail,
        mission_id=mission_id,
        correlation_id=correlation_id,
    )


def _to_change_entity(change: CloudChange, mission_id: str, correlation_id: str) -> TidbCloudChange:
    """Map a historical change onto the TIDB change entity."""
    return TidbCloudChange(
        subject_type=change.subject_type,
        subject=change.subject,
        change_type=change.change_type,
        previous=change.previous,
        current=change.current,
        tool_id=change.source,
        confidence=float(getattr(change, "confidence", 1.0) or 1.0),
        mission_id=mission_id,
        correlation_id=correlation_id,
    )


# -- existing intelligence converters ------------------------------------------


def _from_tidb(record: Any, target_key: str, mission_id: str, correlation_id: str) -> Any | None:
    """Convert a persisted TIDB cloud record back into an observation."""
    observed_at = record.last_seen or record.created_at
    base = {
        "source": record.source or "tidb",
        "tool_id": record.tool_id or "tidb",
        "target_key": target_key,
        "correlation_id": correlation_id,
        "mission_id": mission_id,
        "observed_at": observed_at,
    }
    if isinstance(record, TidbCloudProvider):
        return CloudProviderObservation(
            name=record.name,
            display_name=record.display_name,
            evidence_indicators=tuple(record.evidence_indicators),
            confidence=record.confidence,
            evidence=(_tidb_evidence("provider", record),),
            **base,
        )
    if isinstance(record, TidbCloudAccount):
        return CloudAccountObservation(
            provider=record.provider,
            kind=record.kind,
            value=record.value,
            name=record.name,
            region=record.region,
            environment=record.environment,
            indicators=tuple(record.indicators),
            confidence=record.confidence,
            evidence=(_tidb_evidence("account", record),),
            **base,
        )
    if isinstance(record, TidbCloudRegion):
        return CloudRegionObservation(
            provider=record.provider,
            region=record.region,
            resource=record.resource,
            environment=record.environment,
            indicators=tuple(record.indicators),
            confidence=record.confidence,
            evidence=(_tidb_evidence("region", record),),
            **base,
        )
    if isinstance(record, TidbCloudResource):
        return CloudResourceObservation(
            provider=record.provider,
            resource_kind=record.resource_kind,
            identifier=record.identifier,
            service=record.service,
            region=record.region,
            endpoint=record.endpoint,
            environment=record.environment,
            public=record.public,
            indicators=tuple(record.indicators),
            confidence=record.confidence,
            evidence=(_tidb_evidence("resource", record),),
            **base,
        )
    if isinstance(record, TidbCloudService):
        return CloudServiceObservation(
            provider=record.provider,
            service=record.service,
            category=record.category,
            resource=record.resource,
            region=record.region,
            endpoint=record.endpoint,
            environment=record.environment,
            indicators=tuple(record.indicators),
            confidence=record.confidence,
            evidence=(_tidb_evidence("service", record),),
            **base,
        )
    if isinstance(record, TidbCloudEndpoint):
        return CloudEndpointObservation(
            endpoint=record.endpoint,
            provider=record.provider,
            service=record.service,
            plane=record.plane,
            exposure=record.exposure,
            region=record.region,
            environment=record.environment,
            domain=record.domain,
            indicators=tuple(record.indicators),
            confidence=record.confidence,
            evidence=(_tidb_evidence("endpoint", record),),
            **base,
        )
    if isinstance(record, TidbCloudEnvironment):
        return CloudEnvironmentObservation(
            provider=record.provider,
            environment=record.environment,
            subject=record.subject,
            indicators=tuple(record.indicators),
            confidence=record.confidence,
            evidence=(_tidb_evidence("environment", record),),
            **base,
        )
    if isinstance(record, TidbCloudIdentity):
        return CloudIdentityObservation(
            provider=record.provider,
            identity_kind=record.identity_kind,
            name=record.name,
            identifier=record.identifier,
            account=record.account,
            role=record.role,
            permissions=tuple(record.permissions),
            indicators=tuple(record.indicators),
            confidence=record.confidence,
            evidence=(_tidb_evidence("identity", record),),
            **base,
        )
    if isinstance(record, TidbCloudRole):
        return CloudRoleObservation(
            provider=record.provider,
            name=record.name,
            account=record.account,
            assume_role=record.assume_role,
            indicators=tuple(record.indicators),
            confidence=record.confidence,
            evidence=(_tidb_evidence("role", record),),
            **base,
        )
    if isinstance(record, TidbCloudPermission):
        return CloudPermissionObservation(
            provider=record.provider,
            name=record.name,
            action=record.action,
            resource=record.resource,
            indicators=tuple(record.indicators),
            confidence=record.confidence,
            evidence=(_tidb_evidence("permission", record),),
            **base,
        )
    if isinstance(record, TidbSaaSProvider):
        return SaaSProviderObservation(
            name=record.name,
            display_name=record.display_name,
            provider_kind=record.provider_kind,
            indicators=tuple(record.indicators),
            confidence=record.confidence,
            evidence=(_tidb_evidence("saas", record),),
            **base,
        )
    if isinstance(record, TidbSaaSIntegration):
        return SaaSIntegrationObservation(
            saas_provider=record.saas_provider,
            integration_type=record.integration_type,
            name=record.name,
            endpoint=record.endpoint,
            auth_mechanism=record.auth_mechanism,
            scope=record.scope,
            indicators=tuple(record.indicators),
            confidence=record.confidence,
            evidence=(_tidb_evidence("saas-integration", record),),
            **base,
        )
    if isinstance(record, TidbWebhook):
        return WebhookObservation(
            direction=record.direction,
            provider=record.provider,
            endpoint=record.endpoint,
            event_type=record.event_type,
            signing=record.signing,
            indicators=tuple(record.indicators),
            confidence=record.confidence,
            evidence=(_tidb_evidence("webhook", record),),
            **base,
        )
    if isinstance(record, TidbStorageResource):
        return StorageResourceObservation(
            provider=record.provider,
            storage_kind=record.storage_kind,
            identifier=record.identifier,
            endpoint=record.endpoint,
            public=record.public,
            region=record.region,
            environment=record.environment,
            indicators=tuple(record.indicators),
            confidence=record.confidence,
            evidence=(_tidb_evidence("storage", record),),
            **base,
        )
    if isinstance(record, TidbComputeResource):
        return ComputeResourceObservation(
            provider=record.provider,
            compute_kind=record.compute_kind,
            identifier=record.identifier,
            endpoint=record.endpoint,
            region=record.region,
            environment=record.environment,
            indicators=tuple(record.indicators),
            confidence=record.confidence,
            evidence=(_tidb_evidence("compute", record),),
            **base,
        )
    if isinstance(record, TidbContainerResource):
        return ContainerResourceObservation(
            provider=record.provider,
            container_kind=record.container_kind,
            identifier=record.identifier,
            registry=record.registry,
            image=record.image,
            region=record.region,
            environment=record.environment,
            indicators=tuple(record.indicators),
            confidence=record.confidence,
            evidence=(_tidb_evidence("container", record),),
            **base,
        )
    if isinstance(record, TidbKubernetesResource):
        return KubernetesResourceObservation(
            provider=record.provider,
            cluster=record.cluster,
            kind=record.kind,
            name=record.name,
            endpoint=record.endpoint,
            environment=record.environment,
            indicators=tuple(record.indicators),
            confidence=record.confidence,
            evidence=(_tidb_evidence("kubernetes", record),),
            **base,
        )
    if isinstance(record, TidbDatabaseResource):
        return DatabaseResourceObservation(
            provider=record.provider,
            database_kind=record.database_kind,
            identifier=record.identifier,
            endpoint=record.endpoint,
            technology=record.technology,
            region=record.region,
            public=record.public,
            environment=record.environment,
            indicators=tuple(record.indicators),
            confidence=record.confidence,
            evidence=(_tidb_evidence("database", record),),
            **base,
        )
    if isinstance(record, TidbCloudExposureIndicator):
        return CloudExposureObservation(
            kind=record.kind,
            subject=record.subject,
            detail=record.detail,
            indicators=tuple(record.indicators),
            confidence=record.confidence,
            evidence=(_tidb_evidence("exposure", record),),
            **base,
        )
    if isinstance(record, TidbCloudObservation):
        return CloudObservation(
            origin=record.origin,
            kind=record.kind,
            name=record.name,
            value=record.value,
            detail=record.detail,
            indicators=tuple(record.indicators),
            confidence=record.confidence,
            evidence=(_tidb_evidence("observation", record),),
            **base,
        )
    return None


def _tidb_evidence(subject_type: str, record: Any) -> CloudEvidence:
    return CloudEvidence(
        evidence_type="tidb-intelligence",
        value=record.target_key or getattr(record, "name", "") or subject_type,
        source="tidb",
        strength="moderate",
        tool_id="tidb",
        detail=f"previously persisted {subject_type} intelligence",
    )


def _subject_type_of(record: Any) -> str:
    mapping = {
        "CloudProviderObservation": "provider",
        "CloudServiceObservation": "service",
        "CloudResourceObservation": "resource",
        "CloudEndpointObservation": "endpoint",
        "CloudAccountObservation": "account",
        "CloudRegionObservation": "region",
        "CloudEnvironmentObservation": "environment",
        "CloudIdentityObservation": "identity",
        "CloudRoleObservation": "role",
        "CloudPermissionObservation": "permission",
        "CloudIntegrationObservation": "integration",
        "SaaSProviderObservation": "saas",
        "SaaSApplicationObservation": "saas-application",
        "SaaSIntegrationObservation": "saas-integration",
        "WebhookObservation": "webhook",
        "CloudDependencyObservation": "dependency",
        "StorageResourceObservation": "storage",
        "ComputeResourceObservation": "compute",
        "ContainerResourceObservation": "container",
        "KubernetesResourceObservation": "kubernetes",
        "DatabaseResourceObservation": "database",
        "MessageInfrastructureObservation": "message",
        "ApiGatewayResourceObservation": "gateway",
        "CdnResourceObservation": "cdn",
        "LoadBalancerResourceObservation": "load-balancer",
        "CiCdResourceObservation": "ci-cd",
        "SecretManagementObservation": "secret",
        "CloudExposureObservation": "exposure",
        "CloudObservation": "observation",
    }
    return mapping.get(type(record).__name__, "observation")


# -- topology helpers ----------------------------------------------------------


def _topology_edges(batch: CloudBatch, mission_id: str, correlation_id: str) -> list[GraphRelationship]:
    """Derive cloud edges into the attack-surface topology."""
    edges: list[GraphRelationship] = []
    domain_name = batch.target.value if batch.target.target_type in ("domain", "hostname", "url") else ""
    domain_node = TopologyEntity(kind=EntityKind.DOMAIN, name=domain_name) if domain_name else None

    for record in batch.records:
        if isinstance(record, CloudProviderObservation):
            provider_node = TopologyEntity(kind=EntityKind.CLOUD_PROVIDER, name=record.name)
            if domain_node is not None:
                edges.append(
                    _edge(
                        RelationshipType.HOSTED_ON,
                        domain_node,
                        provider_node,
                        sources=["cloud"],
                        evidence={"provider": record.name, "confidence": record.confidence},
                        confidence=record.confidence,
                        mission_id=mission_id,
                        correlation_id=correlation_id,
                    )
                )
        elif isinstance(record, CloudAccountObservation):
            provider_node = TopologyEntity(kind=EntityKind.CLOUD_PROVIDER, name=record.provider)
            account_node = TopologyEntity(kind=EntityKind.CLOUD_ACCOUNT, name=f"{record.provider}:{record.value}")
            edges.append(
                _edge(
                    RelationshipType.BELONGS_TO,
                    account_node,
                    provider_node,
                    sources=["cloud"],
                    evidence={"kind": record.kind, "confidence": record.confidence},
                    confidence=record.confidence,
                    mission_id=mission_id,
                    correlation_id=correlation_id,
                )
            )
        elif isinstance(record, CloudRegionObservation):
            provider_node = TopologyEntity(kind=EntityKind.CLOUD_PROVIDER, name=record.provider)
            region_node = TopologyEntity(kind=EntityKind.CLOUD_REGION, name=f"{record.provider}:{record.region}")
            edges.append(
                _edge(
                    RelationshipType.PART_OF,
                    region_node,
                    provider_node,
                    sources=["cloud"],
                    evidence={"confidence": record.confidence},
                    confidence=record.confidence,
                    mission_id=mission_id,
                    correlation_id=correlation_id,
                )
            )
        elif isinstance(record, CloudResourceObservation):
            resource_node = TopologyEntity(
                kind=EntityKind.CLOUD_RESOURCE,
                name=f"{record.provider}:{record.identifier}",
            )
            provider_node = TopologyEntity(kind=EntityKind.CLOUD_PROVIDER, name=record.provider)
            edges.append(
                _edge(
                    RelationshipType.BELONGS_TO,
                    resource_node,
                    provider_node,
                    sources=["cloud"],
                    evidence={"kind": record.resource_kind, "confidence": record.confidence},
                    confidence=record.confidence,
                    mission_id=mission_id,
                    correlation_id=correlation_id,
                )
            )
            if domain_node is not None:
                edges.append(
                    _edge(
                        RelationshipType.HOSTED_ON,
                        domain_node,
                        resource_node,
                        sources=["cloud"],
                        evidence={"confidence": record.confidence},
                        confidence=record.confidence,
                        mission_id=mission_id,
                        correlation_id=correlation_id,
                    )
                )
            if record.environment != "unknown":
                env_node = TopologyEntity(kind=EntityKind.CLOUD_ENVIRONMENT, name=record.environment)
                edges.append(
                    _edge(
                        RelationshipType.BELONGS_TO,
                        resource_node,
                        env_node,
                        sources=["cloud"],
                        evidence={"confidence": record.confidence},
                        confidence=record.confidence,
                        mission_id=mission_id,
                        correlation_id=correlation_id,
                    )
                )
        elif isinstance(record, CloudEndpointObservation):
            endpoint_node = TopologyEntity(kind=EntityKind.CLOUD_ENDPOINT, name=record.endpoint)
            provider_node = TopologyEntity(kind=EntityKind.CLOUD_PROVIDER, name=record.provider)
            edges.append(
                _edge(
                    RelationshipType.EXPOSES,
                    provider_node,
                    endpoint_node,
                    sources=["cloud"],
                    evidence={"plane": record.plane, "exposure": record.exposure, "confidence": record.confidence},
                    confidence=record.confidence,
                    mission_id=mission_id,
                    correlation_id=correlation_id,
                )
            )
            if domain_node is not None:
                edges.append(
                    _edge(
                        RelationshipType.HOSTED_ON,
                        domain_node,
                        endpoint_node,
                        sources=["cloud"],
                        evidence={"confidence": record.confidence},
                        confidence=record.confidence,
                        mission_id=mission_id,
                        correlation_id=correlation_id,
                    )
                )
        elif isinstance(record, SaaSProviderObservation):
            saas_node = TopologyEntity(kind=EntityKind.SAAS_PROVIDER, name=record.name)
            if domain_node is not None:
                edges.append(
                    _edge(
                        RelationshipType.USES,
                        domain_node,
                        saas_node,
                        sources=["cloud"],
                        evidence={"confidence": record.confidence},
                        confidence=record.confidence,
                        mission_id=mission_id,
                        correlation_id=correlation_id,
                    )
                )
        elif isinstance(record, SaaSIntegrationObservation):
            saas_node = TopologyEntity(kind=EntityKind.SAAS_PROVIDER, name=record.saas_provider)
            integration_node = TopologyEntity(
                kind=EntityKind.SAAS_INTEGRATION,
                name=f"{record.saas_provider}:{record.integration_type}",
            )
            edges.append(
                _edge(
                    RelationshipType.USES,
                    integration_node,
                    saas_node,
                    sources=["cloud"],
                    evidence={"confidence": record.confidence},
                    confidence=record.confidence,
                    mission_id=mission_id,
                    correlation_id=correlation_id,
                )
            )
        elif isinstance(record, WebhookObservation):
            webhook_node = TopologyEntity(kind=EntityKind.WEBHOOK, name=record.endpoint)
            provider_node = TopologyEntity(kind=EntityKind.SAAS_PROVIDER, name=record.provider or "unknown")
            edges.append(
                _edge(
                    RelationshipType.USES,
                    provider_node,
                    webhook_node,
                    sources=["cloud"],
                    evidence={"direction": record.direction, "confidence": record.confidence},
                    confidence=record.confidence,
                    mission_id=mission_id,
                    correlation_id=correlation_id,
                )
            )
        elif isinstance(record, CdnResourceObservation):
            cdn_node = TopologyEntity(kind=EntityKind.CDN, name=record.identifier or record.endpoint)
            if domain_node is not None:
                edges.append(
                    _edge(
                        RelationshipType.HOSTED_ON,
                        domain_node,
                        cdn_node,
                        sources=["cloud"],
                        evidence={"provider": record.provider, "confidence": record.confidence},
                        confidence=record.confidence,
                        mission_id=mission_id,
                        correlation_id=correlation_id,
                    )
                )
    return edges


def _edge(
    rel_type: RelationshipType,
    source: TopologyEntity,
    target: TopologyEntity,
    *,
    sources: list[str],
    evidence: dict[str, Any],
    confidence: float,
    mission_id: str,
    correlation_id: str,
) -> GraphRelationship:
    return GraphRelationship(
        rel_type=rel_type,
        source=source,
        target=target,
        sources=sources,
        evidence=evidence,
        confidence=confidence,
        mission_id=mission_id,
        correlation_id=correlation_id,
        in_scope=True,
    )


# -- small helpers -------------------------------------------------------------


def _v(value: Any) -> str:
    """Coerce an enum-or-string kind value to its string form."""
    if hasattr(value, "value"):
        return str(value.value)
    return str(value)


def _make_target(target: str) -> CloudTarget:
    """Build a :class:`CloudTarget` from a plain string."""
    stripped = target.strip()
    return CloudTarget(value=stripped, target_type=infer_asset_type(stripped))


def _make_mode(mode: ReconMode | str) -> ReconMode:
    """Coerce a mode into a :class:`ReconMode`."""
    if isinstance(mode, ReconMode):
        return mode
    return ReconMode(str(mode).lower())


def _count_of(records: Sequence[Any], cls: type) -> int:
    return sum(1 for record in records if isinstance(record, cls))


class CloudQueryService:
    """Answer cloud intelligence queries from persisted TIDB records."""

    def __init__(
        self,
        *,
        stores: TidbRepositoryFactory | None = None,
        cache: CachePort | None = None,
    ) -> None:
        self._stores = stores
        self._cache = cache

    def providers(self, *, name: str = "", mission_id: str = "") -> list[dict[str, Any]]:
        """Return the cloud provider inventory."""
        records = self._list(TidbCloudProvider, "name", name, mission_id)
        return [self._provider_dict(record) for record in records]

    def accounts(self, *, provider: str = "", kind: str = "", mission_id: str = "") -> list[dict[str, Any]]:
        """Return the cloud account/subscription/project inventory."""
        records = self._list(TidbCloudAccount, "provider", provider, mission_id)
        if kind:
            records = [record for record in records if record.kind == kind]
        return [self._entity_dict(record) for record in records]

    def regions(self, *, provider: str = "", mission_id: str = "") -> list[dict[str, Any]]:
        """Return the cloud region inventory."""
        return [self._entity_dict(record) for record in self._list(TidbCloudRegion, "provider", provider, mission_id)]

    def resources(self, *, provider: str = "", kind: str = "", mission_id: str = "") -> list[dict[str, Any]]:
        """Return the cloud resource inventory."""
        records = self._list(TidbCloudResource, "provider", provider, mission_id)
        if kind:
            records = [record for record in records if record.resource_kind == kind]
        return [self._entity_dict(record) for record in records]

    def services(self, *, provider: str = "", mission_id: str = "") -> list[dict[str, Any]]:
        """Return the cloud service inventory."""
        return [self._entity_dict(record) for record in self._list(TidbCloudService, "provider", provider, mission_id)]

    def endpoints(self, *, provider: str = "", mission_id: str = "") -> list[dict[str, Any]]:
        """Return the cloud endpoint inventory."""
        return [self._entity_dict(record) for record in self._list(TidbCloudEndpoint, "provider", provider, mission_id)]

    def environments(self, *, provider: str = "", mission_id: str = "") -> list[dict[str, Any]]:
        """Return the cloud environment inventory."""
        return [
            self._entity_dict(record) for record in self._list(TidbCloudEnvironment, "provider", provider, mission_id)
        ]

    def identities(self, *, provider: str = "", mission_id: str = "") -> list[dict[str, Any]]:
        """Return the cloud identity inventory."""
        return [self._entity_dict(record) for record in self._list(TidbCloudIdentity, "provider", provider, mission_id)]

    def roles(self, *, provider: str = "", mission_id: str = "") -> list[dict[str, Any]]:
        """Return the cloud IAM role inventory."""
        return [self._entity_dict(record) for record in self._list(TidbCloudRole, "provider", provider, mission_id)]

    def permissions(self, *, provider: str = "", mission_id: str = "") -> list[dict[str, Any]]:
        """Return the cloud permission inventory."""
        return [
            self._entity_dict(record) for record in self._list(TidbCloudPermission, "provider", provider, mission_id)
        ]

    def integrations(self, *, provider: str = "", mission_id: str = "") -> list[dict[str, Any]]:
        """Return the cloud integration inventory."""
        return [
            self._entity_dict(record) for record in self._list(TidbCloudIntegration, "provider", provider, mission_id)
        ]

    def saas(self, *, name: str = "", mission_id: str = "") -> list[dict[str, Any]]:
        """Return the SaaS provider inventory."""
        records = self._list(TidbSaaSProvider, "name", name, mission_id)
        return [self._entity_dict(record) for record in records]

    def saas_applications(self, *, mission_id: str = "") -> list[dict[str, Any]]:
        """Return the SaaS application inventory."""
        return [self._entity_dict(record) for record in self._list(TidbSaaSApplication, "", "", mission_id)]

    def saas_integrations(self, *, provider: str = "", mission_id: str = "") -> list[dict[str, Any]]:
        """Return the SaaS integration inventory."""
        return [
            self._entity_dict(record)
            for record in self._list(TidbSaaSIntegration, "saas_provider", provider, mission_id)
        ]

    def webhooks(self, *, mission_id: str = "") -> list[dict[str, Any]]:
        """Return the webhook inventory."""
        return [self._entity_dict(record) for record in self._list(TidbWebhook, "", "", mission_id)]

    def dependencies(self, *, mission_id: str = "") -> list[dict[str, Any]]:
        """Return the third-party dependency inventory."""
        return [self._entity_dict(record) for record in self._list(TidbCloudDependency, "", "", mission_id)]

    def storage(self, *, provider: str = "", mission_id: str = "") -> list[dict[str, Any]]:
        """Return the storage resource inventory."""
        return [
            self._entity_dict(record) for record in self._list(TidbStorageResource, "provider", provider, mission_id)
        ]

    def compute(self, *, provider: str = "", mission_id: str = "") -> list[dict[str, Any]]:
        """Return the compute resource inventory."""
        return [
            self._entity_dict(record) for record in self._list(TidbComputeResource, "provider", provider, mission_id)
        ]

    def containers(self, *, provider: str = "", mission_id: str = "") -> list[dict[str, Any]]:
        """Return the container resource inventory."""
        return [
            self._entity_dict(record) for record in self._list(TidbContainerResource, "provider", provider, mission_id)
        ]

    def kubernetes(self, *, provider: str = "", mission_id: str = "") -> list[dict[str, Any]]:
        """Return the Kubernetes resource inventory."""
        return [
            self._entity_dict(record) for record in self._list(TidbKubernetesResource, "provider", provider, mission_id)
        ]

    def databases(self, *, provider: str = "", mission_id: str = "") -> list[dict[str, Any]]:
        """Return the database resource inventory."""
        return [
            self._entity_dict(record) for record in self._list(TidbDatabaseResource, "provider", provider, mission_id)
        ]

    def message_infrastructure(self, *, provider: str = "", mission_id: str = "") -> list[dict[str, Any]]:
        """Return the message infrastructure inventory."""
        return [
            self._entity_dict(record)
            for record in self._list(TidbMessageInfrastructure, "provider", provider, mission_id)
        ]

    def gateways(self, *, provider: str = "", mission_id: str = "") -> list[dict[str, Any]]:
        """Return the API gateway inventory."""
        return [
            self._entity_dict(record) for record in self._list(TidbApiGatewayResource, "provider", provider, mission_id)
        ]

    def cdns(self, *, provider: str = "", mission_id: str = "") -> list[dict[str, Any]]:
        """Return the CDN inventory."""
        return [self._entity_dict(record) for record in self._list(TidbCdnResource, "provider", provider, mission_id)]

    def load_balancers(self, *, provider: str = "", mission_id: str = "") -> list[dict[str, Any]]:
        """Return the load-balancer inventory."""
        return [
            self._entity_dict(record)
            for record in self._list(TidbLoadBalancerResource, "provider", provider, mission_id)
        ]

    def cicd(self, *, provider: str = "", mission_id: str = "") -> list[dict[str, Any]]:
        """Return the CI/CD inventory."""
        return [self._entity_dict(record) for record in self._list(TidbCiCdResource, "provider", provider, mission_id)]

    def secrets(self, *, provider: str = "", mission_id: str = "") -> list[dict[str, Any]]:
        """Return the secret-management indicator inventory (metadata only)."""
        return [
            self._entity_dict(record)
            for record in self._list(TidbSecretManagementIndicator, "provider", provider, mission_id)
        ]

    def exposures(self, *, kind: str = "", mission_id: str = "") -> list[dict[str, Any]]:
        """Return the exposure indicator inventory (intelligence, never verdicts)."""
        records = self._list(TidbCloudExposureIndicator, "", "", mission_id)
        if kind:
            records = [record for record in records if record.kind == kind]
        return [self._entity_dict(record) for record in records]

    def observations(self, *, origin: str = "", mission_id: str = "") -> list[dict[str, Any]]:
        """Return generic cloud observations."""
        return [self._entity_dict(record) for record in self._list(TidbCloudObservation, "origin", origin, mission_id)]

    def changes(self, *, mission_id: str = "") -> list[dict[str, Any]]:
        """Return persisted cloud changes."""
        if self._stores is None:
            return []
        repo = self._stores.repository_for(TidbCloudChange)
        records = list(repo.stream())
        return [
            {
                "subject_type": record.subject_type,
                "subject": record.subject,
                "change_type": record.change_type,
                "previous": record.previous,
                "current": record.current,
                "tool_id": record.tool_id,
                "confidence": record.confidence,
                "mission_id": record.mission_id,
                "created_at": record.created_at,
            }
            for record in records
            if record.deleted_at is None and (not mission_id or record.mission_id == mission_id)
        ]

    def runs(self, *, target_key: str = "", mission_id: str = "") -> list[dict[str, Any]]:
        """Return cloud intelligence run records."""
        if self._stores is None:
            return []
        repo = self._stores.repository_for(TidbCloudRun)
        records = list(repo.list_by("target_key", target_key, limit=500)) if target_key else list(repo.stream())
        return [
            {
                "mission_id": record.mission_id,
                "target_key": record.target_key,
                "status": record.status,
                "mode": record.mode,
                "providers": record.providers,
                "accounts": record.accounts,
                "regions": record.regions,
                "resources": record.resources,
                "services": record.services,
                "endpoints": record.endpoints,
                "environments": record.environments,
                "identities": record.identities,
                "saas_providers": record.saas_providers,
                "saas_integrations": record.saas_integrations,
                "webhooks": record.webhooks,
                "changes": record.changes,
                "conflicts": record.conflicts,
                "started_at": record.started_at,
                "completed_at": record.completed_at,
                "correlation_id": record.correlation_id,
            }
            for record in records
            if record.deleted_at is None and (not mission_id or record.mission_id == mission_id)
        ]

    def summary(self, *, mission_id: str = "") -> dict[str, Any]:
        """Return a compact inventory summary for reporting."""
        return {
            "providers": len(self.providers(mission_id=mission_id)),
            "accounts": len(self.accounts(mission_id=mission_id)),
            "regions": len(self.regions(mission_id=mission_id)),
            "resources": len(self.resources(mission_id=mission_id)),
            "services": len(self.services(mission_id=mission_id)),
            "endpoints": len(self.endpoints(mission_id=mission_id)),
            "environments": len(self.environments(mission_id=mission_id)),
            "identities": len(self.identities(mission_id=mission_id)),
            "roles": len(self.roles(mission_id=mission_id)),
            "permissions": len(self.permissions(mission_id=mission_id)),
            "integrations": len(self.integrations(mission_id=mission_id)),
            "saas_providers": len(self.saas(mission_id=mission_id)),
            "saas_applications": len(self.saas_applications(mission_id=mission_id)),
            "saas_integrations": len(self.saas_integrations(mission_id=mission_id)),
            "webhooks": len(self.webhooks(mission_id=mission_id)),
            "dependencies": len(self.dependencies(mission_id=mission_id)),
            "storage": len(self.storage(mission_id=mission_id)),
            "compute": len(self.compute(mission_id=mission_id)),
            "containers": len(self.containers(mission_id=mission_id)),
            "kubernetes": len(self.kubernetes(mission_id=mission_id)),
            "databases": len(self.databases(mission_id=mission_id)),
            "message_infrastructure": len(self.message_infrastructure(mission_id=mission_id)),
            "gateways": len(self.gateways(mission_id=mission_id)),
            "cdns": len(self.cdns(mission_id=mission_id)),
            "load_balancers": len(self.load_balancers(mission_id=mission_id)),
            "cicd": len(self.cicd(mission_id=mission_id)),
            "secrets": len(self.secrets(mission_id=mission_id)),
            "exposures": len(self.exposures(mission_id=mission_id)),
            "changes": len(self.changes(mission_id=mission_id)),
        }

    # -- helpers ------------------------------------------------------------

    def _list(self, entity: type, field: str, value: str, mission_id: str) -> list[Any]:
        if self._stores is None:
            return []
        repo = self._stores.repository_for(entity)
        records = list(repo.list_by(field, value, limit=1000)) if field and value else list(repo.stream())
        if mission_id:
            records = [record for record in records if record.mission_id == mission_id]
        return [record for record in records if record.deleted_at is None]

    def _provider_dict(self, record: Any) -> dict[str, Any]:
        """Render a persisted cloud provider record."""
        return {
            "name": record.name,
            "display_name": record.display_name,
            "evidence_indicators": list(record.evidence_indicators),
            "confidence": record.confidence,
            "source": record.source,
            "tool_id": record.tool_id,
            "mission_id": record.mission_id,
            "first_seen": record.first_seen,
            "last_seen": record.last_seen,
            "id": record.id,
        }

    def _entity_dict(self, record: Any) -> dict[str, Any]:
        """Render a persisted cloud record as a JSON-safe dictionary."""
        result: dict[str, Any] = {}
        for name in (
            "provider",
            "name",
            "display_name",
            "kind",
            "value",
            "region",
            "resource",
            "service",
            "category",
            "resource_kind",
            "identifier",
            "endpoint",
            "plane",
            "exposure",
            "public",
            "environment",
            "domain",
            "identity_kind",
            "account",
            "role",
            "action",
            "integration_type",
            "saas_provider",
            "storage_kind",
            "compute_kind",
            "container_kind",
            "database_kind",
            "technology",
            "registry",
            "image",
            "cluster",
            "backend",
            "origin",
            "repository",
            "reference",
            "fingerprint",
            "direction",
            "event_type",
            "signing",
            "subject",
            "detail",
            "value",
        ):
            field_value = getattr(record, name, None)
            if field_value not in (None, ""):
                result[name] = field_value
        if getattr(record, "assume_role", None) is not None:
            result["assume_role"] = record.assume_role
        result["confidence"] = record.confidence
        result["indicators"] = list(record.indicators)
        result["source"] = record.source
        result["tool_id"] = record.tool_id
        result["mission_id"] = record.mission_id
        result["first_seen"] = record.first_seen
        result["last_seen"] = record.last_seen
        result["id"] = record.id
        return result
