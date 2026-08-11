# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Authorization intelligence use-case services.

``AuthorizationService`` is the orchestrator — the bridge between a mission and
the authorization intelligence tooling. Given a target and an input bundle of
already-acquired static material, it validates scope, builds an
:class:`AuthorizationStrategy`, runs the in-process analyzer through the
:class:`ExecutionEngine`, folds in existing TIDB intelligence, classifies,
validates, correlates, confidence-scores, diffs history, persists everything to
the TIDB, updates the attack-surface topology and publishes
``authorization.*`` events.

``AuthorizationQueryService`` reads persisted authorization intelligence back
from the TIDB and answers the reporting queries (subjects, roles, groups,
permissions, scopes, claims, policies, resources, actions, identifiers,
ownership, tenants, admin surfaces, function/object/field-level access control,
frontend/backend logic, API correlation, GraphQL/WebSocket/service
authorization, decisions, mass-assignment fields, changes and conflicts). Both
services depend on ports only.

Security boundary: intelligence only. No authorization testing, no IDOR/BOLA/
BFLA/privilege-escalation, no identifier substitution, no cross-tenant access,
no storage of sensitive values.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from hunterx.domain.authorization.classification import AuthorizationClassifier
from hunterx.domain.authorization.confidence import (
    AuthorizationConfidenceEngine,
    AuthorizationConfidencePolicy,
)
from hunterx.domain.authorization.correlator import AuthorizationCorrelator
from hunterx.domain.authorization.history import AuthorizationHistory
from hunterx.domain.authorization.models import (
    AuthorizationBatch,
    AuthorizationChange,
    AuthorizationExecutionSummary,
    AuthorizationTarget,
    AuthzAccessControlObservation,
    AuthzActionObservation,
    AuthzAdminSurfaceObservation,
    AuthzApiCorrelationObservation,
    AuthzBackendObservation,
    AuthzClaimObservation,
    AuthzDecisionObservation,
    AuthzEvidence,
    AuthzFieldLevelObservation,
    AuthzFrontendObservation,
    AuthzFunctionLevelObservation,
    AuthzGraphQLObservation,
    AuthzGroupObservation,
    AuthzMassAssignmentObservation,
    AuthzObjectLevelObservation,
    AuthzObservation,
    AuthzOwnershipObservation,
    AuthzPermissionObservation,
    AuthzPolicyObservation,
    AuthzResourceIdentifierObservation,
    AuthzResourceObservation,
    AuthzRoleObservation,
    AuthzScopeObservation,
    AuthzServiceObservation,
    AuthzSubjectObservation,
    AuthzTenantObservation,
    AuthzWebSocketObservation,
    infer_asset_type,
    observations_from_payload,
)
from hunterx.domain.authorization.scope import (
    AuthorizationScopeEnforcer,
    AuthorizationScopePolicy,
)
from hunterx.domain.authorization.strategy import (
    AuthorizationStrategy,
    AuthorizationStrategyBuilder,
)
from hunterx.domain.authorization.validator import AuthorizationValidator
from hunterx.domain.entities.tidb.authorization_intelligence import (
    AuthorizationAccessControl as TidbAuthorizationAccessControl,
)
from hunterx.domain.entities.tidb.authorization_intelligence import (
    AuthorizationAction as TidbAuthorizationAction,
)
from hunterx.domain.entities.tidb.authorization_intelligence import (
    AuthorizationAdminSurface as TidbAuthorizationAdminSurface,
)
from hunterx.domain.entities.tidb.authorization_intelligence import (
    AuthorizationApiCorrelation as TidbAuthorizationApiCorrelation,
)
from hunterx.domain.entities.tidb.authorization_intelligence import (
    AuthorizationBackend as TidbAuthorizationBackend,
)
from hunterx.domain.entities.tidb.authorization_intelligence import (
    AuthorizationChange as TidbAuthorizationChange,
)
from hunterx.domain.entities.tidb.authorization_intelligence import (
    AuthorizationClaim as TidbAuthorizationClaim,
)
from hunterx.domain.entities.tidb.authorization_intelligence import (
    AuthorizationDecision as TidbAuthorizationDecision,
)
from hunterx.domain.entities.tidb.authorization_intelligence import (
    AuthorizationEvidence as TidbAuthorizationEvidence,
)
from hunterx.domain.entities.tidb.authorization_intelligence import (
    AuthorizationFieldLevel as TidbAuthorizationFieldLevel,
)
from hunterx.domain.entities.tidb.authorization_intelligence import (
    AuthorizationFrontend as TidbAuthorizationFrontend,
)
from hunterx.domain.entities.tidb.authorization_intelligence import (
    AuthorizationFunctionLevel as TidbAuthorizationFunctionLevel,
)
from hunterx.domain.entities.tidb.authorization_intelligence import (
    AuthorizationGraphQL as TidbAuthorizationGraphQL,
)
from hunterx.domain.entities.tidb.authorization_intelligence import (
    AuthorizationGroup as TidbAuthorizationGroup,
)
from hunterx.domain.entities.tidb.authorization_intelligence import (
    AuthorizationIdentifier as TidbAuthorizationIdentifier,
)
from hunterx.domain.entities.tidb.authorization_intelligence import (
    AuthorizationMassAssignment as TidbAuthorizationMassAssignment,
)
from hunterx.domain.entities.tidb.authorization_intelligence import (
    AuthorizationObjectLevel as TidbAuthorizationObjectLevel,
)
from hunterx.domain.entities.tidb.authorization_intelligence import (
    AuthorizationObservation as TidbAuthorizationObservation,
)
from hunterx.domain.entities.tidb.authorization_intelligence import (
    AuthorizationOwnership as TidbAuthorizationOwnership,
)
from hunterx.domain.entities.tidb.authorization_intelligence import (
    AuthorizationPermission as TidbAuthorizationPermission,
)
from hunterx.domain.entities.tidb.authorization_intelligence import (
    AuthorizationPolicy as TidbAuthorizationPolicy,
)
from hunterx.domain.entities.tidb.authorization_intelligence import (
    AuthorizationResource as TidbAuthorizationResource,
)
from hunterx.domain.entities.tidb.authorization_intelligence import (
    AuthorizationRole as TidbAuthorizationRole,
)
from hunterx.domain.entities.tidb.authorization_intelligence import (
    AuthorizationRun as TidbAuthorizationRun,
)
from hunterx.domain.entities.tidb.authorization_intelligence import (
    AuthorizationScope as TidbAuthorizationScope,
)
from hunterx.domain.entities.tidb.authorization_intelligence import (
    AuthorizationService as TidbAuthorizationService,
)
from hunterx.domain.entities.tidb.authorization_intelligence import (
    AuthorizationSubject as TidbAuthorizationSubject,
)
from hunterx.domain.entities.tidb.authorization_intelligence import (
    AuthorizationTenant as TidbAuthorizationTenant,
)
from hunterx.domain.entities.tidb.authorization_intelligence import (
    AuthorizationWebSocket as TidbAuthorizationWebSocket,
)
from hunterx.domain.entities.tidb.topology import TopologyRelationship as TidbTopologyRelationship
from hunterx.domain.events.types import (
    AuthorizationActionDiscoveredEvent,
    AuthorizationAdminSurfaceDiscoveredEvent,
    AuthorizationApiCorrelationDiscoveredEvent,
    AuthorizationBackendDiscoveredEvent,
    AuthorizationChangeDetectedEvent,
    AuthorizationConflictDetectedEvent,
    AuthorizationCorrelationCompletedEvent,
    AuthorizationDecisionDiscoveredEvent,
    AuthorizationDiscoveryCompletedEvent,
    AuthorizationDiscoveryFailedEvent,
    AuthorizationDiscoveryStartedEvent,
    AuthorizationFieldLevelDiscoveredEvent,
    AuthorizationFrontendDiscoveredEvent,
    AuthorizationFunctionLevelDiscoveredEvent,
    AuthorizationGraphQLDiscoveredEvent,
    AuthorizationObjectLevelDiscoveredEvent,
    AuthorizationOwnershipDiscoveredEvent,
    AuthorizationPermissionDiscoveredEvent,
    AuthorizationPhaseStartedEvent,
    AuthorizationPolicyDiscoveredEvent,
    AuthorizationResourceDiscoveredEvent,
    AuthorizationRoleDiscoveredEvent,
    AuthorizationScopeDiscoveredEvent,
    AuthorizationServiceDiscoveredEvent,
    AuthorizationSubjectDiscoveredEvent,
    AuthorizationTenantDiscoveredEvent,
    AuthorizationWebSocketDiscoveredEvent,
)
from hunterx.domain.execution import ExecutionContext
from hunterx.domain.ports.messaging import CachePort, EventBusPort
from hunterx.domain.ports.tidb_repositories import TidbRepositoryFactory
from hunterx.domain.recon.models import ReconMode
from hunterx.domain.topology.enums import EntityKind, RelationshipType
from hunterx.domain.topology.models import GraphRelationship, TopologyEntity
from hunterx.shared.ids import generate_id
from hunterx.shared.time import utcnow_iso
from hunterx.tools.authorization.registry import AUTHORIZATION_TOOL_IDS
from hunterx.tools.sdk.context import ExecutionContextBuilder
from hunterx.tools.sdk.engine import ExecutionEngine


class AuthorizationService:
    """Run authorization intelligence missions through the Tool SDK.

    Usage::

        service = AuthorizationService(engine=engine, stores=stores, event_bus=bus)
        batch = service.run(mission_id="m1", target="https://example.com/api",
                            parameters={"authorization_input": {...}})
    """

    def __init__(
        self,
        *,
        engine: ExecutionEngine,
        stores: TidbRepositoryFactory | None = None,
        event_bus: EventBusPort | None = None,
        cache: CachePort | None = None,
        scope: AuthorizationScopePolicy | None = None,
        strategy_builder: AuthorizationStrategyBuilder | None = None,
        classifier: AuthorizationClassifier | None = None,
        confidence: AuthorizationConfidencePolicy | None = None,
        correlator: AuthorizationCorrelator | None = None,
        validator: AuthorizationValidator | None = None,
        history: AuthorizationHistory | None = None,
    ) -> None:
        self._engine = engine
        self._stores = stores
        self._event_bus = event_bus
        self._cache = cache
        self._scope = scope or AuthorizationScopePolicy()
        self._strategy_builder = strategy_builder or AuthorizationStrategyBuilder()
        self._classifier = classifier or AuthorizationClassifier()
        self._confidence = AuthorizationConfidenceEngine(confidence or AuthorizationConfidencePolicy())
        self._validator = validator or AuthorizationValidator()
        self._correlator = correlator or AuthorizationCorrelator(
            scope=self._scope,
            confidence=self._confidence.policy,
        )
        self._history = history or AuthorizationHistory()
        self._scope_enforcer = AuthorizationScopeEnforcer(self._scope)

    @property
    def engine(self) -> ExecutionEngine:
        """Return the execution engine used by this service."""
        return self._engine

    @property
    def correlator(self) -> AuthorizationCorrelator:
        """Return the correlator used to merge authorization observations."""
        return self._correlator

    def run(
        self,
        *,
        mission_id: str = "",
        target: AuthorizationTarget | str,
        mode: ReconMode | str = ReconMode.HYBRID,
        tools: Sequence[str] | None = None,
        parameters: Mapping[str, Any] | None = None,
        with_history: bool = False,
        historical: Sequence[Any] | None = None,
        min_confidence: float | None = None,
        max_concurrency: int = 4,
    ) -> AuthorizationBatch:
        """Execute an authorization analysis run and return the correlated batch.

        Args:
            mission_id: owning mission id (empty for ad-hoc runs).
            target: the target to analyse (URL, hostname, domain or IP).
            mode: the execution posture (passive, active or hybrid). The
                analyzer is in-process and never tests authorization, so
                passive postures still run it against supplied static material.
            tools: analysis tool ids to run; defaults to every registered
                authorization tool. Requesting an unregistered tool raises
                :class:`ValueError`.
            parameters: per-tool parameters merged into each execution context
                (typically an ``authorization_input`` bundle).
            with_history: compare current observations against ``historical``.
            historical: historical observations to diff against.
            min_confidence: minimum confidence for a record to be retained.
            max_concurrency: execution concurrency ceiling.

        Returns:
            The :class:`AuthorizationBatch` with correlated records, evidence,
            conflicts, changes and execution summaries.

        Raises:
            ValueError: when the target is out of scope or a requested tool is
                not registered.

        """
        authz_target = target if isinstance(target, AuthorizationTarget) else _make_target(target)
        decision = self._scope_enforcer.allows_target(authz_target)
        if not decision.allowed:
            raise ValueError(f"authorization target is out of scope: {decision.reason}")
        recon_mode = _make_mode(mode)
        selected = self._select_tools(tools)
        correlation_id = generate_id()
        parameters = dict(parameters or {})
        parameters["mode"] = recon_mode.value
        if authz_target.target_id:
            parameters["target_id"] = authz_target.target_id

        strategy = self._strategy_builder.build(
            authz_target.value,
            mode=recon_mode,
            target_kind=authz_target.target_type,
            tools=tuple(selected) if selected else (),
            include_history=with_history,
            min_confidence=min_confidence,
            max_concurrency=max_concurrency,
        )
        runnable = [tool_id for tool_id in strategy.tools if tool_id in selected]

        batch = AuthorizationBatch(
            mission_id=mission_id,
            correlation_id=correlation_id,
            target=authz_target,
            mode=recon_mode,
        )
        self._publish(
            AuthorizationDiscoveryStartedEvent(
                mission_id,
                correlation_id,
                authz_target.value,
                mode=recon_mode.value,
                tools=list(runnable),
            )
        )

        raw: list[Any] = []
        try:
            self._publish(AuthorizationPhaseStartedEvent(correlation_id, "collection", mission_id=mission_id))
            for tool_id in runnable:
                context = self._build_context(
                    tool_id,
                    authz_target,
                    mission_id,
                    correlation_id,
                    parameters,
                    strategy,
                )
                outcome = self._engine.execute(context)
                result = outcome.result
                found = observations_from_payload(result.output.json) if result.status.is_success else []
                raw.extend(found)
                summary = AuthorizationExecutionSummary(
                    tool_id=tool_id,
                    status=result.status.value,
                    observations=len(found),
                    resources=len([obs for obs in found if isinstance(obs, AuthzResourceObservation)]),
                    duration_ms=result.duration_ms,
                    error=result.error,
                )
                batch.add_execution(summary)

            if strategy.include_existing and self._stores is not None:
                self._publish(AuthorizationPhaseStartedEvent(correlation_id, "existing-intelligence", mission_id=mission_id))
                raw.extend(self._collect_existing(authz_target, mission_id, correlation_id))

            self._publish(AuthorizationPhaseStartedEvent(correlation_id, "classification", mission_id=mission_id))
            classified = self._classify(raw)

            self._publish(AuthorizationPhaseStartedEvent(correlation_id, "validation", mission_id=mission_id))
            classified = self._validator.filter_valid(classified)

            self._publish(AuthorizationPhaseStartedEvent(correlation_id, "correlation", mission_id=mission_id))
            correlation = self._correlator.correlate(classified, min_confidence=strategy.min_confidence)
            batch.records = list(correlation.records)
            for conflict in correlation.conflicts:
                batch.add_conflict(conflict)
                self._publish(
                    AuthorizationConflictDetectedEvent(
                        correlation_id,
                        conflict.subject,
                        conflict.conflict_type,
                        selected=conflict.selected,
                        mission_id=mission_id,
                    )
                )
            self._publish(
                AuthorizationCorrelationCompletedEvent(
                    mission_id,
                    correlation_id,
                    raw_observations=len(raw),
                    correlated_observations=len(batch.records),
                    conflicts=len(batch.conflicts),
                )
            )

            self._publish(AuthorizationPhaseStartedEvent(correlation_id, "history", mission_id=mission_id))
            if strategy.include_history and historical is not None:
                comparison = self._history.compare(historical, batch.records)
                for change in comparison.changes:
                    batch.add_change(change)
                    self._publish_change(change, correlation_id, mission_id)

            self._publish_discoveries(batch, correlation_id, mission_id)

            if self._stores is not None:
                self._publish(AuthorizationPhaseStartedEvent(correlation_id, "persistence", mission_id=mission_id))
                self._persist(batch, authz_target, mission_id, correlation_id)

            self._publish(AuthorizationPhaseStartedEvent(correlation_id, "topology", mission_id=mission_id))
            if self._stores is not None:
                self._update_topology(batch, mission_id, correlation_id)

            self._publish(
                AuthorizationDiscoveryCompletedEvent(
                    mission_id,
                    correlation_id,
                    target=authz_target.value,
                    resources=batch.resource_count(),
                    roles=batch.role_count(),
                    permissions=_count_of(batch.records, AuthzPermissionObservation),
                    admin_surfaces=_count_of(batch.records, AuthzAdminSurfaceObservation),
                    changes=batch.change_count(),
                    conflicts=batch.conflict_count(),
                )
            )
        except Exception as exc:  # noqa: BLE001 - surfaced as a completion failure
            self._publish(
                AuthorizationDiscoveryFailedEvent(
                    mission_id,
                    correlation_id,
                    authz_target.value,
                    str(exc),
                )
            )
            raise
        return batch

    # -- pipeline helpers ---------------------------------------------------

    def _select_tools(self, tools: Sequence[str] | None) -> list[str]:
        """Return the registered authorization analysis tools to run."""
        registered = self._engine.adapter_for
        if tools is None:
            return [tool_id for tool_id in AUTHORIZATION_TOOL_IDS if registered(tool_id) is not None]
        requested = list(tools)
        missing = [tool_id for tool_id in requested if registered(tool_id) is None]
        if missing:
            raise ValueError(f"requested authorization tools are not registered: {', '.join(missing)}")
        return requested

    def _build_context(
        self,
        tool_id: str,
        target: AuthorizationTarget,
        mission_id: str,
        correlation_id: str,
        parameters: Mapping[str, Any],
        strategy: AuthorizationStrategy,
    ) -> ExecutionContext:
        """Build an execution context for one authorization analysis tool."""
        merged = dict(parameters)
        merged.setdefault("target", target.value)
        merged.setdefault("target_kind", target.target_type)
        return (
            ExecutionContextBuilder(tool_id=tool_id, target=target.value)
            .with_mission(mission_id)
            .with_target_type(target.target_type)
            .with_profile("authorization")
            .with_correlation_id(correlation_id)
            .with_permissions(("network",))
            .with_parameters(merged)
            .build()
        )

    def _classify(self, observations: Sequence[Any]) -> list[Any]:
        """Refine admin-surface/resource classifications deterministically."""
        classified: list[Any] = []
        for observation in observations:
            if isinstance(observation, AuthzAdminSurfaceObservation):
                classified.append(self._classifier.classify_admin_surface(observation))
            elif isinstance(observation, AuthzResourceObservation):
                classified.append(self._classifier.classify_resource(observation))
            else:
                classified.append(observation)
        return classified

    def _collect_existing(
        self,
        target: AuthorizationTarget,
        mission_id: str,
        correlation_id: str,
    ) -> list[Any]:
        """Fold previously persisted authorization intelligence into the run."""
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
        """Read previously persisted authorization records for ``target_key``."""
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
        batch: AuthorizationBatch,
        target: AuthorizationTarget,
        mission_id: str,
        correlation_id: str,
    ) -> int:
        """Persist correlated authorization intelligence into the TIDB."""
        stores = self._stores
        if stores is None:
            raise RuntimeError("cannot persist authorization intelligence without TIDB stores")
        count = 0
        for record in batch.records:
            entity = _to_entity(record, target, mission_id, correlation_id)
            if entity is None:
                continue
            stores.repository_for(type(entity)).save(entity)
            count += 1
            for evidence in getattr(record, "evidence", ()) or ():
                stores.repository_for(TidbAuthorizationEvidence).save(
                    _to_evidence_entity(record, evidence, entity.id, mission_id, correlation_id)
                )
                count += 1
        for conflict in batch.conflicts:
            stores.repository_for(TidbAuthorizationChange).save(
                TidbAuthorizationChange(
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
            stores.repository_for(TidbAuthorizationChange).save(
                _to_change_entity(change, mission_id, correlation_id)
            )
            count += 1
        run = TidbAuthorizationRun(
            mission_id=mission_id,
            target_key=target.value,
            target_id=target.target_id or None,
            status="completed",
            mode=batch.mode.value,
            subjects=_count_of(batch.records, AuthzSubjectObservation),
            roles=batch.role_count(),
            permissions=_count_of(batch.records, AuthzPermissionObservation),
            resources=batch.resource_count(),
            actions=_count_of(batch.records, AuthzActionObservation),
            admin_surfaces=_count_of(batch.records, AuthzAdminSurfaceObservation),
            function_level=_count_of(batch.records, AuthzFunctionLevelObservation),
            object_level=_count_of(batch.records, AuthzObjectLevelObservation),
            field_level=_count_of(batch.records, AuthzFieldLevelObservation),
            changes=batch.change_count(),
            conflicts=batch.conflict_count(),
            started_at=batch.created_at,
            completed_at=utcnow_iso(),
            summary={
                "observations": batch.total_observations(),
                "records": batch.record_count(),
                "tools": [summary.tool_id for summary in batch.executions],
                "groups": _count_of(batch.records, AuthzGroupObservation),
                "scopes": _count_of(batch.records, AuthzScopeObservation),
                "claims": _count_of(batch.records, AuthzClaimObservation),
                "policies": _count_of(batch.records, AuthzPolicyObservation),
                "identifiers": _count_of(batch.records, AuthzResourceIdentifierObservation),
                "ownership": _count_of(batch.records, AuthzOwnershipObservation),
                "tenants": _count_of(batch.records, AuthzTenantObservation),
                "frontend": _count_of(batch.records, AuthzFrontendObservation),
                "backend": _count_of(batch.records, AuthzBackendObservation),
                "api_correlations": _count_of(batch.records, AuthzApiCorrelationObservation),
                "graphql": _count_of(batch.records, AuthzGraphQLObservation),
                "websockets": _count_of(batch.records, AuthzWebSocketObservation),
                "services": _count_of(batch.records, AuthzServiceObservation),
                "decisions": _count_of(batch.records, AuthzDecisionObservation),
                "mass_assignment": _count_of(batch.records, AuthzMassAssignmentObservation),
                "access_control": _count_of(batch.records, AuthzAccessControlObservation),
            },
            correlation_id=correlation_id,
        )
        stores.repository_for(TidbAuthorizationRun).save(run)
        count += 1
        return count

    def _update_topology(self, batch: AuthorizationBatch, mission_id: str, correlation_id: str) -> None:
        """Project authorization records into the attack-surface topology."""
        stores = self._stores
        if stores is None:
            return
        repo = stores.repository_for(TidbTopologyRelationship)
        for edge in _topology_edges(batch, mission_id, correlation_id):
            repo.save(edge.to_tidb())

    # -- events -------------------------------------------------------------

    def _publish_discoveries(self, batch: AuthorizationBatch, correlation_id: str, mission_id: str) -> None:
        """Publish discovery events for the correlated set."""
        for record in batch.records:
            self._publish_record(record, correlation_id, mission_id)

    def _publish_record(self, record: Any, correlation_id: str, mission_id: str) -> None:
        origin = str(getattr(record, "origin", "") or "")
        if isinstance(record, AuthzSubjectObservation):
            self._publish(
                AuthorizationSubjectDiscoveredEvent(
                    correlation_id,
                    origin,
                    record.name,
                    subject_kind=_v(record.subject_kind),
                    confidence=record.confidence,
                    mission_id=mission_id,
                )
            )
        elif isinstance(record, AuthzRoleObservation):
            self._publish(
                AuthorizationRoleDiscoveredEvent(
                    correlation_id,
                    origin,
                    record.name,
                    confidence=record.confidence,
                    mission_id=mission_id,
                )
            )
        elif isinstance(record, AuthzPermissionObservation):
            self._publish(
                AuthorizationPermissionDiscoveredEvent(
                    correlation_id,
                    origin,
                    record.name,
                    confidence=record.confidence,
                    mission_id=mission_id,
                )
            )
        elif isinstance(record, AuthzScopeObservation):
            self._publish(
                AuthorizationScopeDiscoveredEvent(
                    correlation_id,
                    origin,
                    record.name,
                    confidence=record.confidence,
                    mission_id=mission_id,
                )
            )
        elif isinstance(record, AuthzPolicyObservation):
            self._publish(
                AuthorizationPolicyDiscoveredEvent(
                    correlation_id,
                    origin,
                    name=record.name,
                    model_kind=_v(record.model_kind),
                    confidence=record.confidence,
                    mission_id=mission_id,
                )
            )
        elif isinstance(record, AuthzResourceObservation):
            self._publish(
                AuthorizationResourceDiscoveredEvent(
                    correlation_id,
                    origin,
                    record.name,
                    resource_kind=_v(record.resource_kind),
                    confidence=record.confidence,
                    mission_id=mission_id,
                )
            )
        elif isinstance(record, AuthzActionObservation):
            self._publish(
                AuthorizationActionDiscoveredEvent(
                    correlation_id,
                    origin,
                    record.name,
                    resource=record.resource,
                    confidence=record.confidence,
                    mission_id=mission_id,
                )
            )
        elif isinstance(record, AuthzOwnershipObservation):
            self._publish(
                AuthorizationOwnershipDiscoveredEvent(
                    correlation_id,
                    origin,
                    record.name,
                    confidence=record.confidence,
                    mission_id=mission_id,
                )
            )
        elif isinstance(record, AuthzTenantObservation):
            self._publish(
                AuthorizationTenantDiscoveredEvent(
                    correlation_id,
                    origin,
                    record.name,
                    tenant_kind=_v(record.tenant_kind),
                    confidence=record.confidence,
                    mission_id=mission_id,
                )
            )
        elif isinstance(record, AuthzAdminSurfaceObservation):
            self._publish(
                AuthorizationAdminSurfaceDiscoveredEvent(
                    correlation_id,
                    origin,
                    url=record.url,
                    surface_kind=_v(record.surface_kind),
                    confidence=record.confidence,
                    mission_id=mission_id,
                )
            )
        elif isinstance(record, AuthzFunctionLevelObservation):
            self._publish(
                AuthorizationFunctionLevelDiscoveredEvent(
                    correlation_id,
                    origin,
                    function=record.function,
                    endpoint=record.endpoint,
                    confidence=record.confidence,
                    mission_id=mission_id,
                )
            )
        elif isinstance(record, AuthzObjectLevelObservation):
            self._publish(
                AuthorizationObjectLevelDiscoveredEvent(
                    correlation_id,
                    origin,
                    resource=record.resource,
                    endpoint=record.endpoint,
                    confidence=record.confidence,
                    mission_id=mission_id,
                )
            )
        elif isinstance(record, AuthzFieldLevelObservation):
            self._publish(
                AuthorizationFieldLevelDiscoveredEvent(
                    correlation_id,
                    origin,
                    field_name=record.field,
                    resource=record.resource,
                    confidence=record.confidence,
                    mission_id=mission_id,
                )
            )
        elif isinstance(record, AuthzFrontendObservation):
            self._publish(
                AuthorizationFrontendDiscoveredEvent(
                    correlation_id,
                    origin,
                    check_type=record.check_type,
                    target=record.target,
                    confidence=record.confidence,
                    mission_id=mission_id,
                )
            )
        elif isinstance(record, AuthzBackendObservation):
            self._publish(
                AuthorizationBackendDiscoveredEvent(
                    correlation_id,
                    origin,
                    mechanism=record.mechanism,
                    name=record.name,
                    confidence=record.confidence,
                    mission_id=mission_id,
                )
            )
        elif isinstance(record, AuthzApiCorrelationObservation):
            self._publish(
                AuthorizationApiCorrelationDiscoveredEvent(
                    correlation_id,
                    origin,
                    endpoint=record.endpoint,
                    method=record.method,
                    authentication=record.authentication,
                    confidence=record.confidence,
                    mission_id=mission_id,
                )
            )
        elif isinstance(record, AuthzGraphQLObservation):
            self._publish(
                AuthorizationGraphQLDiscoveredEvent(
                    correlation_id,
                    origin,
                    subject=record.subject,
                    name=record.name,
                    directive=record.directive,
                    confidence=record.confidence,
                    mission_id=mission_id,
                )
            )
        elif isinstance(record, AuthzWebSocketObservation):
            self._publish(
                AuthorizationWebSocketDiscoveredEvent(
                    correlation_id,
                    origin,
                    endpoint=record.endpoint,
                    mechanism=record.mechanism,
                    confidence=record.confidence,
                    mission_id=mission_id,
                )
            )
        elif isinstance(record, AuthzServiceObservation):
            self._publish(
                AuthorizationServiceDiscoveredEvent(
                    correlation_id,
                    origin,
                    record.name,
                    confidence=record.confidence,
                    mission_id=mission_id,
                )
            )
        elif isinstance(record, AuthzDecisionObservation):
            self._publish(
                AuthorizationDecisionDiscoveredEvent(
                    correlation_id,
                    origin,
                    _v(record.decision),
                    endpoint=record.endpoint,
                    confidence=record.confidence,
                    mission_id=mission_id,
                )
            )

    def _publish_change(self, change: AuthorizationChange, correlation_id: str, mission_id: str) -> None:
        """Publish the event for one historical change."""
        self._publish(
            AuthorizationChangeDetectedEvent(
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
    TidbAuthorizationSubject,
    TidbAuthorizationRole,
    TidbAuthorizationGroup,
    TidbAuthorizationPermission,
    TidbAuthorizationScope,
    TidbAuthorizationClaim,
    TidbAuthorizationPolicy,
    TidbAuthorizationResource,
    TidbAuthorizationAction,
    TidbAuthorizationIdentifier,
    TidbAuthorizationOwnership,
    TidbAuthorizationTenant,
    TidbAuthorizationAdminSurface,
    TidbAuthorizationFunctionLevel,
    TidbAuthorizationObjectLevel,
    TidbAuthorizationFieldLevel,
    TidbAuthorizationFrontend,
    TidbAuthorizationBackend,
    TidbAuthorizationApiCorrelation,
    TidbAuthorizationGraphQL,
    TidbAuthorizationWebSocket,
    TidbAuthorizationService,
    TidbAuthorizationDecision,
    TidbAuthorizationMassAssignment,
    TidbAuthorizationAccessControl,
    TidbAuthorizationObservation,
)


def _to_entity(record: Any, target: AuthorizationTarget, mission_id: str, correlation_id: str) -> Any | None:
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
    if isinstance(record, AuthzSubjectObservation):
        return TidbAuthorizationSubject(
            origin=record.origin,
            name=record.name,
            subject_kind=_v(record.subject_kind),
            context=record.context,
            indicators=list(record.indicators),
            confidence=record.confidence,
            **base,
        )
    if isinstance(record, AuthzRoleObservation):
        return TidbAuthorizationRole(
            origin=record.origin,
            name=record.name,
            context=record.context,
            default=record.default,
            custom=record.custom,
            indicators=list(record.indicators),
            confidence=record.confidence,
            **base,
        )
    if isinstance(record, AuthzGroupObservation):
        return TidbAuthorizationGroup(
            origin=record.origin,
            name=record.name,
            context=record.context,
            indicators=list(record.indicators),
            confidence=record.confidence,
            **base,
        )
    if isinstance(record, AuthzPermissionObservation):
        return TidbAuthorizationPermission(
            origin=record.origin,
            name=record.name,
            action=record.action,
            resource=record.resource,
            indicators=list(record.indicators),
            confidence=record.confidence,
            **base,
        )
    if isinstance(record, AuthzScopeObservation):
        return TidbAuthorizationScope(
            origin=record.origin,
            name=record.name,
            description=record.description,
            indicators=list(record.indicators),
            confidence=record.confidence,
            **base,
        )
    if isinstance(record, AuthzClaimObservation):
        return TidbAuthorizationClaim(
            origin=record.origin,
            name=record.name,
            value=record.value,
            indicators=list(record.indicators),
            confidence=record.confidence,
            **base,
        )
    if isinstance(record, AuthzPolicyObservation):
        return TidbAuthorizationPolicy(
            origin=record.origin,
            name=record.name,
            model_kind=_v(record.model_kind),
            mechanism=record.mechanism,
            indicators=list(record.indicators),
            confidence=record.confidence,
            **base,
        )
    if isinstance(record, AuthzResourceObservation):
        return TidbAuthorizationResource(
            origin=record.origin,
            name=record.name,
            resource_kind=_v(record.resource_kind),
            identifier=record.identifier,
            parent=record.parent,
            indicators=list(record.indicators),
            confidence=record.confidence,
            **base,
        )
    if isinstance(record, AuthzActionObservation):
        return TidbAuthorizationAction(
            origin=record.origin,
            name=record.name,
            original=record.original,
            resource=record.resource,
            indicators=list(record.indicators),
            confidence=record.confidence,
            **base,
        )
    if isinstance(record, AuthzResourceIdentifierObservation):
        return TidbAuthorizationIdentifier(
            origin=record.origin,
            identifier=record.identifier,
            identifier_kind=_v(record.identifier_kind),
            location=record.location,
            endpoint=record.endpoint,
            indicators=list(record.indicators),
            confidence=record.confidence,
            **base,
        )
    if isinstance(record, AuthzOwnershipObservation):
        return TidbAuthorizationOwnership(
            origin=record.origin,
            name=record.name,
            ownership_kind=_v(record.ownership_kind),
            resource=record.resource,
            indicators=list(record.indicators),
            confidence=record.confidence,
            **base,
        )
    if isinstance(record, AuthzTenantObservation):
        return TidbAuthorizationTenant(
            origin=record.origin,
            name=record.name,
            tenant_kind=_v(record.tenant_kind),
            location=record.location,
            indicators=list(record.indicators),
            confidence=record.confidence,
            **base,
        )
    if isinstance(record, AuthzAdminSurfaceObservation):
        return TidbAuthorizationAdminSurface(
            url=record.url,
            origin=record.origin,
            surface_kind=_v(record.surface_kind),
            method=record.method,
            api_id=record.api_id,
            indicators=list(record.indicators),
            confidence=record.confidence,
            **base,
        )
    if isinstance(record, AuthzFunctionLevelObservation):
        return TidbAuthorizationFunctionLevel(
            origin=record.origin,
            function=record.function,
            endpoint=record.endpoint,
            method=record.method,
            required_role=record.required_role,
            indicators=list(record.indicators),
            confidence=record.confidence,
            **base,
        )
    if isinstance(record, AuthzObjectLevelObservation):
        return TidbAuthorizationObjectLevel(
            origin=record.origin,
            resource=record.resource,
            identifier=record.identifier,
            action=record.action,
            endpoint=record.endpoint,
            method=record.method,
            parent_resource=record.parent_resource,
            indicators=list(record.indicators),
            confidence=record.confidence,
            **base,
        )
    if isinstance(record, AuthzFieldLevelObservation):
        return TidbAuthorizationFieldLevel(
            origin=record.origin,
            field=record.field,
            resource=record.resource,
            endpoint=record.endpoint,
            indicators=list(record.indicators),
            confidence=record.confidence,
            **base,
        )
    if isinstance(record, AuthzFrontendObservation):
        return TidbAuthorizationFrontend(
            origin=record.origin,
            check_type=record.check_type,
            target=record.target,
            js_asset=record.js_asset,
            indicators=list(record.indicators),
            confidence=record.confidence,
            **base,
        )
    if isinstance(record, AuthzBackendObservation):
        return TidbAuthorizationBackend(
            origin=record.origin,
            mechanism=record.mechanism,
            name=record.name,
            target=record.target,
            indicators=list(record.indicators),
            confidence=record.confidence,
            **base,
        )
    if isinstance(record, AuthzApiCorrelationObservation):
        return TidbAuthorizationApiCorrelation(
            origin=record.origin,
            endpoint=record.endpoint,
            method=record.method,
            authentication=record.authentication,
            role=record.role,
            scope=record.scope,
            permission=record.permission,
            resource=record.resource,
            action=record.action,
            tenant=record.tenant,
            policy=record.policy,
            documented=record.documented,
            indicators=list(record.indicators),
            confidence=record.confidence,
            **base,
        )
    if isinstance(record, AuthzGraphQLObservation):
        return TidbAuthorizationGraphQL(
            origin=record.origin,
            subject=record.subject,
            name=record.name,
            directive=record.directive,
            indicators=list(record.indicators),
            confidence=record.confidence,
            **base,
        )
    if isinstance(record, AuthzWebSocketObservation):
        return TidbAuthorizationWebSocket(
            origin=record.origin,
            endpoint=record.endpoint,
            channel=record.channel,
            mechanism=record.mechanism,
            indicators=list(record.indicators),
            confidence=record.confidence,
            **base,
        )
    if isinstance(record, AuthzServiceObservation):
        return TidbAuthorizationService(
            origin=record.origin,
            name=record.name,
            service_kind=record.service_kind,
            mechanism=record.mechanism,
            indicators=list(record.indicators),
            confidence=record.confidence,
            **base,
        )
    if isinstance(record, AuthzDecisionObservation):
        return TidbAuthorizationDecision(
            origin=record.origin,
            decision=_v(record.decision),
            endpoint=record.endpoint,
            method=record.method,
            indicators=list(record.indicators),
            confidence=record.confidence,
            **base,
        )
    if isinstance(record, AuthzMassAssignmentObservation):
        return TidbAuthorizationMassAssignment(
            origin=record.origin,
            model=record.model,
            fields=list(record.fields),
            indicators=list(record.indicators),
            confidence=record.confidence,
            **base,
        )
    if isinstance(record, AuthzAccessControlObservation):
        return TidbAuthorizationAccessControl(
            origin=record.origin,
            subject=record.subject,
            relationship_type=record.relationship_type,
            target=record.target,
            resource=record.resource,
            indicators=list(record.indicators),
            confidence=record.confidence,
            **base,
        )
    if isinstance(record, AuthzObservation):
        return TidbAuthorizationObservation(
            origin=record.origin,
            kind=_v(record.kind),
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
    evidence: AuthzEvidence,
    subject_id: str,
    mission_id: str,
    correlation_id: str,
) -> TidbAuthorizationEvidence:
    """Map an evidence fragment onto the TIDB evidence entity."""
    return TidbAuthorizationEvidence(
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


def _to_change_entity(change: AuthorizationChange, mission_id: str, correlation_id: str) -> TidbAuthorizationChange:
    """Map a historical change onto the TIDB change entity."""
    return TidbAuthorizationChange(
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
    """Convert a persisted TIDB authorization record back into an observation."""
    observed_at = record.last_seen or record.created_at
    base = {
        "source": record.source or "tidb",
        "tool_id": record.tool_id or "tidb",
        "target_key": target_key,
        "correlation_id": correlation_id,
        "mission_id": mission_id,
        "observed_at": observed_at,
    }
    if isinstance(record, TidbAuthorizationSubject):
        return AuthzSubjectObservation(
            origin=record.origin,
            name=record.name,
            subject_kind=record.subject_kind,
            context=record.context,
            indicators=tuple(record.indicators),
            confidence=record.confidence,
            evidence=(_tidb_evidence("subject", record),),
            **base,
        )
    if isinstance(record, TidbAuthorizationRole):
        return AuthzRoleObservation(
            origin=record.origin,
            name=record.name,
            context=record.context,
            default=record.default,
            custom=record.custom,
            indicators=tuple(record.indicators),
            confidence=record.confidence,
            evidence=(_tidb_evidence("role", record),),
            **base,
        )
    if isinstance(record, TidbAuthorizationGroup):
        return AuthzGroupObservation(
            origin=record.origin,
            name=record.name,
            context=record.context,
            indicators=tuple(record.indicators),
            confidence=record.confidence,
            evidence=(_tidb_evidence("group", record),),
            **base,
        )
    if isinstance(record, TidbAuthorizationPermission):
        return AuthzPermissionObservation(
            origin=record.origin,
            name=record.name,
            action=record.action,
            resource=record.resource,
            indicators=tuple(record.indicators),
            confidence=record.confidence,
            evidence=(_tidb_evidence("permission", record),),
            **base,
        )
    if isinstance(record, TidbAuthorizationScope):
        return AuthzScopeObservation(
            origin=record.origin,
            name=record.name,
            description=record.description,
            indicators=tuple(record.indicators),
            confidence=record.confidence,
            evidence=(_tidb_evidence("scope", record),),
            **base,
        )
    if isinstance(record, TidbAuthorizationClaim):
        return AuthzClaimObservation(
            origin=record.origin,
            name=record.name,
            value=record.value,
            indicators=tuple(record.indicators),
            confidence=record.confidence,
            evidence=(_tidb_evidence("claim", record),),
            **base,
        )
    if isinstance(record, TidbAuthorizationPolicy):
        return AuthzPolicyObservation(
            origin=record.origin,
            name=record.name,
            model_kind=record.model_kind,
            mechanism=record.mechanism,
            indicators=tuple(record.indicators),
            confidence=record.confidence,
            evidence=(_tidb_evidence("policy", record),),
            **base,
        )
    if isinstance(record, TidbAuthorizationResource):
        return AuthzResourceObservation(
            origin=record.origin,
            name=record.name,
            resource_kind=record.resource_kind,
            identifier=record.identifier,
            parent=record.parent,
            indicators=tuple(record.indicators),
            confidence=record.confidence,
            evidence=(_tidb_evidence("resource", record),),
            **base,
        )
    if isinstance(record, TidbAuthorizationAction):
        return AuthzActionObservation(
            origin=record.origin,
            name=record.name,
            original=record.original,
            resource=record.resource,
            indicators=tuple(record.indicators),
            confidence=record.confidence,
            evidence=(_tidb_evidence("action", record),),
            **base,
        )
    if isinstance(record, TidbAuthorizationIdentifier):
        return AuthzResourceIdentifierObservation(
            origin=record.origin,
            identifier=record.identifier,
            identifier_kind=record.identifier_kind,
            location=record.location,
            endpoint=record.endpoint,
            indicators=tuple(record.indicators),
            confidence=record.confidence,
            evidence=(_tidb_evidence("identifier", record),),
            **base,
        )
    if isinstance(record, TidbAuthorizationOwnership):
        return AuthzOwnershipObservation(
            origin=record.origin,
            name=record.name,
            ownership_kind=record.ownership_kind,
            resource=record.resource,
            indicators=tuple(record.indicators),
            confidence=record.confidence,
            evidence=(_tidb_evidence("ownership", record),),
            **base,
        )
    if isinstance(record, TidbAuthorizationTenant):
        return AuthzTenantObservation(
            origin=record.origin,
            name=record.name,
            tenant_kind=record.tenant_kind,
            location=record.location,
            indicators=tuple(record.indicators),
            confidence=record.confidence,
            evidence=(_tidb_evidence("tenant", record),),
            **base,
        )
    if isinstance(record, TidbAuthorizationAdminSurface):
        return AuthzAdminSurfaceObservation(
            url=record.url,
            origin=record.origin,
            surface_kind=record.surface_kind,
            method=record.method,
            api_id=record.api_id,
            indicators=tuple(record.indicators),
            confidence=record.confidence,
            evidence=(_tidb_evidence("admin-surface", record),),
            **base,
        )
    if isinstance(record, TidbAuthorizationFunctionLevel):
        return AuthzFunctionLevelObservation(
            origin=record.origin,
            function=record.function,
            endpoint=record.endpoint,
            method=record.method,
            required_role=record.required_role,
            indicators=tuple(record.indicators),
            confidence=record.confidence,
            evidence=(_tidb_evidence("function-level", record),),
            **base,
        )
    if isinstance(record, TidbAuthorizationObjectLevel):
        return AuthzObjectLevelObservation(
            origin=record.origin,
            resource=record.resource,
            identifier=record.identifier,
            action=record.action,
            endpoint=record.endpoint,
            method=record.method,
            parent_resource=record.parent_resource,
            indicators=tuple(record.indicators),
            confidence=record.confidence,
            evidence=(_tidb_evidence("object-level", record),),
            **base,
        )
    if isinstance(record, TidbAuthorizationFieldLevel):
        return AuthzFieldLevelObservation(
            origin=record.origin,
            field=record.field,
            resource=record.resource,
            endpoint=record.endpoint,
            indicators=tuple(record.indicators),
            confidence=record.confidence,
            evidence=(_tidb_evidence("field-level", record),),
            **base,
        )
    if isinstance(record, TidbAuthorizationFrontend):
        return AuthzFrontendObservation(
            origin=record.origin,
            check_type=record.check_type,
            target=record.target,
            js_asset=record.js_asset,
            indicators=tuple(record.indicators),
            confidence=record.confidence,
            evidence=(_tidb_evidence("frontend", record),),
            **base,
        )
    if isinstance(record, TidbAuthorizationBackend):
        return AuthzBackendObservation(
            origin=record.origin,
            mechanism=record.mechanism,
            name=record.name,
            target=record.target,
            indicators=tuple(record.indicators),
            confidence=record.confidence,
            evidence=(_tidb_evidence("backend", record),),
            **base,
        )
    if isinstance(record, TidbAuthorizationApiCorrelation):
        return AuthzApiCorrelationObservation(
            origin=record.origin,
            endpoint=record.endpoint,
            method=record.method,
            authentication=record.authentication,
            role=record.role,
            scope=record.scope,
            permission=record.permission,
            resource=record.resource,
            action=record.action,
            tenant=record.tenant,
            policy=record.policy,
            documented=record.documented,
            indicators=tuple(record.indicators),
            confidence=record.confidence,
            evidence=(_tidb_evidence("api-correlation", record),),
            **base,
        )
    if isinstance(record, TidbAuthorizationGraphQL):
        return AuthzGraphQLObservation(
            origin=record.origin,
            subject=record.subject,
            name=record.name,
            directive=record.directive,
            indicators=tuple(record.indicators),
            confidence=record.confidence,
            evidence=(_tidb_evidence("graphql", record),),
            **base,
        )
    if isinstance(record, TidbAuthorizationWebSocket):
        return AuthzWebSocketObservation(
            origin=record.origin,
            endpoint=record.endpoint,
            channel=record.channel,
            mechanism=record.mechanism,
            indicators=tuple(record.indicators),
            confidence=record.confidence,
            evidence=(_tidb_evidence("websocket", record),),
            **base,
        )
    if isinstance(record, TidbAuthorizationService):
        return AuthzServiceObservation(
            origin=record.origin,
            name=record.name,
            service_kind=record.service_kind,
            mechanism=record.mechanism,
            indicators=tuple(record.indicators),
            confidence=record.confidence,
            evidence=(_tidb_evidence("service", record),),
            **base,
        )
    if isinstance(record, TidbAuthorizationDecision):
        return AuthzDecisionObservation(
            origin=record.origin,
            decision=record.decision,
            endpoint=record.endpoint,
            method=record.method,
            indicators=tuple(record.indicators),
            confidence=record.confidence,
            evidence=(_tidb_evidence("decision", record),),
            **base,
        )
    if isinstance(record, TidbAuthorizationMassAssignment):
        return AuthzMassAssignmentObservation(
            origin=record.origin,
            model=record.model,
            fields=tuple(record.fields),
            indicators=tuple(record.indicators),
            confidence=record.confidence,
            evidence=(_tidb_evidence("mass-assignment", record),),
            **base,
        )
    if isinstance(record, TidbAuthorizationAccessControl):
        return AuthzAccessControlObservation(
            origin=record.origin,
            subject=record.subject,
            relationship_type=record.relationship_type,
            target=record.target,
            resource=record.resource,
            indicators=tuple(record.indicators),
            confidence=record.confidence,
            evidence=(_tidb_evidence("access-control", record),),
            **base,
        )
    if isinstance(record, TidbAuthorizationObservation):
        return AuthzObservation(
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


def _tidb_evidence(subject_type: str, record: Any) -> AuthzEvidence:
    return AuthzEvidence(
        evidence_type="tidb-intelligence",
        value=record.origin or getattr(record, "name", "") or subject_type,
        source="tidb",
        strength="moderate",
        tool_id="tidb",
        detail=f"previously persisted {subject_type} intelligence",
    )


def _subject_type_of(record: Any) -> str:
    mapping = {
        "AuthzSubjectObservation": "subject",
        "AuthzRoleObservation": "role",
        "AuthzGroupObservation": "group",
        "AuthzPermissionObservation": "permission",
        "AuthzScopeObservation": "scope",
        "AuthzClaimObservation": "claim",
        "AuthzPolicyObservation": "policy",
        "AuthzResourceObservation": "resource",
        "AuthzActionObservation": "action",
        "AuthzResourceIdentifierObservation": "identifier",
        "AuthzOwnershipObservation": "ownership",
        "AuthzTenantObservation": "tenant",
        "AuthzAdminSurfaceObservation": "admin-surface",
        "AuthzFunctionLevelObservation": "function-level",
        "AuthzObjectLevelObservation": "object-level",
        "AuthzFieldLevelObservation": "field-level",
        "AuthzFrontendObservation": "frontend",
        "AuthzBackendObservation": "backend",
        "AuthzApiCorrelationObservation": "api-correlation",
        "AuthzGraphQLObservation": "graphql",
        "AuthzWebSocketObservation": "websocket",
        "AuthzServiceObservation": "service",
        "AuthzDecisionObservation": "decision",
        "AuthzMassAssignmentObservation": "mass-assignment",
        "AuthzAccessControlObservation": "access-control",
        "AuthzObservation": "observation",
    }
    return mapping.get(type(record).__name__, "observation")


# -- topology helpers ----------------------------------------------------------


def _topology_edges(
    batch: AuthorizationBatch,
    mission_id: str,
    correlation_id: str,
) -> list[GraphRelationship]:
    """Derive authorization edges into the attack-surface topology."""
    edges: list[GraphRelationship] = []
    for record in batch.records:
        if isinstance(record, AuthzAdminSurfaceObservation):
            origin_node = TopologyEntity(kind=EntityKind.WEB_ORIGIN, name=record.origin)
            surface_node = TopologyEntity(kind=EntityKind.ADMIN_SURFACE, name=record.url or record.origin)
            edges.append(
                GraphRelationship(
                    rel_type=RelationshipType.SERVES,
                    source=origin_node,
                    target=surface_node,
                    sources=["authorization"],
                    evidence={
                        "surface_kind": _v(record.surface_kind),
                        "confidence": record.confidence,
                    },
                    confidence=record.confidence,
                    mission_id=mission_id,
                    correlation_id=correlation_id,
                    in_scope=True,
                )
            )
        elif isinstance(record, AuthzResourceObservation):
            origin_node = TopologyEntity(kind=EntityKind.WEB_ORIGIN, name=record.origin)
            resource_node = TopologyEntity(kind=EntityKind.AUTHORIZATION_RESOURCE, name=record.name)
            edges.append(
                GraphRelationship(
                    rel_type=RelationshipType.SERVES,
                    source=origin_node,
                    target=resource_node,
                    sources=["authorization"],
                    evidence={
                        "resource_kind": _v(record.resource_kind),
                        "confidence": record.confidence,
                    },
                    confidence=record.confidence,
                    mission_id=mission_id,
                    correlation_id=correlation_id,
                    in_scope=True,
                )
            )
        elif isinstance(record, AuthzRoleObservation):
            origin_node = TopologyEntity(kind=EntityKind.WEB_ORIGIN, name=record.origin)
            role_node = TopologyEntity(kind=EntityKind.AUTHORIZATION_ROLE, name=record.name)
            edges.append(
                GraphRelationship(
                    rel_type=RelationshipType.USES,
                    source=origin_node,
                    target=role_node,
                    sources=["authorization"],
                    evidence={"confidence": record.confidence},
                    confidence=record.confidence,
                    mission_id=mission_id,
                    correlation_id=correlation_id,
                    in_scope=True,
                )
            )
        elif isinstance(record, AuthzPermissionObservation):
            origin_node = TopologyEntity(kind=EntityKind.WEB_ORIGIN, name=record.origin)
            permission_node = TopologyEntity(kind=EntityKind.AUTHORIZATION_PERMISSION, name=record.name)
            edges.append(
                GraphRelationship(
                    rel_type=RelationshipType.USES,
                    source=origin_node,
                    target=permission_node,
                    sources=["authorization"],
                    evidence={"confidence": record.confidence},
                    confidence=record.confidence,
                    mission_id=mission_id,
                    correlation_id=correlation_id,
                    in_scope=True,
                )
            )
        elif isinstance(record, AuthzPolicyObservation):
            origin_node = TopologyEntity(kind=EntityKind.WEB_ORIGIN, name=record.origin)
            policy_node = TopologyEntity(kind=EntityKind.AUTHORIZATION_POLICY, name=record.name or _v(record.model_kind))
            edges.append(
                GraphRelationship(
                    rel_type=RelationshipType.USES,
                    source=origin_node,
                    target=policy_node,
                    sources=["authorization"],
                    evidence={"model_kind": _v(record.model_kind), "confidence": record.confidence},
                    confidence=record.confidence,
                    mission_id=mission_id,
                    correlation_id=correlation_id,
                    in_scope=True,
                )
            )
        elif isinstance(record, AuthzTenantObservation):
            origin_node = TopologyEntity(kind=EntityKind.WEB_ORIGIN, name=record.origin)
            tenant_node = TopologyEntity(kind=EntityKind.AUTHORIZATION_TENANT, name=record.name)
            edges.append(
                GraphRelationship(
                    rel_type=RelationshipType.USES,
                    source=origin_node,
                    target=tenant_node,
                    sources=["authorization"],
                    evidence={"tenant_kind": _v(record.tenant_kind), "confidence": record.confidence},
                    confidence=record.confidence,
                    mission_id=mission_id,
                    correlation_id=correlation_id,
                    in_scope=True,
                )
            )
        elif isinstance(record, AuthzApiCorrelationObservation):
            if not record.endpoint:
                continue
            origin_node = TopologyEntity(kind=EntityKind.WEB_ORIGIN, name=record.origin)
            endpoint_node = TopologyEntity(kind=EntityKind.AUTHORIZATION_ENDPOINT, name=record.endpoint)
            edges.append(
                GraphRelationship(
                    rel_type=RelationshipType.SERVES,
                    source=origin_node,
                    target=endpoint_node,
                    sources=["authorization"],
                    evidence={
                        "method": record.method,
                        "authentication": record.authentication,
                        "confidence": record.confidence,
                    },
                    confidence=record.confidence,
                    mission_id=mission_id,
                    correlation_id=correlation_id,
                    in_scope=True,
                )
            )
    return edges


# -- small helpers -------------------------------------------------------------


def _v(value: Any) -> str:
    """Coerce an enum-or-string kind value to its string form."""
    if hasattr(value, "value"):
        return str(value.value)
    return str(value)


def _make_target(target: str) -> AuthorizationTarget:
    """Build an :class:`AuthorizationTarget` from a plain string."""
    stripped = target.strip()
    return AuthorizationTarget(value=stripped, target_type=infer_asset_type(stripped))


def _make_mode(mode: ReconMode | str) -> ReconMode:
    """Coerce a mode into a :class:`ReconMode`."""
    if isinstance(mode, ReconMode):
        return mode
    return ReconMode(str(mode).lower())


def _count_of(records: Sequence[Any], cls: type) -> int:
    return sum(1 for record in records if isinstance(record, cls))


class AuthorizationQueryService:
    """Answer authorization intelligence queries from persisted TIDB records."""

    def __init__(
        self,
        *,
        stores: TidbRepositoryFactory | None = None,
        cache: CachePort | None = None,
    ) -> None:
        self._stores = stores
        self._cache = cache

    def subjects(self, *, origin: str = "", mission_id: str = "") -> list[dict[str, Any]]:
        """Return the authorization subject inventory."""
        return [self._entity_dict(record) for record in self._list(TidbAuthorizationSubject, origin, mission_id)]

    def roles(self, *, origin: str = "", mission_id: str = "") -> list[dict[str, Any]]:
        """Return the role inventory."""
        return [self._entity_dict(record) for record in self._list(TidbAuthorizationRole, origin, mission_id)]

    def groups(self, *, origin: str = "", mission_id: str = "") -> list[dict[str, Any]]:
        """Return the group inventory."""
        return [self._entity_dict(record) for record in self._list(TidbAuthorizationGroup, origin, mission_id)]

    def permissions(self, *, origin: str = "", mission_id: str = "") -> list[dict[str, Any]]:
        """Return the permission inventory."""
        return [self._entity_dict(record) for record in self._list(TidbAuthorizationPermission, origin, mission_id)]

    def scopes(self, *, origin: str = "", mission_id: str = "") -> list[dict[str, Any]]:
        """Return the scope inventory."""
        return [self._entity_dict(record) for record in self._list(TidbAuthorizationScope, origin, mission_id)]

    def claims(self, *, origin: str = "", mission_id: str = "") -> list[dict[str, Any]]:
        """Return the claim inventory."""
        return [self._entity_dict(record) for record in self._list(TidbAuthorizationClaim, origin, mission_id)]

    def policies(self, *, origin: str = "", mission_id: str = "") -> list[dict[str, Any]]:
        """Return the policy inventory."""
        return [self._entity_dict(record) for record in self._list(TidbAuthorizationPolicy, origin, mission_id)]

    def resources(self, *, origin: str = "", mission_id: str = "") -> list[dict[str, Any]]:
        """Return the resource inventory."""
        return [self._entity_dict(record) for record in self._list(TidbAuthorizationResource, origin, mission_id)]

    def actions(self, *, origin: str = "", mission_id: str = "") -> list[dict[str, Any]]:
        """Return the action inventory."""
        return [self._entity_dict(record) for record in self._list(TidbAuthorizationAction, origin, mission_id)]

    def identifiers(self, *, origin: str = "", mission_id: str = "") -> list[dict[str, Any]]:
        """Return the resource-identifier metadata inventory."""
        return [self._entity_dict(record) for record in self._list(TidbAuthorizationIdentifier, origin, mission_id)]

    def ownership(self, *, origin: str = "", mission_id: str = "") -> list[dict[str, Any]]:
        """Return the ownership inventory."""
        return [self._entity_dict(record) for record in self._list(TidbAuthorizationOwnership, origin, mission_id)]

    def tenants(self, *, origin: str = "", mission_id: str = "") -> list[dict[str, Any]]:
        """Return the tenant-boundary inventory."""
        return [self._entity_dict(record) for record in self._list(TidbAuthorizationTenant, origin, mission_id)]

    def admin_surfaces(self, *, origin: str = "", mission_id: str = "") -> list[dict[str, Any]]:
        """Return the administrative-surface inventory."""
        return [self._entity_dict(record) for record in self._list(TidbAuthorizationAdminSurface, origin, mission_id)]

    def function_level(self, *, origin: str = "", mission_id: str = "") -> list[dict[str, Any]]:
        """Return the function-level access-control inventory."""
        return [self._entity_dict(record) for record in self._list(TidbAuthorizationFunctionLevel, origin, mission_id)]

    def object_level(self, *, origin: str = "", mission_id: str = "") -> list[dict[str, Any]]:
        """Return the object-level access-control inventory."""
        return [self._entity_dict(record) for record in self._list(TidbAuthorizationObjectLevel, origin, mission_id)]

    def field_level(self, *, origin: str = "", mission_id: str = "") -> list[dict[str, Any]]:
        """Return the field-level access-control inventory."""
        return [self._entity_dict(record) for record in self._list(TidbAuthorizationFieldLevel, origin, mission_id)]

    def frontend(self, *, origin: str = "", mission_id: str = "") -> list[dict[str, Any]]:
        """Return the frontend authorization-logic inventory."""
        return [self._entity_dict(record) for record in self._list(TidbAuthorizationFrontend, origin, mission_id)]

    def backend(self, *, origin: str = "", mission_id: str = "") -> list[dict[str, Any]]:
        """Return the backend authorization-logic inventory."""
        return [self._entity_dict(record) for record in self._list(TidbAuthorizationBackend, origin, mission_id)]

    def api_correlations(self, *, origin: str = "", mission_id: str = "") -> list[dict[str, Any]]:
        """Return the API authorization correlation inventory."""
        return [self._entity_dict(record) for record in self._list(TidbAuthorizationApiCorrelation, origin, mission_id)]

    def graphql(self, *, origin: str = "", mission_id: str = "") -> list[dict[str, Any]]:
        """Return the GraphQL authorization inventory."""
        return [self._entity_dict(record) for record in self._list(TidbAuthorizationGraphQL, origin, mission_id)]

    def websockets(self, *, origin: str = "", mission_id: str = "") -> list[dict[str, Any]]:
        """Return the WebSocket authorization inventory."""
        return [self._entity_dict(record) for record in self._list(TidbAuthorizationWebSocket, origin, mission_id)]

    def services(self, *, origin: str = "", mission_id: str = "") -> list[dict[str, Any]]:
        """Return the service-to-service authorization inventory."""
        return [self._entity_dict(record) for record in self._list(TidbAuthorizationService, origin, mission_id)]

    def decisions(self, *, origin: str = "", mission_id: str = "") -> list[dict[str, Any]]:
        """Return the decision-indicator inventory."""
        return [self._entity_dict(record) for record in self._list(TidbAuthorizationDecision, origin, mission_id)]

    def mass_assignment(self, *, origin: str = "", mission_id: str = "") -> list[dict[str, Any]]:
        """Return the mass-assignment structural inventory."""
        return [self._entity_dict(record) for record in self._list(TidbAuthorizationMassAssignment, origin, mission_id)]

    def access_control(self, *, origin: str = "", mission_id: str = "") -> list[dict[str, Any]]:
        """Return the access-control relationship inventory."""
        return [self._entity_dict(record) for record in self._list(TidbAuthorizationAccessControl, origin, mission_id)]

    def observations(self, *, origin: str = "", kind: str = "", mission_id: str = "") -> list[dict[str, Any]]:
        """Return the generic authorization observations."""
        records = self._list(TidbAuthorizationObservation, origin, mission_id)
        if kind:
            records = [record for record in records if record.kind == kind]
        return [self._entity_dict(record) for record in records]

    def changes(self, *, mission_id: str = "") -> list[dict[str, Any]]:
        """Return persisted authorization changes."""
        if self._stores is None:
            return []
        repo = self._stores.repository_for(TidbAuthorizationChange)
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
        """Return authorization intelligence run records."""
        if self._stores is None:
            return []
        repo = self._stores.repository_for(TidbAuthorizationRun)
        records = list(repo.list_by("target_key", target_key, limit=500)) if target_key else list(repo.stream())
        return [
            {
                "mission_id": record.mission_id,
                "target_key": record.target_key,
                "status": record.status,
                "mode": record.mode,
                "subjects": record.subjects,
                "roles": record.roles,
                "permissions": record.permissions,
                "resources": record.resources,
                "admin_surfaces": record.admin_surfaces,
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
            "subjects": len(self.subjects(mission_id=mission_id)),
            "roles": len(self.roles(mission_id=mission_id)),
            "groups": len(self.groups(mission_id=mission_id)),
            "permissions": len(self.permissions(mission_id=mission_id)),
            "scopes": len(self.scopes(mission_id=mission_id)),
            "claims": len(self.claims(mission_id=mission_id)),
            "policies": len(self.policies(mission_id=mission_id)),
            "resources": len(self.resources(mission_id=mission_id)),
            "actions": len(self.actions(mission_id=mission_id)),
            "identifiers": len(self.identifiers(mission_id=mission_id)),
            "ownership": len(self.ownership(mission_id=mission_id)),
            "tenants": len(self.tenants(mission_id=mission_id)),
            "admin_surfaces": len(self.admin_surfaces(mission_id=mission_id)),
            "function_level": len(self.function_level(mission_id=mission_id)),
            "object_level": len(self.object_level(mission_id=mission_id)),
            "field_level": len(self.field_level(mission_id=mission_id)),
            "frontend": len(self.frontend(mission_id=mission_id)),
            "backend": len(self.backend(mission_id=mission_id)),
            "api_correlations": len(self.api_correlations(mission_id=mission_id)),
            "graphql": len(self.graphql(mission_id=mission_id)),
            "websockets": len(self.websockets(mission_id=mission_id)),
            "services": len(self.services(mission_id=mission_id)),
            "decisions": len(self.decisions(mission_id=mission_id)),
            "mass_assignment": len(self.mass_assignment(mission_id=mission_id)),
            "access_control": len(self.access_control(mission_id=mission_id)),
            "observations": len(self.observations(mission_id=mission_id)),
            "changes": len(self.changes(mission_id=mission_id)),
        }

    # -- helpers ------------------------------------------------------------

    def _list(self, entity: type, origin: str, mission_id: str) -> list[Any]:
        if self._stores is None:
            return []
        repo = self._stores.repository_for(entity)
        records = list(repo.list_by("origin", origin, limit=1000)) if origin else list(repo.stream())
        if mission_id:
            records = [record for record in records if record.mission_id == mission_id]
        return [record for record in records if record.deleted_at is None]

    def _entity_dict(self, record: Any) -> dict[str, Any]:
        """Render a persisted authorization record as a JSON-safe dictionary."""
        result: dict[str, Any] = {}
        for name in (
            "url",
            "origin",
            "name",
            "kind",
            "subject_kind",
            "resource_kind",
            "identifier_kind",
            "ownership_kind",
            "tenant_kind",
            "model_kind",
            "surface_kind",
            "check_type",
            "mechanism",
            "function",
            "field",
            "action",
            "resource",
            "decision",
            "relationship_type",
            "value",
            "detail",
            "method",
            "endpoint",
        ):
            value = getattr(record, name, None)
            if value not in (None, ""):
                result[name] = value
        result["confidence"] = record.confidence
        result["indicators"] = list(record.indicators)
        result["source"] = record.source
        result["tool_id"] = record.tool_id
        result["mission_id"] = record.mission_id
        result["first_seen"] = record.first_seen
        result["last_seen"] = record.last_seen
        result["id"] = record.id
        return result
