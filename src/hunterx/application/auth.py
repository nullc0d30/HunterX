# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Authentication intelligence use-case services.

``AuthService`` is the orchestrator — the bridge between a mission and the
authentication intelligence tooling. Given a target and an input bundle of
already-acquired static material, it validates scope, builds an
:class:`AuthStrategy`, runs the in-process analyzer through the
:class:`ExecutionEngine`, folds in existing TIDB intelligence, classifies,
validates, correlates, confidence-scores, diffs history, persists everything to
the TIDB, updates the attack-surface topology and publishes ``auth.*`` events.

``AuthQueryService`` reads persisted authentication intelligence back from the
TIDB and answers the reporting queries (surfaces, endpoints, flows, identity
providers, OAuth/OIDC/SAML, cookies, token storage, CSRF, CORS, MFA/WebAuthn,
roles/scopes/permissions, tenants, changes and conflicts). Both services depend
on ports only.

Security boundary: intelligence only. No authentication, no credential or token
storage, no validation of discovered secrets.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from hunterx.domain.auth.classification import AuthClassifier
from hunterx.domain.auth.confidence import AuthConfidenceEngine, AuthConfidencePolicy
from hunterx.domain.auth.correlator import AuthCorrelator
from hunterx.domain.auth.history import AuthHistory
from hunterx.domain.auth.models import (
    AuthBatch,
    AuthChange,
    AuthCookieObservation,
    AuthEndpointObservation,
    AuthEvidence,
    AuthExecutionSummary,
    AuthFlowObservation,
    AuthObservation,
    AuthSchemeObservation,
    AuthSurfaceObservation,
    AuthTarget,
    CORSObservation,
    CSRFObservation,
    IdPObservation,
    JWTIndicatorObservation,
    MFAObservation,
    OAuthObservation,
    OIDCObservation,
    PermissionObservation,
    RoleObservation,
    SAMLIndicatorObservation,
    ScopeObservation,
    TenantObservation,
    TokenStorageObservation,
    WebAuthnObservation,
    infer_asset_type,
    observations_from_payload,
)
from hunterx.domain.auth.scope import AuthScopeEnforcer, AuthScopePolicy
from hunterx.domain.auth.strategy import AuthStrategy, AuthStrategyBuilder
from hunterx.domain.auth.validator import AuthValidator
from hunterx.domain.entities.tidb.auth_intelligence import (
    AuthChange as TidbAuthChange,
)
from hunterx.domain.entities.tidb.auth_intelligence import (
    AuthCookie as TidbAuthCookie,
)
from hunterx.domain.entities.tidb.auth_intelligence import (
    AuthEndpoint as TidbAuthEndpoint,
)
from hunterx.domain.entities.tidb.auth_intelligence import (
    AuthEvidence as TidbAuthEvidence,
)
from hunterx.domain.entities.tidb.auth_intelligence import (
    AuthFlow as TidbAuthFlow,
)
from hunterx.domain.entities.tidb.auth_intelligence import (
    AuthObservation as TidbAuthObservation,
)
from hunterx.domain.entities.tidb.auth_intelligence import AuthRun as TidbAuthRun
from hunterx.domain.entities.tidb.auth_intelligence import AuthScheme as TidbAuthScheme
from hunterx.domain.entities.tidb.auth_intelligence import AuthSurface as TidbAuthSurface
from hunterx.domain.entities.tidb.auth_intelligence import (
    CORSPolicy as TidbCORSPolicy,
)
from hunterx.domain.entities.tidb.auth_intelligence import (
    CSRFMechanism as TidbCSRFMechanism,
)
from hunterx.domain.entities.tidb.auth_intelligence import (
    IdentityProvider as TidbIdentityProvider,
)
from hunterx.domain.entities.tidb.auth_intelligence import (
    MFAMechanism as TidbMFAMechanism,
)
from hunterx.domain.entities.tidb.auth_intelligence import (
    OAuthConfig as TidbOAuthConfig,
)
from hunterx.domain.entities.tidb.auth_intelligence import (
    OIDCConfig as TidbOIDCConfig,
)
from hunterx.domain.entities.tidb.auth_intelligence import (
    PermissionIndicator as TidbPermissionIndicator,
)
from hunterx.domain.entities.tidb.auth_intelligence import (
    RoleIndicator as TidbRoleIndicator,
)
from hunterx.domain.entities.tidb.auth_intelligence import (
    SAMLConfig as TidbSAMLConfig,
)
from hunterx.domain.entities.tidb.auth_intelligence import (
    ScopeIndicator as TidbScopeIndicator,
)
from hunterx.domain.entities.tidb.auth_intelligence import (
    TenantIndicator as TidbTenantIndicator,
)
from hunterx.domain.entities.tidb.auth_intelligence import (
    TokenStorageIndicator as TidbTokenStorageIndicator,
)
from hunterx.domain.entities.tidb.auth_intelligence import (
    WebAuthnIndicator as TidbWebAuthnIndicator,
)
from hunterx.domain.entities.tidb.topology import TopologyRelationship as TidbTopologyRelationship
from hunterx.domain.events.types import (
    AuthChangeDetectedEvent,
    AuthConflictDetectedEvent,
    AuthCorrelationCompletedEvent,
    AuthCORSDiscoveredEvent,
    AuthCSRFDiscoveredEvent,
    AuthDiscoveryCompletedEvent,
    AuthDiscoveryFailedEvent,
    AuthDiscoveryStartedEvent,
    AuthEndpointDiscoveredEvent,
    AuthIdentityProviderDiscoveredEvent,
    AuthLoginSurfaceDiscoveredEvent,
    AuthMFADiscoveredEvent,
    AuthOAuthDiscoveredEvent,
    AuthOIDCDiscoveredEvent,
    AuthPermissionDiscoveredEvent,
    AuthPhaseStartedEvent,
    AuthRoleDiscoveredEvent,
    AuthSAMLDiscoveredEvent,
    AuthSessionCookieDiscoveredEvent,
    AuthTenantDiscoveredEvent,
    AuthTokenStorageDiscoveredEvent,
)
from hunterx.domain.execution import ExecutionContext
from hunterx.domain.ports.messaging import CachePort, EventBusPort
from hunterx.domain.ports.tidb_repositories import TidbRepositoryFactory
from hunterx.domain.recon.models import ReconMode
from hunterx.domain.topology.enums import EntityKind, RelationshipType
from hunterx.domain.topology.models import GraphRelationship, TopologyEntity
from hunterx.shared.ids import generate_id
from hunterx.shared.time import utcnow_iso
from hunterx.tools.auth.registry import AUTH_TOOL_IDS
from hunterx.tools.sdk.context import ExecutionContextBuilder
from hunterx.tools.sdk.engine import ExecutionEngine


class AuthService:
    """Run authentication intelligence missions through the Tool SDK.

    Usage::

        service = AuthService(engine=engine, stores=stores, event_bus=bus)
        batch = service.run(mission_id="m1", target="https://example.com/login",
                            parameters={"auth_input": {...}})
    """

    def __init__(
        self,
        *,
        engine: ExecutionEngine,
        stores: TidbRepositoryFactory | None = None,
        event_bus: EventBusPort | None = None,
        cache: CachePort | None = None,
        scope: AuthScopePolicy | None = None,
        strategy_builder: AuthStrategyBuilder | None = None,
        classifier: AuthClassifier | None = None,
        confidence: AuthConfidencePolicy | None = None,
        correlator: AuthCorrelator | None = None,
        validator: AuthValidator | None = None,
        history: AuthHistory | None = None,
    ) -> None:
        self._engine = engine
        self._stores = stores
        self._event_bus = event_bus
        self._cache = cache
        self._scope = scope or AuthScopePolicy()
        self._strategy_builder = strategy_builder or AuthStrategyBuilder()
        self._classifier = classifier or AuthClassifier()
        self._confidence = AuthConfidenceEngine(confidence or AuthConfidencePolicy())
        self._validator = validator or AuthValidator()
        self._correlator = correlator or AuthCorrelator(
            scope=self._scope,
            confidence=self._confidence.policy,
        )
        self._history = history or AuthHistory()
        self._scope_enforcer = AuthScopeEnforcer(self._scope)

    @property
    def engine(self) -> ExecutionEngine:
        """Return the execution engine used by this service."""
        return self._engine

    @property
    def correlator(self) -> AuthCorrelator:
        """Return the correlator used to merge authentication observations."""
        return self._correlator

    def run(
        self,
        *,
        mission_id: str = "",
        target: AuthTarget | str,
        mode: ReconMode | str = ReconMode.HYBRID,
        tools: Sequence[str] | None = None,
        parameters: Mapping[str, Any] | None = None,
        with_history: bool = False,
        historical: Sequence[Any] | None = None,
        min_confidence: float | None = None,
        max_concurrency: int = 4,
    ) -> AuthBatch:
        """Execute an authentication analysis run and return the correlated batch.

        Args:
            mission_id: owning mission id (empty for ad-hoc runs).
            target: the target to analyse (URL, hostname, domain or IP).
            mode: the execution posture (passive, active or hybrid). The
                analyzer is in-process and never authenticates, so passive
                postures still run it against supplied static material.
            tools: analysis tool ids to run; defaults to every registered auth
                tool. Requesting an unregistered tool raises :class:`ValueError`.
            parameters: per-tool parameters merged into each execution context
                (typically an ``auth_input`` bundle).
            with_history: compare current observations against ``historical``.
            historical: historical observations to diff against.
            min_confidence: minimum confidence for a record to be retained.
            max_concurrency: execution concurrency ceiling.

        Returns:
            The :class:`AuthBatch` with correlated records, evidence, conflicts,
            changes and execution summaries.

        Raises:
            ValueError: when the target is out of scope or a requested tool is
                not registered.

        """
        auth_target = target if isinstance(target, AuthTarget) else _make_target(target)
        decision = self._scope_enforcer.allows_target(auth_target)
        if not decision.allowed:
            raise ValueError(f"authentication target is out of scope: {decision.reason}")
        recon_mode = _make_mode(mode)
        selected = self._select_tools(tools)
        correlation_id = generate_id()
        parameters = dict(parameters or {})
        parameters["mode"] = recon_mode.value
        if auth_target.target_id:
            parameters["target_id"] = auth_target.target_id

        strategy = self._strategy_builder.build(
            auth_target.value,
            mode=recon_mode,
            target_kind=auth_target.target_type,
            tools=tuple(selected) if selected else (),
            include_history=with_history,
            min_confidence=min_confidence,
            max_concurrency=max_concurrency,
        )
        runnable = [tool_id for tool_id in strategy.tools if tool_id in selected]

        batch = AuthBatch(
            mission_id=mission_id,
            correlation_id=correlation_id,
            target=auth_target,
            mode=recon_mode,
        )
        self._publish(
            AuthDiscoveryStartedEvent(
                mission_id,
                correlation_id,
                auth_target.value,
                mode=recon_mode.value,
                tools=list(runnable),
            )
        )

        raw: list[Any] = []
        try:
            self._publish(AuthPhaseStartedEvent(correlation_id, "collection", mission_id=mission_id))
            for tool_id in runnable:
                context = self._build_context(
                    tool_id,
                    auth_target,
                    mission_id,
                    correlation_id,
                    parameters,
                    strategy,
                )
                outcome = self._engine.execute(context)
                result = outcome.result
                found = observations_from_payload(result.output.json) if result.status.is_success else []
                raw.extend(found)
                summary = AuthExecutionSummary(
                    tool_id=tool_id,
                    status=result.status.value,
                    observations=len(found),
                    endpoints=len([obs for obs in found if isinstance(obs, AuthEndpointObservation)]),
                    duration_ms=result.duration_ms,
                    error=result.error,
                )
                batch.add_execution(summary)

            if strategy.include_existing and self._stores is not None:
                self._publish(AuthPhaseStartedEvent(correlation_id, "existing-intelligence", mission_id=mission_id))
                raw.extend(self._collect_existing(auth_target, mission_id, correlation_id))

            self._publish(AuthPhaseStartedEvent(correlation_id, "classification", mission_id=mission_id))
            classified = self._classify(raw)

            self._publish(AuthPhaseStartedEvent(correlation_id, "validation", mission_id=mission_id))
            classified = self._validator.filter_valid(classified)

            self._publish(AuthPhaseStartedEvent(correlation_id, "correlation", mission_id=mission_id))
            correlation = self._correlator.correlate(classified, min_confidence=strategy.min_confidence)
            batch.records = list(correlation.records)
            for conflict in correlation.conflicts:
                batch.add_conflict(conflict)
                self._publish(
                    AuthConflictDetectedEvent(
                        correlation_id,
                        conflict.subject,
                        conflict.conflict_type,
                        selected=conflict.selected,
                        mission_id=mission_id,
                    )
                )
            self._publish(
                AuthCorrelationCompletedEvent(
                    mission_id,
                    correlation_id,
                    raw_observations=len(raw),
                    correlated_observations=len(batch.records),
                    conflicts=len(batch.conflicts),
                )
            )

            self._publish(AuthPhaseStartedEvent(correlation_id, "history", mission_id=mission_id))
            if strategy.include_history and historical is not None:
                comparison = self._history.compare(historical, batch.records)
                for change in comparison.changes:
                    batch.add_change(change)
                    self._publish_change(change, correlation_id, mission_id)

            self._publish_discoveries(batch, correlation_id, mission_id)

            if self._stores is not None:
                self._publish(AuthPhaseStartedEvent(correlation_id, "persistence", mission_id=mission_id))
                self._persist(batch, auth_target, mission_id, correlation_id)

            self._publish(AuthPhaseStartedEvent(correlation_id, "topology", mission_id=mission_id))
            if self._stores is not None:
                self._update_topology(batch, mission_id, correlation_id)

            self._publish(
                AuthDiscoveryCompletedEvent(
                    mission_id,
                    correlation_id,
                    target=auth_target.value,
                    surfaces=batch.surface_count(),
                    endpoints=batch.endpoint_count(),
                    identity_providers=_count_of(batch.records, IdPObservation),
                    changes=batch.change_count(),
                    conflicts=batch.conflict_count(),
                )
            )
        except Exception as exc:  # noqa: BLE001 - surfaced as a completion failure
            self._publish(
                AuthDiscoveryFailedEvent(
                    mission_id,
                    correlation_id,
                    auth_target.value,
                    str(exc),
                )
            )
            raise
        return batch

    # -- pipeline helpers ---------------------------------------------------

    def _select_tools(self, tools: Sequence[str] | None) -> list[str]:
        """Return the registered auth analysis tools to run for this mission."""
        registered = self._engine.adapter_for
        if tools is None:
            return [tool_id for tool_id in AUTH_TOOL_IDS if registered(tool_id) is not None]
        requested = list(tools)
        missing = [tool_id for tool_id in requested if registered(tool_id) is None]
        if missing:
            raise ValueError(f"requested authentication tools are not registered: {', '.join(missing)}")
        return requested

    def _build_context(
        self,
        tool_id: str,
        target: AuthTarget,
        mission_id: str,
        correlation_id: str,
        parameters: Mapping[str, Any],
        strategy: AuthStrategy,
    ) -> ExecutionContext:
        """Build an execution context for one auth analysis tool."""
        merged = dict(parameters)
        merged.setdefault("target", target.value)
        merged.setdefault("target_kind", target.target_type)
        return (
            ExecutionContextBuilder(tool_id=tool_id, target=target.value)
            .with_mission(mission_id)
            .with_target_type(target.target_type)
            .with_profile("authentication")
            .with_correlation_id(correlation_id)
            .with_permissions(("network",))
            .with_parameters(merged)
            .build()
        )

    def _classify(self, observations: Sequence[Any]) -> list[Any]:
        """Refine surface/endpoint classifications deterministically."""
        classified: list[Any] = []
        for observation in observations:
            if isinstance(observation, AuthSurfaceObservation):
                classified.append(self._classifier.classify_surface(observation))
            elif isinstance(observation, AuthEndpointObservation):
                classified.append(self._classifier.classify_endpoint(observation))
            else:
                classified.append(observation)
        return classified

    def _collect_existing(
        self,
        target: AuthTarget,
        mission_id: str,
        correlation_id: str,
    ) -> list[Any]:
        """Fold previously persisted authentication intelligence into the run."""
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
        """Read previously persisted auth records for ``target_key``."""
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
        batch: AuthBatch,
        target: AuthTarget,
        mission_id: str,
        correlation_id: str,
    ) -> int:
        """Persist correlated authentication intelligence into the TIDB."""
        stores = self._stores
        if stores is None:
            raise RuntimeError("cannot persist authentication intelligence without TIDB stores")
        count = 0
        for record in batch.records:
            entity = _to_entity(record, target, mission_id, correlation_id)
            if entity is None:
                continue
            stores.repository_for(type(entity)).save(entity)
            count += 1
            for evidence in getattr(record, "evidence", ()) or ():
                stores.repository_for(TidbAuthEvidence).save(
                    _to_evidence_entity(record, evidence, entity.id, mission_id, correlation_id)
                )
                count += 1
        for conflict in batch.conflicts:
            stores.repository_for(TidbAuthChange).save(
                TidbAuthChange(
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
            stores.repository_for(TidbAuthChange).save(
                _to_change_entity(change, mission_id, correlation_id)
            )
            count += 1
        run = TidbAuthRun(
            mission_id=mission_id,
            target_key=target.value,
            target_id=target.target_id or None,
            status="completed",
            mode=batch.mode.value,
            surfaces=batch.surface_count(),
            endpoints=batch.endpoint_count(),
            flows=_count_of(batch.records, AuthFlowObservation),
            identity_providers=_count_of(batch.records, IdPObservation),
            oauth_configs=_count_of(batch.records, OAuthObservation),
            oidc_configs=_count_of(batch.records, OIDCObservation),
            saml_configs=_count_of(batch.records, SAMLIndicatorObservation),
            schemes=_count_of(batch.records, AuthSchemeObservation),
            cookies=_count_of(batch.records, AuthCookieObservation),
            mfa=_count_of(batch.records, MFAObservation),
            changes=batch.change_count(),
            conflicts=batch.conflict_count(),
            started_at=batch.created_at,
            completed_at=utcnow_iso(),
            summary={
                "observations": batch.total_observations(),
                "records": batch.record_count(),
                "tools": [summary.tool_id for summary in batch.executions],
                "token_storage": _count_of(batch.records, TokenStorageObservation),
                "csrf": _count_of(batch.records, CSRFObservation),
                "cors": _count_of(batch.records, CORSObservation),
                "webauthn": _count_of(batch.records, WebAuthnObservation),
            },
            correlation_id=correlation_id,
        )
        stores.repository_for(TidbAuthRun).save(run)
        count += 1
        return count

    def _update_topology(self, batch: AuthBatch, mission_id: str, correlation_id: str) -> None:
        """Project authentication records into the attack-surface topology."""
        stores = self._stores
        if stores is None:
            return
        repo = stores.repository_for(TidbTopologyRelationship)
        for edge in _topology_edges(batch, mission_id, correlation_id):
            repo.save(edge.to_tidb())

    # -- events -------------------------------------------------------------

    def _publish_discoveries(self, batch: AuthBatch, correlation_id: str, mission_id: str) -> None:
        """Publish discovery events for the correlated set."""
        for record in batch.records:
            self._publish_record(record, correlation_id, mission_id)

    def _publish_record(self, record: Any, correlation_id: str, mission_id: str) -> None:
        origin = str(getattr(record, "origin", "") or "")
        if isinstance(record, AuthSurfaceObservation):
            self._publish(
                AuthLoginSurfaceDiscoveredEvent(
                    correlation_id,
                    origin,
                    _v(record.surface_kind),
                    url=record.url,
                    access_state=_v(record.access_state),
                    confidence=record.confidence,
                    mission_id=mission_id,
                )
            )
        elif isinstance(record, AuthEndpointObservation):
            self._publish(
                AuthEndpointDiscoveredEvent(
                    correlation_id,
                    origin,
                    _v(record.kind),
                    url=record.url,
                    method=record.method,
                    documented=record.documented,
                    confidence=record.confidence,
                    mission_id=mission_id,
                )
            )
        elif isinstance(record, IdPObservation):
            self._publish(
                AuthIdentityProviderDiscoveredEvent(
                    correlation_id,
                    origin,
                    record.name,
                    _v(record.provider_kind),
                    issuer=record.issuer,
                    confidence=record.confidence,
                    mission_id=mission_id,
                )
            )
        elif isinstance(record, OAuthObservation):
            self._publish(
                AuthOAuthDiscoveredEvent(
                    correlation_id,
                    origin,
                    token_endpoint=record.token_endpoint,
                    authorization_endpoint=record.authorization_endpoint,
                    issuer=record.issuer,
                    confidence=record.confidence,
                    mission_id=mission_id,
                )
            )
        elif isinstance(record, OIDCObservation):
            self._publish(
                AuthOIDCDiscoveredEvent(
                    correlation_id,
                    origin,
                    issuer=record.issuer,
                    discovery_url=record.discovery_url,
                    confidence=record.confidence,
                    mission_id=mission_id,
                )
            )
        elif isinstance(record, SAMLIndicatorObservation):
            self._publish(
                AuthSAMLDiscoveredEvent(
                    correlation_id,
                    origin,
                    entity_id=record.entity_id,
                    sso_url=record.sso_url,
                    confidence=record.confidence,
                    mission_id=mission_id,
                )
            )
        elif isinstance(record, AuthCookieObservation):
            if record.session:
                self._publish(
                    AuthSessionCookieDiscoveredEvent(
                        correlation_id,
                        origin,
                        record.name,
                        secure=record.secure,
                        httponly=record.httponly,
                        samesite=record.samesite,
                        confidence=record.confidence,
                        mission_id=mission_id,
                    )
                )
        elif isinstance(record, TokenStorageObservation):
            self._publish(
                AuthTokenStorageDiscoveredEvent(
                    correlation_id,
                    origin,
                    _v(record.storage_type),
                    token_category=record.token_category,
                    confidence=record.confidence,
                    mission_id=mission_id,
                )
            )
        elif isinstance(record, CSRFObservation):
            self._publish(
                AuthCSRFDiscoveredEvent(
                    correlation_id,
                    origin,
                    _v(record.kind),
                    cookie_name=record.cookie_name,
                    header_name=record.header_name,
                    confidence=record.confidence,
                    mission_id=mission_id,
                )
            )
        elif isinstance(record, CORSObservation):
            self._publish(
                AuthCORSDiscoveredEvent(
                    correlation_id,
                    origin,
                    allow_origin=record.allow_origin,
                    allow_credentials=record.allow_credentials,
                    confidence=record.confidence,
                    mission_id=mission_id,
                )
            )
        elif isinstance(record, MFAObservation):
            self._publish(
                AuthMFADiscoveredEvent(
                    correlation_id,
                    origin,
                    _v(record.kind),
                    endpoint=record.endpoint,
                    confidence=record.confidence,
                    mission_id=mission_id,
                )
            )
        elif isinstance(record, RoleObservation):
            self._publish(
                AuthRoleDiscoveredEvent(
                    correlation_id,
                    origin,
                    record.name,
                    confidence=record.confidence,
                    mission_id=mission_id,
                )
            )
        elif isinstance(record, PermissionObservation):
            self._publish(
                AuthPermissionDiscoveredEvent(
                    correlation_id,
                    origin,
                    record.name,
                    confidence=record.confidence,
                    mission_id=mission_id,
                )
            )
        elif isinstance(record, TenantObservation):
            self._publish(
                AuthTenantDiscoveredEvent(
                    correlation_id,
                    origin,
                    record.name,
                    tenant_type=record.tenant_type,
                    confidence=record.confidence,
                    mission_id=mission_id,
                )
            )

    def _publish_change(self, change: AuthChange, correlation_id: str, mission_id: str) -> None:
        """Publish the event for one historical change."""
        self._publish(
            AuthChangeDetectedEvent(
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
    TidbAuthSurface,
    TidbAuthEndpoint,
    TidbAuthFlow,
    TidbIdentityProvider,
    TidbOAuthConfig,
    TidbOIDCConfig,
    TidbSAMLConfig,
    TidbAuthScheme,
    TidbAuthCookie,
    TidbTokenStorageIndicator,
    TidbCSRFMechanism,
    TidbCORSPolicy,
    TidbMFAMechanism,
    TidbWebAuthnIndicator,
    TidbRoleIndicator,
    TidbScopeIndicator,
    TidbPermissionIndicator,
    TidbTenantIndicator,
    TidbAuthObservation,
)


def _to_entity(record: Any, target: AuthTarget, mission_id: str, correlation_id: str) -> Any | None:
    """Map a canonical observation onto its TIDB entity (None when unknown)."""
    target_key = target.value
    if isinstance(record, AuthSurfaceObservation):
        return TidbAuthSurface(
            url=record.url,
            origin=record.origin,
            surface_kind=_v(record.surface_kind),
            access_state=_v(record.access_state),
            indicators=list(record.indicators),
            confidence=record.confidence,
            source=record.source,
            tool_id=record.tool_id,
            target_key=target_key,
            correlation_id=correlation_id,
            mission_id=mission_id,
            first_seen=record.observed_at,
            last_seen=record.observed_at,
        )
    if isinstance(record, AuthEndpointObservation):
        return TidbAuthEndpoint(
            url=record.url,
            method=record.method,
            origin=record.origin,
            kind=_v(record.kind),
            documented=record.documented,
            indicators=list(record.indicators),
            confidence=record.confidence,
            source=record.source,
            tool_id=record.tool_id,
            target_key=target_key,
            correlation_id=correlation_id,
            mission_id=mission_id,
            first_seen=record.observed_at,
            last_seen=record.observed_at,
        )
    if isinstance(record, AuthFlowObservation):
        return TidbAuthFlow(
            name=record.name,
            flow_kind=_v(record.flow_kind),
            origin=record.origin,
            start_state=_v(record.start_state),
            end_state=_v(record.end_state),
            steps=[dict(step) for step in record.steps],
            indicators=list(record.indicators),
            confidence=record.confidence,
            source=record.source,
            tool_id=record.tool_id,
            target_key=target_key,
            correlation_id=correlation_id,
            mission_id=mission_id,
            first_seen=record.observed_at,
            last_seen=record.observed_at,
        )
    if isinstance(record, IdPObservation):
        return TidbIdentityProvider(
            name=record.name,
            provider_kind=_v(record.provider_kind),
            origin=record.origin,
            issuer=record.issuer,
            discovery_url=record.discovery_url,
            endpoints=[dict(item) for item in record.endpoints],
            indicators=list(record.indicators),
            confidence=record.confidence,
            source=record.source,
            tool_id=record.tool_id,
            target_key=target_key,
            correlation_id=correlation_id,
            mission_id=mission_id,
            first_seen=record.observed_at,
            last_seen=record.observed_at,
        )
    if isinstance(record, OAuthObservation):
        return TidbOAuthConfig(
            origin=record.origin,
            authorization_endpoint=record.authorization_endpoint,
            token_endpoint=record.token_endpoint,
            revocation_endpoint=record.revocation_endpoint,
            introspection_endpoint=record.introspection_endpoint,
            userinfo_endpoint=record.userinfo_endpoint,
            issuer=record.issuer,
            jwks_uri=record.jwks_uri,
            client_ids=list(record.client_ids),
            redirect_uris=list(record.redirect_uris),
            scopes=list(record.scopes),
            response_types=list(record.response_types),
            grant_types=list(record.grant_types),
            pkce=record.pkce,
            state_parameter=record.state_parameter,
            indicators=list(record.indicators),
            confidence=record.confidence,
            source=record.source,
            tool_id=record.tool_id,
            target_key=target_key,
            correlation_id=correlation_id,
            mission_id=mission_id,
            first_seen=record.observed_at,
            last_seen=record.observed_at,
        )
    if isinstance(record, OIDCObservation):
        return TidbOIDCConfig(
            origin=record.origin,
            issuer=record.issuer,
            discovery_url=record.discovery_url,
            authorization_endpoint=record.authorization_endpoint,
            token_endpoint=record.token_endpoint,
            userinfo_endpoint=record.userinfo_endpoint,
            jwks_uri=record.jwks_uri,
            scopes=list(record.scopes),
            claims=list(record.claims),
            response_types=list(record.response_types),
            subject_types=list(record.subject_types),
            id_token_signing_alg_values=list(record.id_token_signing_alg_values),
            code_challenge_methods_supported=list(record.code_challenge_methods_supported),
            indicators=list(record.indicators),
            confidence=record.confidence,
            source=record.source,
            tool_id=record.tool_id,
            target_key=target_key,
            correlation_id=correlation_id,
            mission_id=mission_id,
            first_seen=record.observed_at,
            last_seen=record.observed_at,
        )
    if isinstance(record, SAMLIndicatorObservation):
        return TidbSAMLConfig(
            origin=record.origin,
            entity_id=record.entity_id,
            sso_url=record.sso_url,
            acs_url=record.acs_url,
            metadata_url=record.metadata_url,
            idp_name=record.idp_name,
            sp_name=record.sp_name,
            relay_state=record.relay_state,
            indicators=list(record.indicators),
            confidence=record.confidence,
            source=record.source,
            tool_id=record.tool_id,
            target_key=target_key,
            correlation_id=correlation_id,
            mission_id=mission_id,
            first_seen=record.observed_at,
            last_seen=record.observed_at,
        )
    if isinstance(record, JWTIndicatorObservation):
        return TidbAuthObservation(
            origin=record.origin,
            kind="jwt",
            name="jwt-indicator",
            value=f"{record.transport}|{record.location}|{record.algorithm}",
            detail="JWT indicator metadata (values never stored)",
            indicators=list(record.indicators),
            confidence=record.confidence,
            source=record.source,
            tool_id=record.tool_id,
            target_key=target_key,
            correlation_id=correlation_id,
            mission_id=mission_id,
            first_seen=record.observed_at,
            last_seen=record.observed_at,
        )
    if isinstance(record, AuthSchemeObservation):
        return TidbAuthScheme(
            origin=record.origin,
            scheme_type=_v(record.scheme_type),
            name=record.name,
            token_location=record.token_location,
            header_name=record.header_name,
            documented=record.documented,
            indicators=list(record.indicators),
            confidence=record.confidence,
            source=record.source,
            tool_id=record.tool_id,
            target_key=target_key,
            correlation_id=correlation_id,
            mission_id=mission_id,
            first_seen=record.observed_at,
            last_seen=record.observed_at,
        )
    if isinstance(record, AuthCookieObservation):
        return TidbAuthCookie(
            name=record.name,
            origin=record.origin,
            domain=record.domain,
            path=record.path,
            secure=record.secure,
            httponly=record.httponly,
            partitioned=record.partitioned,
            samesite=record.samesite,
            max_age=record.max_age,
            expires=record.expires,
            priority=record.priority,
            prefix=record.prefix,
            session=record.session,
            persistent=record.persistent,
            indicators=list(record.indicators),
            confidence=record.confidence,
            source=record.source,
            tool_id=record.tool_id,
            target_key=target_key,
            correlation_id=correlation_id,
            mission_id=mission_id,
            first_seen=record.observed_at,
            last_seen=record.observed_at,
        )
    if isinstance(record, TokenStorageObservation):
        return TidbTokenStorageIndicator(
            origin=record.origin,
            storage_type=_v(record.storage_type),
            context=record.context,
            token_category=record.token_category,
            js_asset=record.js_asset,
            indicators=list(record.indicators),
            confidence=record.confidence,
            source=record.source,
            tool_id=record.tool_id,
            target_key=target_key,
            correlation_id=correlation_id,
            mission_id=mission_id,
            first_seen=record.observed_at,
            last_seen=record.observed_at,
        )
    if isinstance(record, CSRFObservation):
        return TidbCSRFMechanism(
            origin=record.origin,
            kind=_v(record.kind),
            endpoint=record.endpoint,
            cookie_name=record.cookie_name,
            header_name=record.header_name,
            parameter_name=record.parameter_name,
            samesite=record.samesite,
            indicators=list(record.indicators),
            confidence=record.confidence,
            source=record.source,
            tool_id=record.tool_id,
            target_key=target_key,
            correlation_id=correlation_id,
            mission_id=mission_id,
            first_seen=record.observed_at,
            last_seen=record.observed_at,
        )
    if isinstance(record, CORSObservation):
        return TidbCORSPolicy(
            origin=record.origin,
            allow_origin=record.allow_origin,
            allow_credentials=record.allow_credentials,
            allow_methods=list(record.allow_methods),
            allow_headers=list(record.allow_headers),
            expose_headers=list(record.expose_headers),
            preflight=record.preflight,
            indicators=list(record.indicators),
            confidence=record.confidence,
            source=record.source,
            tool_id=record.tool_id,
            target_key=target_key,
            correlation_id=correlation_id,
            mission_id=mission_id,
            first_seen=record.observed_at,
            last_seen=record.observed_at,
        )
    if isinstance(record, MFAObservation):
        return TidbMFAMechanism(
            origin=record.origin,
            kind=_v(record.kind),
            endpoint=record.endpoint,
            ui=record.ui,
            indicators=list(record.indicators),
            confidence=record.confidence,
            source=record.source,
            tool_id=record.tool_id,
            target_key=target_key,
            correlation_id=correlation_id,
            mission_id=mission_id,
            first_seen=record.observed_at,
            last_seen=record.observed_at,
        )
    if isinstance(record, WebAuthnObservation):
        return TidbWebAuthnIndicator(
            origin=record.origin,
            kind=record.kind,
            api=record.api,
            js_asset=record.js_asset,
            challenge_ref=record.challenge_ref,
            indicators=list(record.indicators),
            confidence=record.confidence,
            source=record.source,
            tool_id=record.tool_id,
            target_key=target_key,
            correlation_id=correlation_id,
            mission_id=mission_id,
            first_seen=record.observed_at,
            last_seen=record.observed_at,
        )
    if isinstance(record, RoleObservation):
        return TidbRoleIndicator(
            origin=record.origin,
            name=record.name,
            context=record.context,
            indicators=list(record.indicators),
            confidence=record.confidence,
            source=record.source,
            tool_id=record.tool_id,
            target_key=target_key,
            correlation_id=correlation_id,
            mission_id=mission_id,
            first_seen=record.observed_at,
            last_seen=record.observed_at,
        )
    if isinstance(record, ScopeObservation):
        return TidbScopeIndicator(
            origin=record.origin,
            name=record.name,
            description=record.description,
            indicators=list(record.indicators),
            confidence=record.confidence,
            source=record.source,
            tool_id=record.tool_id,
            target_key=target_key,
            correlation_id=correlation_id,
            mission_id=mission_id,
            first_seen=record.observed_at,
            last_seen=record.observed_at,
        )
    if isinstance(record, PermissionObservation):
        return TidbPermissionIndicator(
            origin=record.origin,
            name=record.name,
            action=record.action,
            resource=record.resource,
            indicators=list(record.indicators),
            confidence=record.confidence,
            source=record.source,
            tool_id=record.tool_id,
            target_key=target_key,
            correlation_id=correlation_id,
            mission_id=mission_id,
            first_seen=record.observed_at,
            last_seen=record.observed_at,
        )
    if isinstance(record, TenantObservation):
        return TidbTenantIndicator(
            origin=record.origin,
            name=record.name,
            tenant_type=record.tenant_type,
            location=record.location,
            indicators=list(record.indicators),
            confidence=record.confidence,
            source=record.source,
            tool_id=record.tool_id,
            target_key=target_key,
            correlation_id=correlation_id,
            mission_id=mission_id,
            first_seen=record.observed_at,
            last_seen=record.observed_at,
        )
    if isinstance(record, AuthObservation):
        return TidbAuthObservation(
            origin=record.origin,
            kind=_v(record.kind),
            name=record.name,
            value=record.value,
            detail=record.detail,
            indicators=list(record.indicators),
            confidence=record.confidence,
            source=record.source,
            tool_id=record.tool_id,
            target_key=target_key,
            correlation_id=correlation_id,
            mission_id=mission_id,
            first_seen=record.observed_at,
            last_seen=record.observed_at,
        )
    return None


def _to_evidence_entity(
    record: Any,
    evidence: AuthEvidence,
    subject_id: str,
    mission_id: str,
    correlation_id: str,
) -> TidbAuthEvidence:
    """Map an evidence fragment onto the TIDB evidence entity."""
    return TidbAuthEvidence(
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


def _to_change_entity(change: AuthChange, mission_id: str, correlation_id: str) -> TidbAuthChange:
    """Map a historical change onto the TIDB change entity."""
    return TidbAuthChange(
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
    """Convert a persisted TIDB auth record back into a canonical observation."""
    observed_at = record.last_seen or record.created_at
    base = {
        "source": record.source or "tidb",
        "tool_id": record.tool_id or "tidb",
        "target_key": target_key,
        "correlation_id": correlation_id,
        "mission_id": mission_id,
        "observed_at": observed_at,
    }
    if isinstance(record, TidbAuthSurface):
        return AuthSurfaceObservation(
            url=record.url,
            origin=record.origin,
            surface_kind=record.surface_kind,
            access_state=record.access_state,
            indicators=tuple(record.indicators),
            confidence=record.confidence,
            evidence=(_tidb_evidence("surface", record),),
            **base,
        )
    if isinstance(record, TidbAuthEndpoint):
        return AuthEndpointObservation(
            url=record.url,
            method=record.method,
            origin=record.origin,
            kind=record.kind,
            documented=record.documented,
            indicators=tuple(record.indicators),
            confidence=record.confidence,
            evidence=(_tidb_evidence("endpoint", record),),
            **base,
        )
    if isinstance(record, TidbAuthFlow):
        return AuthFlowObservation(
            name=record.name,
            flow_kind=record.flow_kind,
            origin=record.origin,
            start_state=record.start_state,
            end_state=record.end_state,
            steps=tuple(dict(item) for item in record.steps),
            indicators=tuple(record.indicators),
            confidence=record.confidence,
            evidence=(_tidb_evidence("flow", record),),
            **base,
        )
    if isinstance(record, TidbIdentityProvider):
        return IdPObservation(
            name=record.name,
            provider_kind=record.provider_kind,
            origin=record.origin,
            issuer=record.issuer,
            discovery_url=record.discovery_url,
            endpoints=tuple(dict(item) for item in record.endpoints),
            indicators=tuple(record.indicators),
            confidence=record.confidence,
            evidence=(_tidb_evidence("identity-provider", record),),
            **base,
        )
    if isinstance(record, TidbOAuthConfig):
        return OAuthObservation(
            origin=record.origin,
            authorization_endpoint=record.authorization_endpoint,
            token_endpoint=record.token_endpoint,
            revocation_endpoint=record.revocation_endpoint,
            introspection_endpoint=record.introspection_endpoint,
            userinfo_endpoint=record.userinfo_endpoint,
            issuer=record.issuer,
            jwks_uri=record.jwks_uri,
            client_ids=tuple(record.client_ids),
            redirect_uris=tuple(record.redirect_uris),
            scopes=tuple(record.scopes),
            response_types=tuple(record.response_types),
            grant_types=tuple(record.grant_types),
            pkce=record.pkce,
            state_parameter=record.state_parameter,
            indicators=tuple(record.indicators),
            confidence=record.confidence,
            evidence=(_tidb_evidence("oauth", record),),
            **base,
        )
    if isinstance(record, TidbOIDCConfig):
        return OIDCObservation(
            origin=record.origin,
            issuer=record.issuer,
            discovery_url=record.discovery_url,
            authorization_endpoint=record.authorization_endpoint,
            token_endpoint=record.token_endpoint,
            userinfo_endpoint=record.userinfo_endpoint,
            jwks_uri=record.jwks_uri,
            scopes=tuple(record.scopes),
            claims=tuple(record.claims),
            response_types=tuple(record.response_types),
            subject_types=tuple(record.subject_types),
            id_token_signing_alg_values=tuple(record.id_token_signing_alg_values),
            code_challenge_methods_supported=tuple(record.code_challenge_methods_supported),
            indicators=tuple(record.indicators),
            confidence=record.confidence,
            evidence=(_tidb_evidence("oidc", record),),
            **base,
        )
    if isinstance(record, TidbSAMLConfig):
        return SAMLIndicatorObservation(
            origin=record.origin,
            entity_id=record.entity_id,
            sso_url=record.sso_url,
            acs_url=record.acs_url,
            metadata_url=record.metadata_url,
            idp_name=record.idp_name,
            sp_name=record.sp_name,
            relay_state=record.relay_state,
            indicators=tuple(record.indicators),
            confidence=record.confidence,
            evidence=(_tidb_evidence("saml", record),),
            **base,
        )
    if isinstance(record, TidbAuthScheme):
        return AuthSchemeObservation(
            origin=record.origin,
            scheme_type=record.scheme_type,
            name=record.name,
            token_location=record.token_location,
            header_name=record.header_name,
            documented=record.documented,
            indicators=tuple(record.indicators),
            confidence=record.confidence,
            evidence=(_tidb_evidence("scheme", record),),
            **base,
        )
    if isinstance(record, TidbAuthCookie):
        return AuthCookieObservation(
            name=record.name,
            origin=record.origin,
            domain=record.domain,
            path=record.path,
            secure=record.secure,
            httponly=record.httponly,
            partitioned=record.partitioned,
            samesite=record.samesite,
            max_age=record.max_age,
            expires=record.expires,
            priority=record.priority,
            prefix=record.prefix,
            session=record.session,
            persistent=record.persistent,
            indicators=tuple(record.indicators),
            confidence=record.confidence,
            evidence=(_tidb_evidence("cookie", record),),
            **base,
        )
    if isinstance(record, TidbTokenStorageIndicator):
        return TokenStorageObservation(
            origin=record.origin,
            storage_type=record.storage_type,
            context=record.context,
            token_category=record.token_category,
            js_asset=record.js_asset,
            indicators=tuple(record.indicators),
            confidence=record.confidence,
            evidence=(_tidb_evidence("token-storage", record),),
            **base,
        )
    if isinstance(record, TidbCSRFMechanism):
        return CSRFObservation(
            origin=record.origin,
            kind=record.kind,
            endpoint=record.endpoint,
            cookie_name=record.cookie_name,
            header_name=record.header_name,
            parameter_name=record.parameter_name,
            samesite=record.samesite,
            indicators=tuple(record.indicators),
            confidence=record.confidence,
            evidence=(_tidb_evidence("csrf", record),),
            **base,
        )
    if isinstance(record, TidbCORSPolicy):
        return CORSObservation(
            origin=record.origin,
            allow_origin=record.allow_origin,
            allow_credentials=record.allow_credentials,
            allow_methods=tuple(record.allow_methods),
            allow_headers=tuple(record.allow_headers),
            expose_headers=tuple(record.expose_headers),
            preflight=record.preflight,
            indicators=tuple(record.indicators),
            confidence=record.confidence,
            evidence=(_tidb_evidence("cors", record),),
            **base,
        )
    if isinstance(record, TidbMFAMechanism):
        return MFAObservation(
            origin=record.origin,
            kind=record.kind,
            endpoint=record.endpoint,
            ui=record.ui,
            indicators=tuple(record.indicators),
            confidence=record.confidence,
            evidence=(_tidb_evidence("mfa", record),),
            **base,
        )
    if isinstance(record, TidbWebAuthnIndicator):
        return WebAuthnObservation(
            origin=record.origin,
            kind=record.kind,
            api=record.api,
            js_asset=record.js_asset,
            challenge_ref=record.challenge_ref,
            indicators=tuple(record.indicators),
            confidence=record.confidence,
            evidence=(_tidb_evidence("webauthn", record),),
            **base,
        )
    if isinstance(record, TidbRoleIndicator):
        return RoleObservation(
            origin=record.origin,
            name=record.name,
            context=record.context,
            indicators=tuple(record.indicators),
            confidence=record.confidence,
            evidence=(_tidb_evidence("role", record),),
            **base,
        )
    if isinstance(record, TidbScopeIndicator):
        return ScopeObservation(
            origin=record.origin,
            name=record.name,
            description=record.description,
            indicators=tuple(record.indicators),
            confidence=record.confidence,
            evidence=(_tidb_evidence("scope", record),),
            **base,
        )
    if isinstance(record, TidbPermissionIndicator):
        return PermissionObservation(
            origin=record.origin,
            name=record.name,
            action=record.action,
            resource=record.resource,
            indicators=tuple(record.indicators),
            confidence=record.confidence,
            evidence=(_tidb_evidence("permission", record),),
            **base,
        )
    if isinstance(record, TidbTenantIndicator):
        return TenantObservation(
            origin=record.origin,
            name=record.name,
            tenant_type=record.tenant_type,
            location=record.location,
            indicators=tuple(record.indicators),
            confidence=record.confidence,
            evidence=(_tidb_evidence("tenant", record),),
            **base,
        )
    if isinstance(record, TidbAuthObservation):
        return AuthObservation(
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


def _tidb_evidence(subject_type: str, record: Any) -> AuthEvidence:
    return AuthEvidence(
        evidence_type="tidb-intelligence",
        value=record.origin or getattr(record, "name", "") or subject_type,
        source="tidb",
        strength="moderate",
        tool_id="tidb",
        detail=f"previously persisted {subject_type} intelligence",
    )


def _subject_type_of(record: Any) -> str:
    mapping = {
        "AuthSurfaceObservation": "surface",
        "AuthEndpointObservation": "endpoint",
        "AuthFlowObservation": "flow",
        "IdPObservation": "identity-provider",
        "OAuthObservation": "oauth",
        "OIDCObservation": "oidc",
        "SAMLIndicatorObservation": "saml",
        "JWTIndicatorObservation": "jwt",
        "AuthSchemeObservation": "scheme",
        "AuthCookieObservation": "cookie",
        "TokenStorageObservation": "token-storage",
        "CSRFObservation": "csrf",
        "CORSObservation": "cors",
        "MFAObservation": "mfa",
        "WebAuthnObservation": "webauthn",
        "RoleObservation": "role",
        "ScopeObservation": "scope",
        "PermissionObservation": "permission",
        "TenantObservation": "tenant",
        "AuthObservation": "observation",
    }
    return mapping.get(type(record).__name__, "observation")


# -- topology helpers ----------------------------------------------------------


def _topology_edges(batch: AuthBatch, mission_id: str, correlation_id: str) -> list[GraphRelationship]:
    """Derive authentication edges into the attack-surface topology."""
    edges: list[GraphRelationship] = []
    surface_by_url: dict[str, TopologyEntity] = {}
    for record in batch.records:
        if not isinstance(record, AuthSurfaceObservation):
            continue
        origin_node = TopologyEntity(kind=EntityKind.WEB_ORIGIN, name=record.origin)
        surface_node = TopologyEntity(kind=EntityKind.AUTH_SURFACE, name=record.url or record.origin)
        edges.append(
            GraphRelationship(
                rel_type=RelationshipType.SERVES,
                source=origin_node,
                target=surface_node,
                sources=["auth"],
                evidence={
                    "surface_kind": _v(record.surface_kind),
                    "access_state": _v(record.access_state),
                    "confidence": record.confidence,
                },
                confidence=record.confidence,
                mission_id=mission_id,
                correlation_id=correlation_id,
                in_scope=True,
            )
        )
        surface_by_url[record.url or record.origin] = surface_node
    for record in batch.records:
        if not isinstance(record, AuthEndpointObservation):
            continue
        origin_node = TopologyEntity(kind=EntityKind.WEB_ORIGIN, name=record.origin)
        endpoint_node = TopologyEntity(kind=EntityKind.AUTH_ENDPOINT, name=record.url)
        edges.append(
            GraphRelationship(
                rel_type=RelationshipType.SERVES,
                source=origin_node,
                target=endpoint_node,
                sources=["auth"],
                evidence={
                    "kind": _v(record.kind),
                    "method": record.method,
                    "confidence": record.confidence,
                },
                confidence=record.confidence,
                mission_id=mission_id,
                correlation_id=correlation_id,
                in_scope=True,
            )
        )
    for record in batch.records:
        if not isinstance(record, IdPObservation):
            continue
        origin_node = TopologyEntity(kind=EntityKind.WEB_ORIGIN, name=record.origin)
        idp_node = TopologyEntity(kind=EntityKind.IDENTITY_PROVIDER, name=record.name)
        edges.append(
            GraphRelationship(
                rel_type=RelationshipType.USES,
                source=origin_node,
                target=idp_node,
                sources=["auth"],
                evidence={"issuer": record.issuer, "confidence": record.confidence},
                confidence=record.confidence,
                mission_id=mission_id,
                correlation_id=correlation_id,
                in_scope=True,
            )
        )
    for record in batch.records:
        if not isinstance(record, AuthSchemeObservation):
            continue
        origin_node = TopologyEntity(kind=EntityKind.WEB_ORIGIN, name=record.origin)
        scheme_node = TopologyEntity(kind=EntityKind.AUTHENTICATION_SCHEME, name=_v(record.scheme_type))
        edges.append(
            GraphRelationship(
                rel_type=RelationshipType.USES,
                source=origin_node,
                target=scheme_node,
                sources=["auth"],
                evidence={"header": record.header_name, "confidence": record.confidence},
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


def _make_target(target: str) -> AuthTarget:
    """Build an :class:`AuthTarget` from a plain string."""
    stripped = target.strip()
    return AuthTarget(value=stripped, target_type=infer_asset_type(stripped))


def _make_mode(mode: ReconMode | str) -> ReconMode:
    """Coerce a mode into a :class:`ReconMode`."""
    if isinstance(mode, ReconMode):
        return mode
    return ReconMode(str(mode).lower())


def _count_of(records: Sequence[Any], cls: type) -> int:
    return sum(1 for record in records if isinstance(record, cls))


class AuthQueryService:
    """Answer authentication intelligence queries from persisted TIDB records."""

    def __init__(
        self,
        *,
        stores: TidbRepositoryFactory | None = None,
        cache: CachePort | None = None,
    ) -> None:
        self._stores = stores
        self._cache = cache

    def surfaces(self, *, origin: str = "", mission_id: str = "") -> list[dict[str, Any]]:
        """Return the authentication surface inventory."""
        return [self._entity_dict(record) for record in self._list(TidbAuthSurface, origin, mission_id)]

    def endpoints(self, *, origin: str = "", kind: str = "", mission_id: str = "") -> list[dict[str, Any]]:
        """Return the authentication endpoint inventory."""
        records = self._list(TidbAuthEndpoint, origin, mission_id)
        if kind:
            records = [record for record in records if record.kind == kind]
        return [self._entity_dict(record) for record in records]

    def flows(self, *, origin: str = "", mission_id: str = "") -> list[dict[str, Any]]:
        """Return the modeled authentication flows."""
        return [self._entity_dict(record) for record in self._list(TidbAuthFlow, origin, mission_id)]

    def identity_providers(self, *, origin: str = "", mission_id: str = "") -> list[dict[str, Any]]:
        """Return the identity provider inventory."""
        return [self._entity_dict(record) for record in self._list(TidbIdentityProvider, origin, mission_id)]

    def oauth(self, *, origin: str = "", mission_id: str = "") -> list[dict[str, Any]]:
        """Return the OAuth configuration inventory."""
        return [self._entity_dict(record) for record in self._list(TidbOAuthConfig, origin, mission_id)]

    def oidc(self, *, origin: str = "", mission_id: str = "") -> list[dict[str, Any]]:
        """Return the OIDC configuration inventory."""
        return [self._entity_dict(record) for record in self._list(TidbOIDCConfig, origin, mission_id)]

    def saml(self, *, origin: str = "", mission_id: str = "") -> list[dict[str, Any]]:
        """Return the SAML configuration inventory."""
        return [self._entity_dict(record) for record in self._list(TidbSAMLConfig, origin, mission_id)]

    def cookies(self, *, origin: str = "", mission_id: str = "") -> list[dict[str, Any]]:
        """Return the cookie security metadata inventory."""
        return [self._entity_dict(record) for record in self._list(TidbAuthCookie, origin, mission_id)]

    def token_storage(self, *, origin: str = "", mission_id: str = "") -> list[dict[str, Any]]:
        """Return the token-storage indicator inventory."""
        return [self._entity_dict(record) for record in self._list(TidbTokenStorageIndicator, origin, mission_id)]

    def csrf(self, *, origin: str = "", mission_id: str = "") -> list[dict[str, Any]]:
        """Return the CSRF mechanism inventory."""
        return [self._entity_dict(record) for record in self._list(TidbCSRFMechanism, origin, mission_id)]

    def cors(self, *, origin: str = "", mission_id: str = "") -> list[dict[str, Any]]:
        """Return the CORS configuration inventory."""
        return [self._entity_dict(record) for record in self._list(TidbCORSPolicy, origin, mission_id)]

    def mfa(self, *, origin: str = "", mission_id: str = "") -> list[dict[str, Any]]:
        """Return the MFA mechanism inventory."""
        return [self._entity_dict(record) for record in self._list(TidbMFAMechanism, origin, mission_id)]

    def webauthn(self, *, origin: str = "", mission_id: str = "") -> list[dict[str, Any]]:
        """Return the WebAuthn/passkey indicator inventory."""
        return [self._entity_dict(record) for record in self._list(TidbWebAuthnIndicator, origin, mission_id)]

    def roles(self, *, origin: str = "", mission_id: str = "") -> list[dict[str, Any]]:
        """Return the role indicator inventory."""
        return [self._entity_dict(record) for record in self._list(TidbRoleIndicator, origin, mission_id)]

    def scopes(self, *, origin: str = "", mission_id: str = "") -> list[dict[str, Any]]:
        """Return the scope indicator inventory."""
        return [self._entity_dict(record) for record in self._list(TidbScopeIndicator, origin, mission_id)]

    def permissions(self, *, origin: str = "", mission_id: str = "") -> list[dict[str, Any]]:
        """Return the permission indicator inventory."""
        return [self._entity_dict(record) for record in self._list(TidbPermissionIndicator, origin, mission_id)]

    def tenants(self, *, origin: str = "", mission_id: str = "") -> list[dict[str, Any]]:
        """Return the tenant indicator inventory."""
        return [self._entity_dict(record) for record in self._list(TidbTenantIndicator, origin, mission_id)]

    def observations(self, *, origin: str = "", kind: str = "", mission_id: str = "") -> list[dict[str, Any]]:
        """Return the generic authentication observations."""
        records = self._list(TidbAuthObservation, origin, mission_id)
        if kind:
            records = [record for record in records if record.kind == kind]
        return [self._entity_dict(record) for record in records]

    def schemes(self, *, origin: str = "", mission_id: str = "") -> list[dict[str, Any]]:
        """Return the authentication scheme inventory."""
        return [self._entity_dict(record) for record in self._list(TidbAuthScheme, origin, mission_id)]

    def changes(self, *, mission_id: str = "") -> list[dict[str, Any]]:
        """Return persisted authentication changes."""
        if self._stores is None:
            return []
        repo = self._stores.repository_for(TidbAuthChange)
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
        """Return authentication intelligence run records."""
        if self._stores is None:
            return []
        repo = self._stores.repository_for(TidbAuthRun)
        records = list(repo.list_by("target_key", target_key, limit=500)) if target_key else list(repo.stream())
        return [
            {
                "mission_id": record.mission_id,
                "target_key": record.target_key,
                "status": record.status,
                "mode": record.mode,
                "surfaces": record.surfaces,
                "endpoints": record.endpoints,
                "identity_providers": record.identity_providers,
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
            "surfaces": len(self.surfaces(mission_id=mission_id)),
            "endpoints": len(self.endpoints(mission_id=mission_id)),
            "flows": len(self.flows(mission_id=mission_id)),
            "identity_providers": len(self.identity_providers(mission_id=mission_id)),
            "oauth_configs": len(self.oauth(mission_id=mission_id)),
            "oidc_configs": len(self.oidc(mission_id=mission_id)),
            "saml_configs": len(self.saml(mission_id=mission_id)),
            "schemes": len(self.schemes(mission_id=mission_id)),
            "cookies": len(self.cookies(mission_id=mission_id)),
            "token_storage": len(self.token_storage(mission_id=mission_id)),
            "csrf": len(self.csrf(mission_id=mission_id)),
            "cors": len(self.cors(mission_id=mission_id)),
            "mfa": len(self.mfa(mission_id=mission_id)),
            "webauthn": len(self.webauthn(mission_id=mission_id)),
            "roles": len(self.roles(mission_id=mission_id)),
            "scopes": len(self.scopes(mission_id=mission_id)),
            "permissions": len(self.permissions(mission_id=mission_id)),
            "tenants": len(self.tenants(mission_id=mission_id)),
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
        """Render a persisted auth record as a JSON-safe dictionary."""
        result: dict[str, Any] = {}
        for name in (
            "url",
            "origin",
            "name",
            "kind",
            "surface_kind",
            "access_state",
            "scheme_type",
            "header_name",
            "token_location",
            "samesite",
            "secure",
            "httponly",
            "prefix",
            "session",
            "persistent",
            "storage_type",
            "token_category",
            "issuer",
            "discovery_url",
            "entity_id",
            "allow_origin",
            "allow_credentials",
            "tenant_type",
            "provider_kind",
            "flow_kind",
            "value",
            "detail",
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
