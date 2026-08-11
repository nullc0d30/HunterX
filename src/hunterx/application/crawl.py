# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Web crawling & web attack-surface discovery use-case services.

``CrawlService`` is the orchestrator — the bridge between a mission and the web
crawling tooling. Given a target and a posture, it validates scope, builds a
:class:`CrawlStrategy`, selects the registered crawling tools, runs each through
the :class:`ExecutionEngine` pipeline, normalizes, correlates and confidence-
scores the observations, diffs history, persists everything to the TIDB, folds
discoveries into the attack-surface topology and publishes ``crawl.*`` events.

``CrawlQueryService`` reads persisted web intelligence back from the TIDB and
answers the reporting queries (origins, URLs, endpoints, redirects, auth
boundaries and execution history). Both services depend on ports only.
"""

from __future__ import annotations

import contextlib
from collections.abc import Mapping, Sequence
from typing import Any

from hunterx.domain.entities.tidb.topology import TopologyRelationship as TidbTopologyRelationship
from hunterx.domain.entities.tidb.web_crawl import (
    AuthenticationBoundary as TidbAuthenticationBoundary,
)
from hunterx.domain.entities.tidb.web_crawl import (
    CrawlEvidence as TidbCrawlEvidence,
)
from hunterx.domain.entities.tidb.web_crawl import (
    CrawlExecution as TidbCrawlExecution,
)
from hunterx.domain.entities.tidb.web_crawl import (
    URLObservation as TidbURLObservation,
)
from hunterx.domain.entities.tidb.web_crawl import (
    WebAPIEndpoint as TidbWebAPIEndpoint,
)
from hunterx.domain.entities.tidb.web_crawl import (
    WebGraphQLEndpoint as TidbWebGraphQLEndpoint,
)
from hunterx.domain.entities.tidb.web_crawl import (
    WebOrigin as TidbWebOrigin,
)
from hunterx.domain.entities.tidb.web_crawl import (
    WebRedirect as TidbWebRedirect,
)
from hunterx.domain.entities.tidb.web_crawl import (
    WebSocketEndpoint as TidbWebSocketEndpoint,
)
from hunterx.domain.events.types import (
    CrawlAuthBoundaryDiscoveredEvent,
    CrawlChangeDetectedEvent,
    CrawlCompletedEvent,
    CrawlCorrelationCompletedEvent,
    CrawlEndpointDiscoveredEvent,
    CrawlFailedEvent,
    CrawlGraphQLDiscoveredEvent,
    CrawlPhaseStartedEvent,
    CrawlRedirectDiscoveredEvent,
    CrawlStartedEvent,
    CrawlUrlDiscoveredEvent,
    CrawlWebSocketDiscoveredEvent,
)
from hunterx.domain.execution import ExecutionContext
from hunterx.domain.ports.messaging import CachePort, EventBusPort
from hunterx.domain.ports.tidb_repositories import TidbRepositoryFactory
from hunterx.domain.topology.enums import EntityKind, RelationshipType
from hunterx.domain.topology.models import GraphRelationship, TopologyEntity
from hunterx.domain.topology.normalizer import TopologyNormalizer
from hunterx.domain.web.confidence import WebConfidenceEngine
from hunterx.domain.web.correlator import WebCorrelator
from hunterx.domain.web.history import WebCrawlHistory
from hunterx.domain.web.models import (
    APIEndpoint,
    AuthenticationBoundary,
    CrawlEvidence,
    CrawlExecutionSummary,
    CrawlPayload,
    CrawlTarget,
    GraphQLEndpoint,
    Redirect,
    URLObservation,
    WebCrawlBatch,
    WebCrawlMode,
    WebSocketEndpoint,
    observations_from_payload,
)
from hunterx.domain.web.scope import WebScopeEnforcer, WebScopePolicy
from hunterx.domain.web.strategy import WEB_TOOL_IDS, CrawlStrategy, CrawlStrategyBuilder
from hunterx.domain.web.urls import URLNormalizer
from hunterx.shared.ids import generate_id
from hunterx.shared.time import utcnow_iso
from hunterx.tools.sdk.context import ExecutionContextBuilder
from hunterx.tools.sdk.engine import ExecutionEngine

#: Artifact type tags used by the confidence engine per observation class.
_ARTIFACT_TYPES = {
    "url": "url",
    "redirect": "redirect",
    "api_endpoint": "api_endpoint",
    "websocket": "websocket",
    "graphql": "graphql",
    "auth_boundary": "auth_boundary",
}


class CrawlService:
    """Run web crawling missions through the Tool SDK.

    Usage::

        service = CrawlService(engine=engine, stores=stores, event_bus=bus)
        batch = service.run(mission_id="m1", target="https://example.com", mode="active")
    """

    def __init__(
        self,
        *,
        engine: ExecutionEngine,
        stores: TidbRepositoryFactory | None = None,
        event_bus: EventBusPort | None = None,
        cache: CachePort | None = None,
        scope: WebScopePolicy | None = None,
        strategy_builder: CrawlStrategyBuilder | None = None,
        confidence: WebConfidenceEngine | None = None,
        correlator: WebCorrelator | None = None,
        history: WebCrawlHistory | None = None,
    ) -> None:
        self._engine = engine
        self._stores = stores
        self._event_bus = event_bus
        self._cache = cache
        self._scope = scope or WebScopePolicy()
        self._confidence = confidence or WebConfidenceEngine()
        self._strategy_builder = strategy_builder or CrawlStrategyBuilder()
        self._correlator = correlator or WebCorrelator()
        self._history = history or WebCrawlHistory()
        self._scope_enforcer = WebScopeEnforcer(self._scope)
        self._topology_normalizer = TopologyNormalizer()

    @property
    def engine(self) -> ExecutionEngine:
        """Return the execution engine used by this service."""
        return self._engine

    def run(
        self,
        *,
        mission_id: str = "",
        target: CrawlTarget | str,
        mode: WebCrawlMode | str = WebCrawlMode.ACTIVE,
        tools: Sequence[str] | None = None,
        parameters: Mapping[str, Any] | None = None,
        with_history: bool = False,
        historical: Sequence[URLObservation] | None = None,
        min_confidence: float | None = None,
        max_concurrency: int = 2,
    ) -> WebCrawlBatch:
        """Execute a web crawl run and return the correlated batch.

        Args:
            mission_id: owning mission id (empty for ad-hoc runs).
            target: the target to crawl (URL, host, domain or IP).
            mode: the execution posture (passive, active, sitemap, robots...).
            tools: crawling tool ids to run; defaults to every registered
                crawling tool. Requesting an unregistered tool raises
                :class:`ValueError`.
            parameters: per-tool parameters merged into each execution context.
            with_history: compare current observations against ``historical``.
            historical: historical URL observations to diff against.
            min_confidence: minimum confidence for an observation to be retained.
            max_concurrency: execution concurrency ceiling.

        Returns:
            The :class:`WebCrawlBatch` with correlated observations, evidence,
            changes and execution summaries.

        Raises:
            ValueError: when the target is out of scope or a requested tool is
                not registered.

        """
        crawl_target = target if isinstance(target, CrawlTarget) else _make_target(target)
        enforcer, scope = self._scope_for(crawl_target)
        decision = enforcer.allows_target(crawl_target.value, crawl_target.target_type)
        if not decision.allowed:
            raise ValueError(f"crawl target is out of scope: {decision.reason}")
        crawl_mode = _make_mode(mode)
        selected = self._select_tools(tools)
        if crawl_mode in (WebCrawlMode.PASSIVE, WebCrawlMode.HISTORICAL):
            selected = []
        correlation_id = generate_id()
        parameters = dict(parameters or {})
        parameters["mode"] = crawl_mode.value
        if crawl_target.target_id:
            parameters["target_id"] = crawl_target.target_id
        parameters.setdefault("scope_roots", scope.roots or ())
        parameters.setdefault("follow_subdomains", scope.follow_subdomains)

        strategy = self._strategy_builder.build(
            crawl_target.value,
            mode=crawl_mode,
            target_kind=crawl_target.target_type,
            tools=tuple(selected) if selected else (),
            max_concurrency=max_concurrency,
            with_incremental=crawl_mode is WebCrawlMode.INCREMENTAL,
        )
        runnable = [tool_id for tool_id in strategy.tools if tool_id in selected]

        batch = WebCrawlBatch(
            mission_id=mission_id,
            correlation_id=correlation_id,
            target=crawl_target,
            mode=crawl_mode,
        )
        self._publish(
            CrawlStartedEvent(
                mission_id,
                correlation_id,
                crawl_target.value,
                mode=crawl_mode.value,
                tools=list(runnable),
            )
        )

        raw = CrawlPayload()
        try:
            self._publish(CrawlPhaseStartedEvent(correlation_id, "collection", mission_id=mission_id))
            for tool_id in runnable:
                context = self._build_context(
                    tool_id,
                    crawl_target,
                    mission_id,
                    correlation_id,
                    parameters,
                    strategy,
                )
                outcome = self._engine.execute(context)
                result = outcome.result
                found = observations_from_payload(result.output.json) if result.status.is_success else CrawlPayload()
                raw = _merge_payload(raw, found)
                batch.add_execution(
                    CrawlExecutionSummary(
                        tool_id=tool_id,
                        status=result.status.value,
                        urls=len(found.urls),
                        duration_ms=result.duration_ms,
                        error=result.error,
                    )
                )

            self._publish(CrawlPhaseStartedEvent(correlation_id, "correlation", mission_id=mission_id))
            correlation = self._correlator.correlate(
                urls=raw.urls,
                redirects=raw.redirects,
                endpoints=raw.endpoints,
                websockets=raw.websockets,
                graphqls=raw.graphqls,
                auth_boundaries=raw.auth_boundaries,
                evidence=raw.evidence,
            )
            batch.urls = [
                observation
                for observation in (self._score(observation, "url", min_confidence) for observation in correlation.urls)
                if observation is not None
            ]
            batch.redirects = correlation.redirects
            batch.endpoints = correlation.endpoints
            batch.websockets = correlation.websockets
            batch.graphqls = correlation.graphqls
            batch.auth_boundaries = correlation.auth_boundaries
            batch.evidence = correlation.evidence
            self._publish(
                CrawlCorrelationCompletedEvent(
                    mission_id,
                    correlation_id,
                    raw_observations=correlation.raw_count,
                    correlated_observations=correlation.raw_count - correlation.dropped_count,
                    urls=len(correlation.urls),
                )
            )

            self._publish(CrawlPhaseStartedEvent(correlation_id, "history", mission_id=mission_id))
            if strategy.incremental and historical is not None:
                diff = self._history.compare(historical, batch.urls, correlation_id=correlation_id, mission_id=mission_id)
                for change in diff.changes:
                    self._publish(
                        CrawlChangeDetectedEvent(
                            correlation_id,
                            change.url,
                            change.change_type,
                            previous=change.previous,
                            current=change.current,
                            tool_id=change.tool_id,
                            mission_id=mission_id,
                        )
                    )

            self._publish_discoveries(batch, correlation_id, mission_id)

            if self._stores is not None:
                self._publish(CrawlPhaseStartedEvent(correlation_id, "persistence", mission_id=mission_id))
                self._persist(batch, crawl_target, mission_id, correlation_id, strategy)

            self._publish(CrawlPhaseStartedEvent(correlation_id, "topology", mission_id=mission_id))
            if self._stores is not None:
                self._update_topology(batch, mission_id, correlation_id)

            self._publish(
                CrawlCompletedEvent(
                    mission_id,
                    correlation_id,
                    target=crawl_target.value,
                    urls=len(correlation.urls),
                    distinct=batch.distinct_urls(),
                    endpoints=len(batch.endpoints),
                )
            )
        except Exception as exc:  # noqa: BLE001 - surfaced as a completion failure
            self._publish(
                CrawlFailedEvent(
                    mission_id,
                    correlation_id,
                    crawl_target.value,
                    str(exc),
                )
            )
            raise
        return batch

    # -- pipeline helpers ---------------------------------------------------

    def _select_tools(self, tools: Sequence[str] | None) -> list[str]:
        """Return the registered crawling tools to run for this mission."""
        registered = self._engine.adapter_for
        if tools is None:
            return [tool_id for tool_id in WEB_TOOL_IDS if registered(tool_id) is not None]
        requested = list(tools)
        missing = [tool_id for tool_id in requested if registered(tool_id) is None]
        if missing:
            raise ValueError(f"requested crawling tools are not registered: {', '.join(missing)}")
        return requested

    def _scope_for(self, target: CrawlTarget) -> tuple[WebScopeEnforcer, WebScopePolicy]:
        """Return the enforcer/policy for a crawl target.

        When no scope roots are configured the target itself authorizes its own
        host tree (matching the crawler tool's seed-root derivation and the
        other capabilities' open-by-default posture); configured roots remain
        strictly fail-closed.
        """
        policy = self._scope
        if policy.is_empty() and target.value:
            root = target.value
            if target.target_type == "url" or "://" in root:
                with contextlib.suppress(ValueError):
                    root = URLNormalizer().host(root)
            policy = WebScopePolicy(
                roots=(root,),
                excluded_extensions=policy.excluded_extensions,
                max_depth=policy.max_depth,
                follow_subdomains=policy.follow_subdomains,
                respect_robots=policy.respect_robots,
            )
        return WebScopeEnforcer(policy), policy

    def _build_context(
        self,
        tool_id: str,
        target: CrawlTarget,
        mission_id: str,
        correlation_id: str,
        parameters: Mapping[str, Any],
        strategy: CrawlStrategy,
    ) -> ExecutionContext:
        """Build an execution context for one crawling tool."""
        merged = dict(parameters)
        merged.setdefault("depth", strategy.policy.max_depth)
        merged.setdefault("max_pages", strategy.policy.max_pages)
        merged.setdefault("timeout", strategy.policy.timeout_seconds)
        merged.setdefault("respect_robots", strategy.policy.respect_robots)
        merged.setdefault("follow_subdomains", self._scope.follow_subdomains)
        if strategy.fetch_sitemap:
            merged.setdefault("fetch_sitemap", True)
        if strategy.fetch_robots:
            merged.setdefault("fetch_robots", True)
        return (
            ExecutionContextBuilder(tool_id=tool_id, target=target.value)
            .with_mission(mission_id)
            .with_target_type(target.target_type)
            .with_profile("web-crawling")
            .with_correlation_id(correlation_id)
            .with_permissions(("network",))
            .with_parameters(merged)
            .build()
        )

    def _score(
        self,
        observation: URLObservation,
        artifact_type: str,
        min_confidence: float | None,
    ) -> URLObservation | None:
        """Recompute confidence for a URL observation and enforce the floor."""
        from dataclasses import replace

        score = self._confidence.score(
            artifact_type,
            observation.source,
            evidence_count=0,
            status_code=observation.status_code,
        )
        if min_confidence is not None and score < min_confidence:
            return None
        return replace(observation, confidence=score)

    def _persist(
        self,
        batch: WebCrawlBatch,
        target: CrawlTarget,
        mission_id: str,
        correlation_id: str,
        strategy: CrawlStrategy,
    ) -> int:
        """Persist correlated web intelligence into the TIDB; returns rows."""
        stores = self._stores
        if stores is None:
            raise RuntimeError("cannot persist web intelligence without TIDB stores")
        count = 0
        origins = self._persist_origins(batch.urls, mission_id, correlation_id)
        for observation in batch.urls:
            origin_id = origins.get(observation.origin)
            stores.repository_for(TidbURLObservation).save(
                _to_url_entity(observation, origin_id, mission_id, correlation_id)
            )
            count += 1
        for redirect in batch.redirects:
            stores.repository_for(TidbWebRedirect).save(
                _to_redirect_entity(redirect, mission_id, correlation_id)
            )
            count += 1
        for endpoint in batch.endpoints:
            stores.repository_for(TidbWebAPIEndpoint).save(
                _to_api_entity(endpoint, mission_id, correlation_id)
            )
            count += 1
        for websocket in batch.websockets:
            stores.repository_for(TidbWebSocketEndpoint).save(
                _to_websocket_entity(websocket, mission_id, correlation_id)
            )
            count += 1
        for graphql in batch.graphqls:
            stores.repository_for(TidbWebGraphQLEndpoint).save(
                _to_graphql_entity(graphql, mission_id, correlation_id)
            )
            count += 1
        for boundary in batch.auth_boundaries:
            stores.repository_for(TidbAuthenticationBoundary).save(
                _to_auth_entity(boundary, mission_id, correlation_id)
            )
            count += 1
        for evidence in batch.evidence:
            stores.repository_for(TidbCrawlEvidence).save(
                _to_evidence_entity(evidence, mission_id, correlation_id)
            )
            count += 1
        run = TidbCrawlExecution(
            mission_id=mission_id,
            target_key=target.value,
            target_id=target.target_id or None,
            mode=batch.mode.value,
            status="completed",
            urls_seen=batch.url_count(),
            urls_distinct=batch.distinct_urls(),
            endpoints=len(batch.endpoints),
            redirects=len(batch.redirects),
            websockets=len(batch.websockets),
            graphqls=len(batch.graphqls),
            auth_boundaries=len(batch.auth_boundaries),
            policy=strategy.policy.snapshot(),
            started_at=batch.created_at,
            completed_at=utcnow_iso(),
            summary={
                "tools": [summary.tool_id for summary in batch.executions],
                "incremental": strategy.incremental,
            },
            correlation_id=correlation_id,
        )
        stores.repository_for(TidbCrawlExecution).save(run)
        count += 1
        return count

    def _persist_origins(
        self,
        urls: Sequence[URLObservation],
        mission_id: str,
        correlation_id: str,
    ) -> dict[str, str]:
        """Persist distinct web origins and return an origin -> record-id map."""
        stores = self._stores
        if stores is None:
            return {}
        repo = stores.repository_for(TidbWebOrigin)
        seen: dict[str, str] = {}
        for observation in urls:
            if not observation.origin or observation.origin in seen:
                continue
            entity = TidbWebOrigin(
                scheme=observation.origin.split("://", 1)[0],
                host=observation.target_key,
                port=None,
                target_id=observation.target_id,
                confidence=observation.confidence,
                key=observation.origin,
                meta={"mission_id": mission_id, "correlation_id": correlation_id},
            )
            repo.save(entity)
            seen[observation.origin] = entity.id
        return seen

    def _update_topology(self, batch: WebCrawlBatch, mission_id: str, correlation_id: str) -> None:
        """Derive web origin/URL/endpoint edges and persist them into the topology."""
        stores = self._stores
        if stores is None:
            return
        repo = stores.repository_for(TidbTopologyRelationship)
        edges = self._topology_edges(batch, mission_id, correlation_id)
        for edge in edges:
            repo.save(edge.to_tidb())

    def _topology_edges(
        self,
        batch: WebCrawlBatch,
        mission_id: str,
        correlation_id: str,
    ) -> list[GraphRelationship]:
        """Derive graph edges from a correlated web crawl batch."""
        edges: list[GraphRelationship] = []
        origin_names = {observation.origin for observation in batch.urls if observation.origin}
        for origin in sorted(origin_names):
            edges.append(
                self._edge(
                    source_kind=EntityKind.HOSTNAME,
                    source_name=batch.target.value,
                    rel_type=RelationshipType.EXPOSES,
                    target_kind=EntityKind.WEB_ORIGIN,
                    target_name=origin,
                    confidence=0.9,
                    mission_id=mission_id,
                    correlation_id=correlation_id,
                )
            )
        for observation in batch.urls:
            host = observation.target_key
            edges.append(
                self._edge(
                    source_kind=EntityKind.WEB_ORIGIN,
                    source_name=observation.origin,
                    rel_type=RelationshipType.HOSTED_ON,
                    target_kind=EntityKind.HOSTNAME,
                    target_name=host,
                    confidence=observation.confidence,
                    mission_id=mission_id,
                    correlation_id=correlation_id,
                )
            )
            edges.append(
                self._edge(
                    source_kind=EntityKind.WEB_ORIGIN,
                    source_name=observation.origin,
                    rel_type=RelationshipType.SERVES,
                    target_kind=EntityKind.URL,
                    target_name=observation.url,
                    confidence=observation.confidence,
                    mission_id=mission_id,
                    correlation_id=correlation_id,
                )
            )
        for endpoint in batch.endpoints:
            edges.append(
                self._edge(
                    source_kind=EntityKind.WEB_ORIGIN,
                    source_name=_origin_for(endpoint.url),
                    rel_type=RelationshipType.SERVES,
                    target_kind=EntityKind.API_ENDPOINT,
                    target_name=f"{endpoint.method.value} {endpoint.url}",
                    confidence=endpoint.confidence,
                    mission_id=mission_id,
                    correlation_id=correlation_id,
                )
            )
        return edges

    def _edge(
        self,
        *,
        source_kind: EntityKind,
        source_name: str,
        rel_type: RelationshipType,
        target_kind: EntityKind,
        target_name: str,
        confidence: float,
        mission_id: str,
        correlation_id: str,
    ) -> GraphRelationship:
        return GraphRelationship(
            rel_type=rel_type,
            source=TopologyEntity(kind=source_kind, name=self._topology_normalizer.normalize(source_kind, source_name)),
            target=TopologyEntity(kind=target_kind, name=self._topology_normalizer.normalize(target_kind, target_name)),
            sources=["web-crawling"],
            evidence={"capability": "web-crawling"},
            confidence=confidence,
            mission_id=mission_id,
            correlation_id=correlation_id,
            in_scope=True,
        )

    # -- events -------------------------------------------------------------

    def _publish_discoveries(self, batch: WebCrawlBatch, correlation_id: str, mission_id: str) -> None:
        """Publish discovery events for the correlated artifact set."""
        for observation in batch.urls:
            self._publish(
                CrawlUrlDiscoveredEvent(
                    correlation_id,
                    observation.url,
                    status_code=observation.status_code,
                    tool_id=observation.tool_id,
                    mission_id=mission_id,
                )
            )
        for endpoint in batch.endpoints:
            self._publish(
                CrawlEndpointDiscoveredEvent(
                    correlation_id,
                    endpoint.url,
                    endpoint.method.value,
                    tool_id=endpoint.tool_id,
                    mission_id=mission_id,
                )
            )
        for websocket in batch.websockets:
            self._publish(
                CrawlWebSocketDiscoveredEvent(
                    correlation_id,
                    websocket.url,
                    tool_id=websocket.tool_id,
                    mission_id=mission_id,
                )
            )
        for graphql in batch.graphqls:
            self._publish(
                CrawlGraphQLDiscoveredEvent(
                    correlation_id,
                    graphql.url,
                    tool_id=graphql.tool_id,
                    mission_id=mission_id,
                )
            )
        for redirect in batch.redirects:
            self._publish(
                CrawlRedirectDiscoveredEvent(
                    correlation_id,
                    redirect.source_url,
                    redirect.destination_url,
                    status_code=redirect.status_code,
                    tool_id=redirect.tool_id,
                    mission_id=mission_id,
                )
            )
        for boundary in batch.auth_boundaries:
            self._publish(
                CrawlAuthBoundaryDiscoveredEvent(
                    correlation_id,
                    boundary.url,
                    boundary.scheme,
                    tool_id=boundary.tool_id,
                    mission_id=mission_id,
                )
            )

    def _publish(self, event: Any) -> None:
        """Publish an event when an event bus is configured."""
        if self._event_bus is not None:
            self._event_bus.publish(event)


class CrawlQueryService:
    """Answer web crawling intelligence queries from persisted TIDB records."""

    def __init__(
        self,
        *,
        stores: TidbRepositoryFactory | None = None,
        cache: CachePort | None = None,
    ) -> None:
        self._stores = stores
        self._cache = cache

    def origins(self, *, host: str = "", mission_id: str = "") -> list[dict[str, Any]]:
        """Return persisted web origins (optionally filtered)."""
        records = self._records(TidbWebOrigin, "host", host, mission_id="")
        if mission_id:
            records = [
                record
                for record in records
                if dict(record.meta or {}).get("mission_id") == mission_id
            ]
        return [self._origin_dict(record) for record in records]

    def urls(self, *, host: str = "", mission_id: str = "") -> list[dict[str, Any]]:
        """Return persisted URL observations (optionally filtered)."""
        return [
            self._url_dict(record)
            for record in self._records(TidbURLObservation, "target_key", host, mission_id)
        ]

    def endpoints(self, *, host: str = "", mission_id: str = "") -> list[dict[str, Any]]:
        """Return persisted API endpoints (optionally filtered)."""
        return [
            self._api_dict(record)
            for record in self._records(TidbWebAPIEndpoint, "target_key", host, mission_id)
        ]

    def websockets(self, *, host: str = "", mission_id: str = "") -> list[dict[str, Any]]:
        """Return persisted WebSocket endpoints (optionally filtered)."""
        return [
            self._websocket_dict(record)
            for record in self._records(TidbWebSocketEndpoint, "target_key", host, mission_id)
        ]

    def graphql(self, *, host: str = "", mission_id: str = "") -> list[dict[str, Any]]:
        """Return persisted GraphQL endpoints (optionally filtered)."""
        return [
            self._graphql_dict(record)
            for record in self._records(TidbWebGraphQLEndpoint, "target_key", host, mission_id)
        ]

    def auth_boundaries(self, *, host: str = "", mission_id: str = "") -> list[dict[str, Any]]:
        """Return persisted authentication boundaries (optionally filtered)."""
        return [
            self._auth_dict(record)
            for record in self._records(TidbAuthenticationBoundary, "target_key", host, mission_id)
        ]

    def redirects(self, *, host: str = "", mission_id: str = "") -> list[dict[str, Any]]:
        """Return persisted redirect observations (optionally filtered)."""
        return [
            self._redirect_dict(record)
            for record in self._records(TidbWebRedirect, "target_key", host, mission_id)
        ]

    def executions(self, *, target: str = "", mission_id: str = "") -> list[dict[str, Any]]:
        """Return persisted crawl run records (optionally filtered)."""
        return [
            self._execution_dict(record)
            for record in self._records(TidbCrawlExecution, "target_key", target, mission_id)
        ]

    # -- helpers ------------------------------------------------------------

    def _records(self, entity_type: type, field: str, value: str, mission_id: str) -> list[Any]:
        if self._stores is None:
            return []
        repo = self._stores.repository_for(entity_type)
        records = list(repo.list_by(field, value, limit=1000)) if value else list(repo.stream())
        if mission_id:
            records = [
                record
                for record in records
                if getattr(record, "mission_id", None) == mission_id
            ]
        return [record for record in records if record.deleted_at is None]

    def _origin_dict(self, record: Any) -> dict[str, Any]:
        meta = dict(record.meta or {})
        return {
            "id": record.id,
            "key": record.key,
            "scheme": record.scheme,
            "host": record.host,
            "port": record.port,
            "confidence": record.confidence,
            "target_id": record.target_id,
            "mission_id": meta.get("mission_id", ""),
            "correlation_id": meta.get("correlation_id", ""),
            "first_seen": record.first_seen,
            "last_seen": record.last_seen,
        }

    def _url_dict(self, record: Any) -> dict[str, Any]:
        return {
            "id": record.id,
            "url": record.url,
            "method": record.method,
            "origin_id": record.origin_id,
            "path": record.path,
            "query": record.query,
            "status_code": record.status_code,
            "content_type": record.content_type,
            "source": record.source,
            "tool_id": record.tool_id,
            "confidence": record.confidence,
            "target_key": record.target_key,
            "mission_id": record.mission_id,
            "times_seen": record.times_seen,
            "first_seen": record.first_seen,
            "last_seen": record.last_seen,
        }

    def _api_dict(self, record: Any) -> dict[str, Any]:
        return {
            "id": record.id,
            "url": record.url,
            "method": record.method,
            "content_type": record.content_type,
            "response_content_type": record.response_content_type,
            "parameters": record.parameters,
            "confidence": record.confidence,
            "tool_id": record.tool_id,
            "target_key": record.target_key,
            "mission_id": record.mission_id,
        }

    def _websocket_dict(self, record: Any) -> dict[str, Any]:
        return {
            "id": record.id,
            "url": record.url,
            "protocol": record.protocol,
            "confidence": record.confidence,
            "tool_id": record.tool_id,
            "target_key": record.target_key,
            "mission_id": record.mission_id,
        }

    def _graphql_dict(self, record: Any) -> dict[str, Any]:
        return {
            "id": record.id,
            "url": record.url,
            "methods": record.methods,
            "introspection": record.introspection,
            "confidence": record.confidence,
            "tool_id": record.tool_id,
            "target_key": record.target_key,
            "mission_id": record.mission_id,
        }

    def _auth_dict(self, record: Any) -> dict[str, Any]:
        return {
            "id": record.id,
            "url": record.url,
            "scheme": record.scheme,
            "indicators": record.indicators,
            "confidence": record.confidence,
            "tool_id": record.tool_id,
            "target_key": record.target_key,
            "mission_id": record.mission_id,
        }

    def _redirect_dict(self, record: Any) -> dict[str, Any]:
        return {
            "id": record.id,
            "source_url": record.source_url,
            "destination_url": record.destination_url,
            "status_code": record.status_code,
            "redirect_type": record.redirect_type,
            "chain": record.chain,
            "tool_id": record.tool_id,
            "target_key": record.target_key,
            "mission_id": record.mission_id,
        }

    def _execution_dict(self, record: Any) -> dict[str, Any]:
        return {
            "id": record.id,
            "mission_id": record.mission_id,
            "target_key": record.target_key,
            "target_id": record.target_id,
            "mode": record.mode,
            "status": record.status,
            "urls_seen": record.urls_seen,
            "urls_distinct": record.urls_distinct,
            "endpoints": record.endpoints,
            "redirects": record.redirects,
            "websockets": record.websockets,
            "graphqls": record.graphqls,
            "auth_boundaries": record.auth_boundaries,
            "started_at": record.started_at,
            "completed_at": record.completed_at,
            "summary": record.summary,
            "correlation_id": record.correlation_id,
        }


# -- TIDB mapping helpers -----------------------------------------------------


def _to_url_entity(
    observation: URLObservation,
    origin_id: str | None,
    mission_id: str,
    correlation_id: str,
) -> TidbURLObservation:
    """Map a correlated URL observation onto the TIDB entity."""
    return TidbURLObservation(
        url=observation.url,
        method=observation.method.value,
        origin_id=origin_id,
        path=observation.path,
        query=observation.query,
        status_code=observation.status_code,
        content_type=observation.content_type,
        source=observation.source,
        tool_id=observation.tool_id,
        confidence=observation.confidence,
        target_id=observation.target_id,
        target_key=observation.target_key,
        correlation_id=correlation_id,
        mission_id=mission_id,
        execution_id=observation.execution_id,
        key=observation.key(),
        first_seen=observation.observed_at,
        last_seen=observation.observed_at,
    )


def _to_redirect_entity(
    redirect: Redirect,
    mission_id: str,
    correlation_id: str,
) -> TidbWebRedirect:
    """Map a redirect observation onto the TIDB entity."""
    return TidbWebRedirect(
        source_url=redirect.source_url,
        destination_url=redirect.destination_url,
        status_code=redirect.status_code,
        redirect_type=redirect.redirect_type,
        chain=list(redirect.chain),
        source=redirect.source,
        tool_id=redirect.tool_id,
        confidence=redirect.confidence,
        target_key=redirect.target_key,
        correlation_id=correlation_id,
        mission_id=mission_id,
        first_seen=redirect.observed_at,
        last_seen=redirect.observed_at,
    )


def _to_api_entity(
    endpoint: APIEndpoint,
    mission_id: str,
    correlation_id: str,
) -> TidbWebAPIEndpoint:
    """Map an API endpoint onto the TIDB entity."""
    return TidbWebAPIEndpoint(
        url=endpoint.url,
        method=endpoint.method.value,
        content_type=endpoint.content_type,
        response_content_type=endpoint.response_content_type,
        parameters=[dict(item) for item in endpoint.parameters],
        evidence=[dict(item) for item in endpoint.evidence],
        confidence=endpoint.confidence,
        source=endpoint.source,
        tool_id=endpoint.tool_id,
        target_key=endpoint.target_key,
        correlation_id=correlation_id,
        mission_id=mission_id,
        first_seen=endpoint.observed_at,
        last_seen=endpoint.observed_at,
    )


def _to_websocket_entity(
    endpoint: WebSocketEndpoint,
    mission_id: str,
    correlation_id: str,
) -> TidbWebSocketEndpoint:
    """Map a WebSocket endpoint onto the TIDB entity."""
    return TidbWebSocketEndpoint(
        url=endpoint.url,
        protocol=endpoint.protocol,
        evidence=[dict(item) for item in endpoint.evidence],
        confidence=endpoint.confidence,
        source=endpoint.source,
        tool_id=endpoint.tool_id,
        target_key=endpoint.target_key,
        correlation_id=correlation_id,
        mission_id=mission_id,
        first_seen=endpoint.observed_at,
        last_seen=endpoint.observed_at,
    )


def _to_graphql_entity(
    endpoint: GraphQLEndpoint,
    mission_id: str,
    correlation_id: str,
) -> TidbWebGraphQLEndpoint:
    """Map a GraphQL endpoint onto the TIDB entity."""
    return TidbWebGraphQLEndpoint(
        url=endpoint.url,
        methods=list(endpoint.methods),
        introspection=endpoint.introspection,
        evidence=[dict(item) for item in endpoint.evidence],
        confidence=endpoint.confidence,
        source=endpoint.source,
        tool_id=endpoint.tool_id,
        target_key=endpoint.target_key,
        correlation_id=correlation_id,
        mission_id=mission_id,
        first_seen=endpoint.observed_at,
        last_seen=endpoint.observed_at,
    )


def _to_auth_entity(
    boundary: AuthenticationBoundary,
    mission_id: str,
    correlation_id: str,
) -> TidbAuthenticationBoundary:
    """Map an authentication boundary onto the TIDB entity."""
    return TidbAuthenticationBoundary(
        url=boundary.url,
        scheme=boundary.scheme,
        indicators=list(boundary.indicators),
        confidence=boundary.confidence,
        source=boundary.source,
        tool_id=boundary.tool_id,
        target_key=boundary.target_key,
        correlation_id=correlation_id,
        mission_id=mission_id,
        first_seen=boundary.observed_at,
        last_seen=boundary.observed_at,
    )


def _to_evidence_entity(
    evidence: CrawlEvidence,
    mission_id: str,
    correlation_id: str,
) -> TidbCrawlEvidence:
    """Map crawl evidence onto the TIDB entity."""
    return TidbCrawlEvidence(
        url=evidence.url,
        evidence_type=evidence.evidence_type,
        value=evidence.value,
        source=evidence.source,
        tool_id=evidence.tool_id,
        integrity=evidence.integrity,
        target_key=evidence.target_key,
        correlation_id=correlation_id,
        mission_id=mission_id,
        first_seen=evidence.observed_at,
        last_seen=evidence.observed_at,
    )


# -- small helpers -------------------------------------------------------------


def _make_target(target: str) -> CrawlTarget:
    """Build a :class:`CrawlTarget` from a plain string."""
    from hunterx.domain.web.urls import is_supported_scheme

    stripped = target.strip()
    if is_supported_scheme(stripped):
        return CrawlTarget(value=stripped, target_type="url")
    return CrawlTarget(value=stripped, target_type="host")


def _make_mode(mode: WebCrawlMode | str) -> WebCrawlMode:
    """Coerce a mode into a :class:`WebCrawlMode`."""
    if isinstance(mode, WebCrawlMode):
        return mode
    return WebCrawlMode(str(mode).lower())


def _merge_payload(a: CrawlPayload, b: CrawlPayload) -> CrawlPayload:
    """Concatenate two artifact payloads preserving order."""
    return CrawlPayload(
        urls=a.urls + b.urls,
        redirects=a.redirects + b.redirects,
        endpoints=a.endpoints + b.endpoints,
        websockets=a.websockets + b.websockets,
        graphqls=a.graphqls + b.graphqls,
        auth_boundaries=a.auth_boundaries + b.auth_boundaries,
        evidence=a.evidence + b.evidence,
    )


def _origin_for(url: str) -> str:
    """Return the canonical origin of an endpoint URL (best effort)."""
    try:
        return URLNormalizer().origin(url)
    except ValueError:
        return url
