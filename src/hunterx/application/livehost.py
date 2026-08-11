# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Live Host & Service Discovery use-case service.

The live discovery orchestrator — the bridge between a mission and the live
host tooling. Given a target and a posture, it builds a :class:`LiveStrategy`,
selects the registered live discovery tools, runs each through the
:class:`ExecutionEngine` pipeline, collects the raw observations, normalizes,
validates, correlates them across tools, resolves conflicts, compares against
historical state, persists everything to the TIDB and publishes ``host.*``
events.

The service depends on ports only: the execution engine (tools layer), the
TIDB repository factory (domain port) and the event bus port. Concrete
SQL/in-memory stores are injected by the platform assembler.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from hunterx.domain.entities.tidb.network import (
    DiscoveryConflict as TidbDiscoveryConflict,
)
from hunterx.domain.entities.tidb.network import HostObservation as TidbHostObservation
from hunterx.domain.entities.tidb.network import LiveChange as TidbLiveChange
from hunterx.domain.entities.tidb.network import PortObservation as TidbPortObservation
from hunterx.domain.entities.tidb.network import ServiceObservation as TidbServiceObservation
from hunterx.domain.events.types import (
    LiveChangeDetectedEvent,
    LiveConflictDetectedEvent,
    LiveCorrelationCompletedEvent,
    LiveDiscoveryCompletedEvent,
    LiveDiscoveryFailedEvent,
    LiveDiscoveryStartedEvent,
    LiveObservationDiscoveredEvent,
    LivePhaseStartedEvent,
    LiveToolFailedEvent,
)
from hunterx.domain.execution import ExecutionContext
from hunterx.domain.livehost.confidence import LiveConfidenceEngine
from hunterx.domain.livehost.conflicts import LiveConflictResolver
from hunterx.domain.livehost.correlator import LiveCorrelator
from hunterx.domain.livehost.history import LiveHistory
from hunterx.domain.livehost.models import (
    HttpFinding,
    LiveBatch,
    LiveExecutionSummary,
    LiveHost,
    LiveTarget,
    PortFinding,
    ServiceFinding,
    TlsFinding,
    observations_from_payload,
)
from hunterx.domain.livehost.normalizer import LiveNormalizer
from hunterx.domain.livehost.scope import LiveScopeEnforcer, LiveScopePolicy
from hunterx.domain.livehost.strategy import LiveStrategy, LiveStrategyBuilder
from hunterx.domain.livehost.validator import LiveValidator
from hunterx.domain.ports.messaging import EventBusPort
from hunterx.domain.ports.tidb_repositories import TidbRepositoryFactory
from hunterx.domain.recon.models import ReconMode
from hunterx.shared.ids import generate_id
from hunterx.tools.livehost.registry import LIVE_TOOL_IDS
from hunterx.tools.sdk.context import ExecutionContextBuilder
from hunterx.tools.sdk.engine import ExecutionEngine


class LiveHostService:
    """Run live host & service discovery missions through the Tool SDK.

    Usage::

        service = LiveHostService(engine=engine, stores=stores, event_bus=bus)
        batch = service.run(mission_id="m1", target="10.0.0.0/24", mode="active")
    """

    def __init__(
        self,
        *,
        engine: ExecutionEngine,
        stores: TidbRepositoryFactory | None = None,
        event_bus: EventBusPort | None = None,
        scope: LiveScopePolicy | None = None,
        cache: object | None = None,
        confidence: LiveConfidenceEngine | None = None,
        correlator: LiveCorrelator | None = None,
    ) -> None:
        self._engine = engine
        self._stores = stores
        self._event_bus = event_bus
        self._scope = scope or LiveScopePolicy()
        self._cache = cache
        self._confidence = confidence or LiveConfidenceEngine()
        self._correlator = correlator or LiveCorrelator(
            scope=self._scope,
            confidence=self._confidence.policy,
        )
        self._normalizer = LiveNormalizer()
        self._validator = LiveValidator()
        self._strategy_builder = LiveStrategyBuilder()
        self._scope_enforcer = LiveScopeEnforcer(self._scope)
        self._conflict_resolver = LiveConflictResolver()
        self._history = LiveHistory()

    @property
    def engine(self) -> ExecutionEngine:
        """Return the execution engine used by this service."""
        return self._engine

    @property
    def correlator(self) -> LiveCorrelator:
        """Return the correlator used to merge live observations."""
        return self._correlator

    def run(
        self,
        *,
        mission_id: str = "",
        target: LiveTarget | str,
        mode: ReconMode | str = ReconMode.HYBRID,
        tools: Sequence[str] | None = None,
        parameters: Mapping[str, Any] | None = None,
        ports: Sequence[int] | None = None,
        protocol: str = "tcp",
        with_service_detection: bool | None = None,
        with_tls: bool | None = None,
        with_http: bool | None = None,
        with_history: bool = False,
        historical: Sequence[object] | None = None,
        max_concurrency: int = 8,
    ) -> LiveBatch:
        """Execute a live discovery run and return the correlated batch.

        Args:
            mission_id: owning mission id (empty for ad-hoc runs).
            target: the target to discover (IP, CIDR, hostname or domain).
            mode: the execution posture (passive, active or hybrid).
            tools: live discovery tool ids to run; defaults to every registered
                live tool. Requesting an unregistered tool raises
                :class:`ValueError`.
            parameters: per-tool parameters merged into each execution context.
            ports: ports to probe (defaults to the top-ports set).
            protocol: transport protocol (``tcp``, ``udp`` or ``both``).
            with_service_detection: fingerprint detected services.
            with_tls: collect TLS certificate metadata.
            with_http: collect HTTP service surfaces.
            with_history: compare current observations against ``historical``.
            historical: historical observations to diff against.
            max_concurrency: execution concurrency ceiling.

        Returns:
            The :class:`LiveBatch` with correlated hosts, ports, services,
            TLS/HTTP observations, changes, conflicts and execution summaries.

        """
        live_target = target if isinstance(target, LiveTarget) else _make_target(target)
        recon_mode = _make_mode(mode)
        selected = self._select_tools(tools)
        if recon_mode is ReconMode.PASSIVE:
            selected = []
        correlation_id = generate_id()
        parameters = dict(parameters or {})
        parameters["mode"] = recon_mode.value
        if live_target.target_id:
            parameters["target_id"] = live_target.target_id

        strategy = self._strategy_builder.build(
            live_target.value,
            mode=recon_mode,
            target_kind=live_target.target_type,
            ports=tuple(ports) if ports else (),
            protocol=protocol,
            with_service_detection=with_service_detection,
            with_tls=with_tls,
            with_http=with_http,
            with_history=with_history,
            tools=tuple(selected) if selected else (),
            max_concurrency=max_concurrency,
        )
        runnable = [tool_id for tool_id in strategy.tools if tool_id in selected]

        batch = LiveBatch(
            mission_id=mission_id,
            correlation_id=correlation_id,
            target=live_target,
            mode=recon_mode,
        )
        self._publish(
            LiveDiscoveryStartedEvent(
                mission_id,
                correlation_id,
                live_target.value,
                mode=recon_mode.value,
                tools=list(runnable),
            )
        )

        raw_hosts: list[LiveHost] = []
        raw_ports: list[PortFinding] = []
        raw_services: list[ServiceFinding] = []
        raw_tls: list[TlsFinding] = []
        raw_http: list[HttpFinding] = []
        try:
            self._publish(LivePhaseStartedEvent(correlation_id, "collection", mission_id=mission_id))
            for tool_id in runnable:
                context = self._build_context(
                    tool_id,
                    live_target,
                    mission_id,
                    correlation_id,
                    parameters,
                    strategy,
                )
                outcome = self._engine.execute(context)
                result = outcome.result
                found_hosts, found_ports, found_services, found_tls, found_http = (
                    observations_from_payload(result.output.json) if result.status.is_success else ([], [], [], [], [])
                )
                raw_hosts.extend(found_hosts)
                raw_ports.extend(found_ports)
                raw_services.extend(found_services)
                raw_tls.extend(found_tls)
                raw_http.extend(found_http)
                summary = LiveExecutionSummary(
                    tool_id=tool_id,
                    status=result.status.value,
                    records=len(found_hosts)
                    + len(found_ports)
                    + len(found_services)
                    + len(found_tls)
                    + len(found_http),
                    hosts=len(found_hosts),
                    ports=len(found_ports),
                    services=len(found_services),
                    duration_ms=result.duration_ms,
                    error=result.error,
                )
                batch.add_execution(summary)
                if not result.status.is_success:
                    self._publish(
                        LiveToolFailedEvent(
                            correlation_id,
                            live_target.value,
                            result.error or result.status.value,
                            tool_id=tool_id,
                            mission_id=mission_id,
                        )
                    )

            self._publish(LivePhaseStartedEvent(correlation_id, "normalization", mission_id=mission_id))
            normalized = self._normalizer.normalize_many([*raw_hosts, *raw_ports, *raw_services, *raw_tls, *raw_http])

            self._publish(LivePhaseStartedEvent(correlation_id, "validation", mission_id=mission_id))
            for observation in normalized:
                self._validator.validate_observation(observation)

            self._publish(LivePhaseStartedEvent(correlation_id, "correlation", mission_id=mission_id))
            correlated = self._correlator.correlate(
                hosts=raw_hosts,
                ports=raw_ports,
                services=raw_services,
                tls=raw_tls,
                http=raw_http,
            )
            in_scope = self._scope_enforcer.filter_observations(
                [*correlated.hosts, *correlated.ports, *correlated.services, *correlated.tls, *correlated.http]
            )
            for observation in in_scope:
                if isinstance(observation, LiveHost):
                    batch.add_host(observation)
                elif isinstance(observation, PortFinding):
                    batch.add_port(observation)
                elif isinstance(observation, ServiceFinding):
                    batch.add_service(observation)
                elif isinstance(observation, TlsFinding):
                    batch.add_tls(observation)
                elif isinstance(observation, HttpFinding):
                    batch.add_http(observation)
            for conflict in correlated.conflicts:
                batch.add_conflict(conflict)
                self._publish(
                    LiveConflictDetectedEvent(
                        correlation_id,
                        conflict.kind,
                        conflict.key,
                        [_observation_str(item) for item in conflict.observations],
                        selected=conflict.selected,
                        mission_id=mission_id,
                    )
                )
            for observation in in_scope:
                self._publish(
                    LiveObservationDiscoveredEvent(
                        correlation_id,
                        _kind(observation),
                        observation.key(),  # type: ignore[attr-defined]
                        tool_id=observation.tool_id,  # type: ignore[attr-defined]
                        mission_id=mission_id,
                    )
                )
            self._publish(
                LiveCorrelationCompletedEvent(
                    mission_id,
                    correlation_id,
                    raw_observations=len(raw_hosts) + len(raw_ports) + len(raw_services) + len(raw_tls) + len(raw_http),
                    correlated_observations=batch.total_records(),
                    conflicts=len(correlated.conflicts),
                    hosts=batch.host_count(),
                    ports=batch.port_count(),
                    services=batch.service_count(),
                )
            )

            self._publish(LivePhaseStartedEvent(correlation_id, "history", mission_id=mission_id))
            if strategy.with_history and historical is not None:
                comparison = self._history.compare(historical, in_scope)
                for change in comparison.changes:
                    batch.add_change(change)
                    self._publish(
                        LiveChangeDetectedEvent(
                            correlation_id,
                            change.kind,
                            change.key,
                            change.change_type,
                            old_value=change.previous,
                            new_value=change.current,
                            mission_id=mission_id,
                        )
                    )

            if self._stores is not None:
                self._publish(LivePhaseStartedEvent(correlation_id, "persistence", mission_id=mission_id))
                self._persist(batch, live_target, mission_id, correlation_id)

            self._publish(
                LiveDiscoveryCompletedEvent(
                    mission_id,
                    correlation_id,
                    target=live_target.value,
                    hosts=batch.host_count(),
                    ports=batch.port_count(),
                    services=batch.service_count(),
                )
            )
        except Exception as exc:  # noqa: BLE001 - surfaced as a completion failure
            self._publish(
                LiveDiscoveryFailedEvent(
                    correlation_id,
                    live_target.value,
                    str(exc),
                    mission_id=mission_id,
                )
            )
            raise
        return batch

    def _select_tools(self, tools: Sequence[str] | None) -> list[str]:
        """Return the registered live discovery tools to run."""
        registered = self._engine.adapter_for
        if tools is None:
            return [tool_id for tool_id in LIVE_TOOL_IDS if registered(tool_id) is not None]
        requested = list(tools)
        missing = [tool_id for tool_id in requested if registered(tool_id) is None]
        if missing:
            raise ValueError(f"requested live discovery tools are not registered: {', '.join(missing)}")
        return requested

    def _build_context(
        self,
        tool_id: str,
        target: LiveTarget,
        mission_id: str,
        correlation_id: str,
        parameters: Mapping[str, Any],
        strategy: LiveStrategy,
    ) -> ExecutionContext:
        """Build an execution context for one live discovery tool."""
        merged = dict(parameters)
        if strategy.ports:
            merged.setdefault("ports", list(strategy.ports))
        if strategy.protocol:
            merged.setdefault("protocol", strategy.protocol)
        merged.setdefault("service_detection", strategy.with_service_detection)
        merged.setdefault("with_tls", strategy.with_tls)
        merged.setdefault("with_http", strategy.with_http)
        return (
            ExecutionContextBuilder(tool_id=tool_id, target=target.value)
            .with_mission(mission_id)
            .with_target_type(target.target_type)
            .with_profile("livehost")
            .with_correlation_id(correlation_id)
            .with_permissions(("network",))
            .with_parameters(merged)
            .build()
        )

    def _persist(
        self,
        batch: LiveBatch,
        target: LiveTarget,
        mission_id: str,
        correlation_id: str,
    ) -> int:
        """Persist correlated live observations into the TIDB; returns rows written."""
        stores = self._stores
        if stores is None:
            raise RuntimeError("cannot persist live observations without TIDB stores")
        count = 0
        for host in batch.hosts:
            stores.repository_for(TidbHostObservation).save(
                _to_host_observation(host, target, mission_id, correlation_id)
            )
            count += 1
        for port in batch.ports:
            stores.repository_for(TidbPortObservation).save(
                _to_port_observation(port, target, mission_id, correlation_id)
            )
            count += 1
        for service in batch.services:
            stores.repository_for(TidbServiceObservation).save(
                _to_service_observation(service, target, mission_id, correlation_id)
            )
            count += 1
        for change in batch.changes:
            stores.repository_for(TidbLiveChange).save(_to_live_change(change, mission_id, correlation_id))
            count += 1
        for conflict in batch.conflicts:
            stores.repository_for(TidbDiscoveryConflict).save(
                _to_discovery_conflict(conflict, mission_id, correlation_id)
            )
            count += 1
        return count

    def _publish(self, event: Any) -> None:
        """Publish an event when an event bus is configured."""
        if self._event_bus is not None:
            self._event_bus.publish(event)


def _make_target(target: str) -> LiveTarget:
    """Build a :class:`LiveTarget` from a plain string."""
    stripped = target.strip()
    kind = _infer_target_kind(stripped)
    return LiveTarget(value=stripped, target_type=kind)


def _infer_target_kind(value: str) -> str:
    """Infer a canonical target kind from a target value."""
    import ipaddress

    candidate = value.strip()
    if "/" in candidate:
        try:
            ipaddress.ip_network(candidate, strict=False)
            return "cidr"
        except ValueError:
            return "host"
    try:
        ipaddress.ip_address(candidate)
        return "ip"
    except ValueError:
        return "domain" if "." in candidate else "host"


def _make_mode(mode: ReconMode | str) -> ReconMode:
    """Coerce a mode into a :class:`ReconMode`."""
    if isinstance(mode, ReconMode):
        return mode
    return ReconMode(str(mode).lower())


def _kind(observation: object) -> str:
    """Return the observation kind discriminator."""
    if isinstance(observation, LiveHost):
        return "host"
    if isinstance(observation, PortFinding):
        return "port"
    if isinstance(observation, ServiceFinding):
        return "service"
    if isinstance(observation, TlsFinding):
        return "tls"
    if isinstance(observation, HttpFinding):
        return "http"
    return "observation"


def _observation_str(observation: dict[str, Any]) -> str:
    """Render a conflicting observation dict as a stable string."""
    source = str(observation.get("source") or "")
    value = str(observation.get("value") or "")
    return f"{source}:{value}"


def _to_host_observation(
    host: LiveHost,
    target: LiveTarget,
    mission_id: str,
    correlation_id: str,
) -> TidbHostObservation:
    """Map a correlated host onto the TIDB host observation entity."""
    return TidbHostObservation(
        address=host.address,
        ip_version=host.ip_version,
        hostname=host.hostname,
        state=host.state.value,
        reachable=host.reachable,
        methods=[method.value for method in host.methods],
        rtt_ms=host.rtt_ms,
        tool_id=host.tool_id,
        source=host.source,
        target_id=host.target_id or target.target_id,
        execution_id=host.execution_id,
        correlation_id=correlation_id,
    )


def _to_port_observation(
    port: PortFinding,
    target: LiveTarget,
    mission_id: str,
    correlation_id: str,
) -> TidbPortObservation:
    """Map a correlated port onto the TIDB port observation entity."""
    return TidbPortObservation(
        address=port.address,
        port=port.port,
        protocol=port.protocol.value,
        state=port.state.value,
        reason=port.reason,
        tool_id=port.tool_id,
        source=port.source,
        target_id=port.target_id or target.target_id,
        execution_id=port.execution_id,
        correlation_id=correlation_id,
    )


def _to_service_observation(
    service: ServiceFinding,
    target: LiveTarget,
    mission_id: str,
    correlation_id: str,
) -> TidbServiceObservation:
    """Map a correlated service onto the TIDB service observation entity."""
    return TidbServiceObservation(
        address=service.address,
        port=service.port,
        protocol=service.protocol.value,
        service=service.service,
        product=service.product,
        software_version=service.version,
        extrainfo=service.extrainfo,
        banner=service.banner,
        fingerprint_method=service.fingerprint_method,
        evidence=list(service.evidence),
        tool_id=service.tool_id,
        source=service.source,
        target_id=service.target_id or target.target_id,
        execution_id=service.execution_id,
        correlation_id=correlation_id,
    )


def _to_live_change(change: Any, mission_id: str, correlation_id: str) -> TidbLiveChange:
    """Map a history change onto the TIDB live change entity."""
    return TidbLiveChange(
        kind=change.kind,
        key=change.key,
        change_type=change.change_type,
        old_value=change.previous,
        new_value=change.current,
        tool_id=change.source,
        confidence=getattr(change, "confidence", 0.9),
        mission_id=mission_id,
        correlation_id=correlation_id,
    )


def _to_discovery_conflict(
    conflict: Any,
    mission_id: str,
    correlation_id: str,
) -> TidbDiscoveryConflict:
    """Map a discovery conflict onto the TIDB conflict entity."""
    return TidbDiscoveryConflict(
        kind=conflict.kind,
        key=conflict.key,
        observations=[
            {"source": str(item.get("source") or ""), "value": str(item.get("value") or "")}
            for item in conflict.observations
        ],
        conflict_type="value",
        selected_value=conflict.selected,
        selected_source="",
        reason=conflict.reason,
        confidence=conflict.confidence,
        mission_id=mission_id,
        correlation_id=correlation_id,
    )
