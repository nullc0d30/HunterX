# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Live discovery correlation and conflict detection.

Correlates observations from multiple tools/executions into a single canonical
set, merging corroborating facts and surfacing conflicts. The correlator never
silently discards an observation: values that disagree across sources are
reported as :class:`DiscoveryConflict` records with full provenance, and every
out-of-scope observation is counted rather than dropped silently.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, replace
from typing import Any, Protocol, TypeVar

from hunterx.domain.livehost.confidence import LiveConfidenceEngine, LiveConfidencePolicy
from hunterx.domain.livehost.models import (
    DiscoveryConflict,
    HttpFinding,
    LiveHost,
    PortFinding,
    ServiceFinding,
    TlsFinding,
)
from hunterx.domain.livehost.scope import LiveScopeEnforcer, LiveScopePolicy


class _Observable(Protocol):
    """Structural contract every live discovery observation satisfies."""

    @property
    def observed_at(self) -> str: ...

    def key(self) -> str: ...

    def to_dict(self) -> dict[str, Any]: ...


_T = TypeVar("_T", bound=_Observable)
_U = TypeVar("_U")

_StateValue = Callable[[_T], str]
_GroupKey = Callable[[_T], str]
_Merge = Callable[[Sequence[_T], LiveConfidenceEngine], _T]


@dataclass(frozen=True, slots=True)
class LiveCorrelationResult:
    """The outcome of correlating a set of live discovery observations.

    Attributes:
        hosts: canonical, merged host observations.
        ports: canonical, merged port observations.
        services: canonical, merged service observations.
        tls: canonical, merged TLS observations.
        http: canonical, merged HTTP observations.
        conflicts: observations that disagreed across sources.
        scoped_out: observations removed by scope enforcement.
        merged: number of observation groups that carried corroboration.

    """

    hosts: tuple[LiveHost, ...] = ()
    ports: tuple[PortFinding, ...] = ()
    services: tuple[ServiceFinding, ...] = ()
    tls: tuple[TlsFinding, ...] = ()
    http: tuple[HttpFinding, ...] = ()
    conflicts: tuple[DiscoveryConflict, ...] = ()
    scoped_out: int = 0
    merged: int = 0


def correlate_observations(
    hosts: Iterable[LiveHost] = (),
    ports: Iterable[PortFinding] = (),
    services: Iterable[ServiceFinding] = (),
    tls: Iterable[TlsFinding] = (),
    http: Iterable[HttpFinding] = (),
    *,
    scope: LiveScopePolicy | None = None,
    confidence: LiveConfidencePolicy | None = None,
) -> LiveCorrelationResult:
    """Correlate discovery observations into a canonical set.

    Observations sharing a canonical key are merged (sources accumulated,
    confidence raised by corroboration). Distinct values for the same group
    (address, address+port, ...) produce a :class:`DiscoveryConflict`. Scope
    enforcement drops out-of-scope observations.
    """
    enforcer = LiveScopeEnforcer(scope)
    engine = LiveConfidenceEngine(confidence)
    conflicts: list[DiscoveryConflict] = []
    scoped_out = 0
    merged = 0

    canonical_hosts, host_conflicts, host_scoped, host_merged = _correlate_type(
        hosts,
        kind="host",
        state_value=_host_state,
        group_key=_host_group,
        merge=_merge_hosts,
        enforcer=enforcer,
        engine=engine,
    )
    conflicts.extend(host_conflicts)
    scoped_out += host_scoped
    merged += host_merged

    canonical_ports, port_conflicts, port_scoped, port_merged = _correlate_type(
        ports,
        kind="port",
        state_value=_port_state,
        group_key=_port_group,
        merge=_merge_ports,
        enforcer=enforcer,
        engine=engine,
    )
    conflicts.extend(port_conflicts)
    scoped_out += port_scoped
    merged += port_merged

    canonical_services, service_conflicts, service_scoped, service_merged = _correlate_type(
        services,
        kind="service",
        state_value=_service_fingerprint,
        group_key=_service_group,
        merge=_merge_services,
        enforcer=enforcer,
        engine=engine,
    )
    conflicts.extend(service_conflicts)
    scoped_out += service_scoped
    merged += service_merged

    canonical_tls, tls_conflicts, tls_scoped, tls_merged = _correlate_type(
        tls,
        kind="tls",
        state_value=_tls_fingerprint,
        group_key=_tls_group,
        merge=_merge_tls,
        enforcer=enforcer,
        engine=engine,
    )
    conflicts.extend(tls_conflicts)
    scoped_out += tls_scoped
    merged += tls_merged

    canonical_http, http_conflicts, http_scoped, http_merged = _correlate_type(
        http,
        kind="http",
        state_value=_http_surface,
        group_key=_http_group,
        merge=_merge_http,
        enforcer=enforcer,
        engine=engine,
    )
    conflicts.extend(http_conflicts)
    scoped_out += http_scoped
    merged += http_merged

    return LiveCorrelationResult(
        hosts=tuple(canonical_hosts),
        ports=tuple(canonical_ports),
        services=tuple(canonical_services),
        tls=tuple(canonical_tls),
        http=tuple(canonical_http),
        conflicts=tuple(_dedupe_conflicts(conflicts)),
        scoped_out=scoped_out,
        merged=merged,
    )


class LiveCorrelator:
    """Object-style correlator wrapping :func:`correlate_observations`."""

    def __init__(self, scope: LiveScopePolicy | None = None, confidence: LiveConfidencePolicy | None = None) -> None:
        self._scope = scope
        self._confidence = confidence

    def correlate(
        self,
        hosts: Iterable[LiveHost] = (),
        ports: Iterable[PortFinding] = (),
        services: Iterable[ServiceFinding] = (),
        tls: Iterable[TlsFinding] = (),
        http: Iterable[HttpFinding] = (),
    ) -> LiveCorrelationResult:
        """Correlate observations and return the result."""
        return correlate_observations(hosts, ports, services, tls, http, scope=self._scope, confidence=self._confidence)


def _correlate_type(
    observations: Iterable[_T],
    *,
    kind: str,
    state_value: _StateValue[_T],
    group_key: _GroupKey[_T],
    merge: _Merge[_T],
    enforcer: LiveScopeEnforcer,
    engine: LiveConfidenceEngine,
) -> tuple[list[_T], list[DiscoveryConflict], int, int]:
    """Correlate one observation kind into canonical records plus conflicts."""
    grouped: dict[str, list[_T]] = {}
    scoped_out = 0
    for observation in observations:
        if not enforcer.allows_observation(observation).allowed:
            scoped_out += 1
            continue
        grouped.setdefault(observation.key(), []).append(observation)

    canonical = [merge(group, engine) for group in grouped.values()]

    group_buckets: dict[str, dict[str, _T]] = {}
    for group in grouped.values():
        bucket = group_buckets.setdefault(group_key(group[0]), {})
        for observation in group:
            value = state_value(observation)
            if value not in bucket or engine.observation_confidence(observation) > engine.observation_confidence(
                bucket[value]
            ):
                bucket[value] = observation

    conflicts: list[DiscoveryConflict] = []
    for group_value, bucket in group_buckets.items():
        if len(bucket) <= 1:
            continue
        best = max(bucket.values(), key=engine.observation_confidence)
        conflicts.append(
            DiscoveryConflict(
                kind=kind,
                key=group_value,
                observations=tuple(_observation_dict(value) for value in bucket.values()),
                reason="conflicting observations across sources",
                selected=state_value(best),
                confidence=engine.observation_confidence(best),
            )
        )

    merged = sum(1 for group in grouped.values() if len(group) > 1)
    return canonical, conflicts, scoped_out, merged


# -- state values and group keys (per observation kind) ----------------------


def _host_state(host: LiveHost) -> str:
    return host.state.value


def _host_group(host: LiveHost) -> str:
    return host.key()


def _port_state(port: PortFinding) -> str:
    return port.state.value


def _port_group(port: PortFinding) -> str:
    return f"{port.address}|{port.protocol.value}|{port.port}"


def _service_fingerprint(service: ServiceFinding) -> str:
    return f"{service.product}|{service.version}"


def _service_group(service: ServiceFinding) -> str:
    return f"{service.address}|{service.protocol.value}|{service.port}"


def _tls_fingerprint(tls: TlsFinding) -> str:
    return tls.sha256


def _tls_group(tls: TlsFinding) -> str:
    return f"{tls.address}|{tls.port}"


def _http_surface(http: HttpFinding) -> str:
    return str(http.status_code)


def _http_group(http: HttpFinding) -> str:
    return http.key()


# -- merge helpers -----------------------------------------------------------


def _merge_hosts(observations: Sequence[LiveHost], engine: LiveConfidenceEngine) -> LiveHost:
    rep = _representative(observations, engine)
    methods = tuple(_dedupe_iter(method for obs in observations for method in obs.methods))
    return replace(
        rep,
        methods=methods,
        source=_join_sources(observations),
        confidence=engine.merged_confidence(observations),
        observed_at=_earliest(observations),
    )


def _merge_ports(observations: Sequence[PortFinding], engine: LiveConfidenceEngine) -> PortFinding:
    rep = _representative(observations, engine)
    return replace(
        rep,
        source=_join_sources(observations),
        confidence=engine.merged_confidence(observations),
        observed_at=_earliest(observations),
    )


def _merge_services(observations: Sequence[ServiceFinding], engine: LiveConfidenceEngine) -> ServiceFinding:
    rep = _representative(observations, engine)
    evidence = tuple(_dedupe_iter(part for obs in observations for part in obs.evidence))
    return replace(
        rep,
        evidence=evidence,
        source=_join_sources(observations),
        confidence=engine.merged_confidence(observations),
        observed_at=_earliest(observations),
    )


def _merge_tls(observations: Sequence[TlsFinding], engine: LiveConfidenceEngine) -> TlsFinding:
    rep = _representative(observations, engine)
    san = tuple(_dedupe_iter(part for obs in observations for part in obs.san))
    ciphers = tuple(_dedupe_iter(part for obs in observations for part in obs.ciphers))
    return replace(
        rep,
        san=san,
        ciphers=ciphers,
        source=_join_sources(observations),
        confidence=engine.merged_confidence(observations),
        observed_at=_earliest(observations),
    )


def _merge_http(observations: Sequence[HttpFinding], engine: LiveConfidenceEngine) -> HttpFinding:
    rep = _representative(observations, engine)
    tech_hints = tuple(_dedupe_iter(part for obs in observations for part in obs.tech_hints))
    return replace(
        rep,
        tech_hints=tech_hints,
        source=_join_sources(observations),
        confidence=engine.merged_confidence(observations),
        observed_at=_earliest(observations),
    )


def _representative(observations: Sequence[_T], engine: LiveConfidenceEngine) -> _T:
    """Return the highest-confidence observation of a corroborated group."""
    return max(observations, key=engine.observation_confidence)


def _join_sources(observations: Sequence[object]) -> str:
    """Join the distinct sources of a corroborated group."""
    return ",".join(sorted({str(getattr(obs, "source", "")) for obs in observations if getattr(obs, "source", "")}))


def _earliest(observations: Sequence[object]) -> str:
    """Return the earliest observation timestamp of a corroborated group."""
    return min(str(getattr(obs, "observed_at", "")) for obs in observations)


def _dedupe_iter(values: Iterable[_U]) -> Iterable[_U]:
    """Yield distinct non-empty values preserving first-seen order."""
    seen: set[str] = set()
    for value in values:
        key = str(value).strip().lower()
        if not key or key in seen:
            continue
        seen.add(key)
        yield value


# -- small helpers -----------------------------------------------------------


def _observation_dict(observation: object) -> dict[str, Any]:
    """Return the JSON-safe payload of an observation for conflict records."""
    to_dict = getattr(observation, "to_dict", None)
    if to_dict is None:
        return {"record_id": getattr(observation, "record_id", "")}
    return dict(to_dict())


def _dedupe_conflicts(conflicts: Iterable[DiscoveryConflict]) -> list[DiscoveryConflict]:
    """Dedupe conflicts that repeat the same kind/key/selected tuple."""
    seen: set[tuple[str, str, str]] = set()
    unique: list[DiscoveryConflict] = []
    for conflict in conflicts:
        key = (conflict.kind, conflict.key, conflict.selected)
        if key in seen:
            continue
        seen.add(key)
        unique.append(conflict)
    return unique
