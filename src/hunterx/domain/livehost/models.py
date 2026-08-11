# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Live Host & Service Discovery canonical domain models.

Pure data contracts for the live host & service discovery capability: the
canonical host, port, service, TLS and HTTP observations every tool adapter
produces, the reachability outcomes, the change and conflict records produced
by historical comparison and correlation, the execution summaries and the
batch that carries everything back to the application layer. No I/O and no
execution here.

The TIDB ``network`` entities (:mod:`hunterx.domain.entities.tidb.network`)
are the persistence projection of these models; this module is the runtime
surface the discovery pipeline is built on.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from hunterx.domain.recon.models import ReconMode
from hunterx.shared.ids import generate_id
from hunterx.shared.time import utcnow_iso


class TransportProtocol(StrEnum):
    """Transport layer protocol of a discovered service."""

    TCP = "tcp"
    UDP = "udp"


class PortState(StrEnum):
    """Observed state of a network port.

    Values follow the canonical port states used by Nmap so tool output maps
    onto the model without lossy translation.
    """

    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    UNFILTERED = "unfiltered"
    UNKNOWN = "unknown"


class HostState(StrEnum):
    """Reachability state of a host."""

    REACHABLE = "reachable"
    UNREACHABLE = "unreachable"
    UNKNOWN = "unknown"


class ReachabilityMethod(StrEnum):
    """Technique used to determine that a host is reachable.

    A failed ICMP probe is never proof a host is offline, so the actual method
    that produced the evidence is always recorded alongside the outcome.
    """

    TCP_CONNECT = "tcp-connect"
    TCP_SYN = "tcp-syn"
    ICMP = "icmp"
    DNS = "dns"
    APPLICATION = "application"


#: Observation types carried inside the pipeline JSON payload.
OBSERVATION_HOST = "host"
OBSERVATION_PORT = "port"
OBSERVATION_SERVICE = "service"
OBSERVATION_TLS = "tls"
OBSERVATION_HTTP = "http"

#: Well-known default TCP ports used when no mission policy is provided.
DEFAULT_TOP_PORTS: tuple[int, ...] = (
    21,
    22,
    23,
    25,
    53,
    80,
    110,
    111,
    135,
    139,
    143,
    443,
    445,
    993,
    995,
    1723,
    3306,
    3389,
    5432,
    5900,
    8080,
    8443,
    8888,
    9090,
    27017,
)


@dataclass(frozen=True, slots=True)
class LiveTarget:
    """A single live host & service discovery target.

    Attributes:
        value: canonical target identifier (a domain, hostname, IP or CIDR).
        target_type: canonical target kind (``domain``, ``host``, ``ip``,
            ``cidr``).
        target_id: owning target record id when the target is persisted.

    """

    value: str
    target_type: str = "ip"
    target_id: str = ""


@dataclass(frozen=True, slots=True)
class LiveHost:
    """A canonical host reachability observation.

    Attributes:
        address: canonical (compressed) IPv4/IPv6 address.
        ip_version: IP protocol version (``4`` or ``6``).
        hostname: associated hostname when known (lowercase).
        state: reachability state.
        reachable: whether the host responded (``None`` when untested).
        methods: reachability methods that produced evidence.
        rtt_ms: round-trip latency in milliseconds (``0`` when unknown).
        tool_id: the tool that produced the observation.
        source: upstream source of the observation.
        confidence: detection confidence in ``[0, 1]``.
        target_id: owning target record id when in-scope.
        observed_at: UTC ISO-8601 observation timestamp.
        execution_id: owning execution id.
        correlation_id: correlation id shared by the run.
        record_id: stable identifier for this observation.

    """

    address: str
    ip_version: int = 4
    hostname: str = ""
    state: HostState = HostState.UNKNOWN
    reachable: bool | None = None
    methods: tuple[ReachabilityMethod, ...] = ()
    rtt_ms: int = 0
    tool_id: str = ""
    source: str = ""
    confidence: float = 1.0
    target_id: str | None = None
    observed_at: str = field(default_factory=utcnow_iso)
    execution_id: str = ""
    correlation_id: str = ""
    record_id: str = field(default_factory=generate_id, kw_only=True)

    def __post_init__(self) -> None:
        if not self.address.strip():
            raise ValueError("live host address must not be empty")
        object.__setattr__(self, "address", _normalize_address(self.address))
        object.__setattr__(self, "hostname", _normalize_hostname(self.hostname))

    def key(self) -> str:
        """Return the canonical deduplication key for this host."""
        return f"host:{self.address}"

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe dictionary for pipeline serialization."""
        return {
            "type": OBSERVATION_HOST,
            "record_id": self.record_id,
            "address": self.address,
            "ip_version": self.ip_version,
            "hostname": self.hostname,
            "state": self.state.value,
            "reachable": self.reachable,
            "methods": [method.value for method in self.methods],
            "rtt_ms": self.rtt_ms,
            "tool_id": self.tool_id,
            "source": self.source,
            "confidence": self.confidence,
            "target_id": self.target_id,
            "observed_at": self.observed_at,
            "execution_id": self.execution_id,
            "correlation_id": self.correlation_id,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> LiveHost:
        """Rebuild a host from a :meth:`to_dict` payload."""
        return cls(
            address=str(payload["address"]),
            ip_version=int(_optional_int(payload.get("ip_version"), 4) or 4),
            hostname=str(payload.get("hostname") or ""),
            state=_parse_host_state(payload.get("state")),
            reachable=_optional_bool(payload.get("reachable")),
            methods=tuple(_parse_method(value) for value in payload.get("methods") or ()),
            rtt_ms=int(_optional_int(payload.get("rtt_ms"), 0) or 0),
            tool_id=str(payload.get("tool_id") or ""),
            source=str(payload.get("source") or ""),
            confidence=float(payload.get("confidence") or 1.0),
            target_id=payload.get("target_id"),
            observed_at=str(payload.get("observed_at") or utcnow_iso()),
            execution_id=str(payload.get("execution_id") or ""),
            correlation_id=str(payload.get("correlation_id") or ""),
            record_id=str(payload.get("record_id") or generate_id()),
        )


@dataclass(frozen=True, slots=True)
class PortFinding:
    """A canonical port state observation.

    Attributes:
        address: canonical (compressed) IPv4/IPv6 address.
        port: port number.
        protocol: transport protocol (``tcp``/``udp``).
        state: observed port state.
        reason: reason reported by the tool (``syn-ack``, ``reset``, ...).
        tool_id: the tool that produced the observation.
        source: upstream source of the observation.
        confidence: detection confidence in ``[0, 1]``.
        target_id: owning target record id when in-scope.
        observed_at: UTC ISO-8601 observation timestamp.
        execution_id: owning execution id.
        correlation_id: correlation id shared by the run.
        record_id: stable identifier for this observation.

    """

    address: str
    port: int
    protocol: TransportProtocol = TransportProtocol.TCP
    state: PortState = PortState.OPEN
    reason: str = ""
    tool_id: str = ""
    source: str = ""
    confidence: float = 1.0
    target_id: str | None = None
    observed_at: str = field(default_factory=utcnow_iso)
    execution_id: str = ""
    correlation_id: str = ""
    record_id: str = field(default_factory=generate_id, kw_only=True)

    def __post_init__(self) -> None:
        object.__setattr__(self, "address", _normalize_address(self.address))
        object.__setattr__(self, "port", _clamp_port(self.port))
        object.__setattr__(self, "protocol", TransportProtocol(str(self.protocol).lower()))

    def key(self) -> str:
        """Return the canonical deduplication key for this port."""
        return f"port:{self.address}|{self.protocol.value}|{self.port}"

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe dictionary for pipeline serialization."""
        return {
            "type": OBSERVATION_PORT,
            "record_id": self.record_id,
            "address": self.address,
            "port": self.port,
            "protocol": self.protocol.value,
            "state": self.state.value,
            "reason": self.reason,
            "tool_id": self.tool_id,
            "source": self.source,
            "confidence": self.confidence,
            "target_id": self.target_id,
            "observed_at": self.observed_at,
            "execution_id": self.execution_id,
            "correlation_id": self.correlation_id,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> PortFinding:
        """Rebuild a port from a :meth:`to_dict` payload."""
        return cls(
            address=str(payload["address"]),
            port=int(_optional_int(payload.get("port"), 0) or 0),
            protocol=_parse_protocol(payload.get("protocol")),
            state=_parse_port_state(payload.get("state")),
            reason=str(payload.get("reason") or ""),
            tool_id=str(payload.get("tool_id") or ""),
            source=str(payload.get("source") or ""),
            confidence=float(payload.get("confidence") or 1.0),
            target_id=payload.get("target_id"),
            observed_at=str(payload.get("observed_at") or utcnow_iso()),
            execution_id=str(payload.get("execution_id") or ""),
            correlation_id=str(payload.get("correlation_id") or ""),
            record_id=str(payload.get("record_id") or generate_id()),
        )


@dataclass(frozen=True, slots=True)
class ServiceFinding:
    """A canonical service fingerprint observation.

    Attributes:
        address: canonical (compressed) IPv4/IPv6 address.
        port: port number.
        protocol: transport protocol.
        service: canonical service name (``ssh``, ``http``, ``smtp``...).
        product: vendor/product string when fingerprinted.
        version: software version when the evidence supports it.
        extrainfo: additional fingerprint metadata.
        banner: raw service banner (evidence, preserved verbatim).
        fingerprint_method: how the service was identified (``probed``,
            ``matched``, ``syn-ack``, ``unknown``).
        confidence: detection confidence in ``[0, 1]``.
        evidence: extra evidence fragments.
        tool_id: the tool that produced the observation.
        source: upstream source of the observation.
        target_id: owning target record id when in-scope.
        observed_at: UTC ISO-8601 observation timestamp.
        execution_id: owning execution id.
        correlation_id: correlation id shared by the run.
        record_id: stable identifier for this observation.

    """

    address: str
    port: int
    protocol: TransportProtocol = TransportProtocol.TCP
    service: str = ""
    product: str = ""
    version: str = ""
    extrainfo: str = ""
    banner: str = ""
    fingerprint_method: str = "unknown"
    confidence: float = 1.0
    evidence: tuple[str, ...] = ()
    tool_id: str = ""
    source: str = ""
    target_id: str | None = None
    observed_at: str = field(default_factory=utcnow_iso)
    execution_id: str = ""
    correlation_id: str = ""
    record_id: str = field(default_factory=generate_id, kw_only=True)

    def __post_init__(self) -> None:
        object.__setattr__(self, "address", _normalize_address(self.address))
        object.__setattr__(self, "port", _clamp_port(self.port))
        object.__setattr__(self, "protocol", TransportProtocol(str(self.protocol).lower()))
        object.__setattr__(self, "service", str(self.service).strip().lower())

    def key(self) -> str:
        """Return the canonical deduplication key for this service."""
        return f"service:{self.address}|{self.protocol.value}|{self.port}|{self.service}"

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe dictionary for pipeline serialization."""
        return {
            "type": OBSERVATION_SERVICE,
            "record_id": self.record_id,
            "address": self.address,
            "port": self.port,
            "protocol": self.protocol.value,
            "service": self.service,
            "product": self.product,
            "version": self.version,
            "extrainfo": self.extrainfo,
            "banner": self.banner,
            "fingerprint_method": self.fingerprint_method,
            "confidence": self.confidence,
            "evidence": list(self.evidence),
            "tool_id": self.tool_id,
            "source": self.source,
            "target_id": self.target_id,
            "observed_at": self.observed_at,
            "execution_id": self.execution_id,
            "correlation_id": self.correlation_id,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> ServiceFinding:
        """Rebuild a service from a :meth:`to_dict` payload."""
        return cls(
            address=str(payload["address"]),
            port=int(_optional_int(payload.get("port"), 0) or 0),
            protocol=_parse_protocol(payload.get("protocol")),
            service=str(payload.get("service") or ""),
            product=str(payload.get("product") or ""),
            version=str(payload.get("version") or ""),
            extrainfo=str(payload.get("extrainfo") or ""),
            banner=str(payload.get("banner") or ""),
            fingerprint_method=str(payload.get("fingerprint_method") or "unknown"),
            confidence=float(payload.get("confidence") or 1.0),
            evidence=tuple(str(item) for item in payload.get("evidence") or ()),
            tool_id=str(payload.get("tool_id") or ""),
            source=str(payload.get("source") or ""),
            target_id=payload.get("target_id"),
            observed_at=str(payload.get("observed_at") or utcnow_iso()),
            execution_id=str(payload.get("execution_id") or ""),
            correlation_id=str(payload.get("correlation_id") or ""),
            record_id=str(payload.get("record_id") or generate_id()),
        )


@dataclass(frozen=True, slots=True)
class TlsFinding:
    """Non-invasive TLS metadata collected from a detected TLS service.

    Only passively observable certificate metadata is collected; no
    cryptographic attack is ever performed.

    Attributes:
        address: canonical (compressed) IPv4/IPv6 address.
        port: port number.
        subject: certificate subject CN.
        issuer: certificate issuer CN.
        serial: certificate serial number.
        sha256: SHA-256 certificate fingerprint (lowercase hex).
        san: Subject Alternative Names.
        not_before: validity start (ISO).
        not_after: validity end (ISO).
        tls_version: negotiated/offered TLS version.
        ciphers: observed cipher suites.
        tool_id: the tool that produced the observation.
        source: upstream source of the observation.
        confidence: detection confidence in ``[0, 1]``.
        target_id: owning target record id when in-scope.
        observed_at: UTC ISO-8601 observation timestamp.
        execution_id: owning execution id.
        correlation_id: correlation id shared by the run.
        record_id: stable identifier for this observation.

    """

    address: str
    port: int
    subject: str = ""
    issuer: str = ""
    serial: str = ""
    sha256: str = ""
    san: tuple[str, ...] = ()
    not_before: str = ""
    not_after: str = ""
    tls_version: str = ""
    ciphers: tuple[str, ...] = ()
    tool_id: str = ""
    source: str = ""
    confidence: float = 1.0
    target_id: str | None = None
    observed_at: str = field(default_factory=utcnow_iso)
    execution_id: str = ""
    correlation_id: str = ""
    record_id: str = field(default_factory=generate_id, kw_only=True)

    def __post_init__(self) -> None:
        object.__setattr__(self, "address", _normalize_address(self.address))
        object.__setattr__(self, "port", _clamp_port(self.port))
        object.__setattr__(self, "sha256", str(self.sha256).strip().lower())

    def key(self) -> str:
        """Return the canonical deduplication key for this TLS observation."""
        return f"tls:{self.address}|{self.port}|{self.sha256}"

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe dictionary for pipeline serialization."""
        return {
            "type": OBSERVATION_TLS,
            "record_id": self.record_id,
            "address": self.address,
            "port": self.port,
            "subject": self.subject,
            "issuer": self.issuer,
            "serial": self.serial,
            "sha256": self.sha256,
            "san": list(self.san),
            "not_before": self.not_before,
            "not_after": self.not_after,
            "tls_version": self.tls_version,
            "ciphers": list(self.ciphers),
            "tool_id": self.tool_id,
            "source": self.source,
            "confidence": self.confidence,
            "target_id": self.target_id,
            "observed_at": self.observed_at,
            "execution_id": self.execution_id,
            "correlation_id": self.correlation_id,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> TlsFinding:
        """Rebuild a TLS observation from a :meth:`to_dict` payload."""
        return cls(
            address=str(payload["address"]),
            port=int(_optional_int(payload.get("port"), 0) or 0),
            subject=str(payload.get("subject") or ""),
            issuer=str(payload.get("issuer") or ""),
            serial=str(payload.get("serial") or ""),
            sha256=str(payload.get("sha256") or ""),
            san=tuple(str(item) for item in payload.get("san") or ()),
            not_before=str(payload.get("not_before") or ""),
            not_after=str(payload.get("not_after") or ""),
            tls_version=str(payload.get("tls_version") or ""),
            ciphers=tuple(str(item) for item in payload.get("ciphers") or ()),
            tool_id=str(payload.get("tool_id") or ""),
            source=str(payload.get("source") or ""),
            confidence=float(payload.get("confidence") or 1.0),
            target_id=payload.get("target_id"),
            observed_at=str(payload.get("observed_at") or utcnow_iso()),
            execution_id=str(payload.get("execution_id") or ""),
            correlation_id=str(payload.get("correlation_id") or ""),
            record_id=str(payload.get("record_id") or generate_id()),
        )


@dataclass(frozen=True, slots=True)
class HttpFinding:
    """Basic service-level HTTP intelligence.

    Only the service surface is recorded (scheme, host, port, status, server
    metadata, redirect target and safely observable technology hints). Web
    crawling is explicitly out of scope for this capability.

    Attributes:
        address: canonical (compressed) IPv4/IPv6 address.
        port: port number.
        scheme: ``http`` or ``https``.
        host: the Host header / target hostname.
        status_code: HTTP status code (``None`` when not observable).
        server: ``Server`` header value.
        title: document title when trivially available.
        redirect_target: ``Location`` header value (empty when none).
        tech_hints: safely observable technology hints.
        tool_id: the tool that produced the observation.
        source: upstream source of the observation.
        target_id: owning target record id when in-scope.
        observed_at: UTC ISO-8601 observation timestamp.
        execution_id: owning execution id.
        correlation_id: correlation id shared by the run.
        record_id: stable identifier for this observation.

    """

    address: str
    port: int
    scheme: str = "http"
    host: str = ""
    status_code: int | None = None
    server: str = ""
    title: str = ""
    redirect_target: str = ""
    tech_hints: tuple[str, ...] = ()
    confidence: float = 1.0
    tool_id: str = ""
    source: str = ""
    target_id: str | None = None
    observed_at: str = field(default_factory=utcnow_iso)
    execution_id: str = ""
    correlation_id: str = ""
    record_id: str = field(default_factory=generate_id, kw_only=True)

    def __post_init__(self) -> None:
        object.__setattr__(self, "address", _normalize_address(self.address))
        object.__setattr__(self, "port", _clamp_port(self.port))
        object.__setattr__(self, "scheme", str(self.scheme).strip().lower())
        object.__setattr__(self, "host", _normalize_hostname(self.host))

    def key(self) -> str:
        """Return the canonical deduplication key for this HTTP observation."""
        return f"http:{self.address}|{self.port}|{self.scheme}"

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe dictionary for pipeline serialization."""
        return {
            "type": OBSERVATION_HTTP,
            "record_id": self.record_id,
            "address": self.address,
            "port": self.port,
            "scheme": self.scheme,
            "host": self.host,
            "status_code": self.status_code,
            "server": self.server,
            "title": self.title,
            "redirect_target": self.redirect_target,
            "tech_hints": list(self.tech_hints),
            "confidence": self.confidence,
            "tool_id": self.tool_id,
            "source": self.source,
            "target_id": self.target_id,
            "observed_at": self.observed_at,
            "execution_id": self.execution_id,
            "correlation_id": self.correlation_id,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> HttpFinding:
        """Rebuild an HTTP observation from a :meth:`to_dict` payload."""
        return cls(
            address=str(payload["address"]),
            port=int(_optional_int(payload.get("port"), 0) or 0),
            scheme=str(payload.get("scheme") or "http"),
            host=str(payload.get("host") or ""),
            status_code=_optional_int(payload.get("status_code")),
            server=str(payload.get("server") or ""),
            title=str(payload.get("title") or ""),
            redirect_target=str(payload.get("redirect_target") or ""),
            tech_hints=tuple(str(item) for item in payload.get("tech_hints") or ()),
            confidence=float(payload.get("confidence") or 1.0),
            tool_id=str(payload.get("tool_id") or ""),
            source=str(payload.get("source") or ""),
            target_id=payload.get("target_id"),
            observed_at=str(payload.get("observed_at") or utcnow_iso()),
            execution_id=str(payload.get("execution_id") or ""),
            correlation_id=str(payload.get("correlation_id") or ""),
            record_id=str(payload.get("record_id") or generate_id()),
        )


@dataclass(frozen=True, slots=True)
class ReachabilityResult:
    """The outcome of probing a single host for reachability.

    Attributes:
        address: canonical (compressed) IPv4/IPv6 address.
        reachable: whether the host responded.
        method: reachability method used.
        rtt_ms: round-trip latency in milliseconds.
        error: error message when the probe failed.
        observed_at: UTC ISO-8601 observation timestamp.

    """

    address: str
    reachable: bool
    method: ReachabilityMethod = ReachabilityMethod.TCP_CONNECT
    rtt_ms: int = 0
    error: str = ""
    observed_at: str = field(default_factory=utcnow_iso)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe dictionary for reporting."""
        return {
            "address": self.address,
            "reachable": self.reachable,
            "method": self.method.value,
            "rtt_ms": self.rtt_ms,
            "error": self.error,
            "observed_at": self.observed_at,
        }


@dataclass(frozen=True, slots=True)
class LiveChange:
    """A detected difference between historical and current discovery state.

    Attributes:
        kind: observation kind affected (``host``, ``port``, ``service``,
            ``tls``).
        key: canonical key of the affected observation.
        change_type: ``added``, ``removed`` or ``changed``.
        previous: previous value (empty for added observations).
        current: current value (empty for removed observations).
        detected_at: UTC ISO-8601 detection timestamp.
        source: tool that produced the current observation.
        details: extra change context (e.g. old/new version).

    """

    kind: str
    key: str
    change_type: str
    previous: str = ""
    current: str = ""
    detected_at: str = field(default_factory=utcnow_iso)
    source: str = ""
    details: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe dictionary for reporting."""
        return {
            "kind": self.kind,
            "key": self.key,
            "change_type": self.change_type,
            "previous": self.previous,
            "current": self.current,
            "detected_at": self.detected_at,
            "source": self.source,
            "details": dict(self.details),
        }


@dataclass(frozen=True, slots=True)
class DiscoveryConflict:
    """A disagreement between tools about the same observation.

    Conflicts are never silently overwritten: every observation, its source,
    tool, timestamp and method are preserved alongside the canonical choice
    and the reason it was selected.

    Attributes:
        kind: observation kind affected (``port``, ``service``, ``tls``).
        key: canonical key of the affected observation.
        observations: the disagreeing observations with provenance.
        reason: human-readable explanation of the selection.
        selected: the canonical value selected.
        confidence: confidence in the selected value in ``[0, 1]``.
        detected_at: UTC ISO-8601 detection timestamp.

    """

    kind: str
    key: str
    observations: tuple[dict[str, Any], ...] = ()
    reason: str = ""
    selected: str = ""
    confidence: float = 0.0
    detected_at: str = field(default_factory=utcnow_iso)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe dictionary for reporting."""
        return {
            "kind": self.kind,
            "key": self.key,
            "observations": [dict(obs) for obs in self.observations],
            "reason": self.reason,
            "selected": self.selected,
            "confidence": self.confidence,
            "detected_at": self.detected_at,
        }


@dataclass(frozen=True, slots=True)
class LiveExecutionSummary:
    """Outcome of running one discovery tool through the execution engine.

    Attributes:
        tool_id: the tool executed.
        status: terminal execution status value.
        records: number of observations produced.
        hosts: number of host observations.
        ports: number of port observations.
        services: number of service observations.
        duration_ms: execution duration in milliseconds.
        error: error message when the execution failed.

    """

    tool_id: str
    status: str
    records: int = 0
    hosts: int = 0
    ports: int = 0
    services: int = 0
    duration_ms: int = 0
    error: str = ""


@dataclass(slots=True)
class LiveBatch:
    """The result of one live host & service discovery run.

    Aggregates the correlated hosts, ports, services, TLS and HTTP
    observations, the reachability outcomes, changes, conflicts and the run's
    identity.

    Attributes:
        mission_id: owning mission id (empty for ad-hoc runs).
        correlation_id: correlation id shared by every execution in the run.
        target: the target analysed.
        mode: the execution posture used.
        hosts: canonical host observations.
        ports: canonical port observations.
        services: canonical service observations.
        tls: TLS metadata observations.
        http: HTTP service observations.
        reachability: per-address reachability outcomes.
        changes: historical changes detected.
        conflicts: conflicting observations recorded.
        executions: per-tool execution summaries.
        created_at: UTC ISO-8601 run timestamp.
        batch_id: stable identifier for this run.

    """

    mission_id: str
    correlation_id: str
    target: LiveTarget
    mode: ReconMode = ReconMode.HYBRID
    hosts: list[LiveHost] = field(default_factory=list)
    ports: list[PortFinding] = field(default_factory=list)
    services: list[ServiceFinding] = field(default_factory=list)
    tls: list[TlsFinding] = field(default_factory=list)
    http: list[HttpFinding] = field(default_factory=list)
    reachability: list[ReachabilityResult] = field(default_factory=list)
    changes: list[LiveChange] = field(default_factory=list)
    conflicts: list[DiscoveryConflict] = field(default_factory=list)
    executions: list[LiveExecutionSummary] = field(default_factory=list)
    created_at: str = field(default_factory=utcnow_iso)
    batch_id: str = field(default_factory=generate_id, kw_only=True)

    def add_host(self, host: LiveHost) -> None:
        """Append a canonical host observation to the batch."""
        self.hosts.append(host)

    def add_hosts(self, hosts: list[LiveHost]) -> None:
        """Append several host observations to the batch."""
        self.hosts.extend(hosts)

    def add_port(self, port: PortFinding) -> None:
        """Append a canonical port observation to the batch."""
        self.ports.append(port)

    def add_ports(self, ports: list[PortFinding]) -> None:
        """Append several port observations to the batch."""
        self.ports.extend(ports)

    def add_service(self, service: ServiceFinding) -> None:
        """Append a canonical service observation to the batch."""
        self.services.append(service)

    def add_services(self, services: list[ServiceFinding]) -> None:
        """Append several service observations to the batch."""
        self.services.extend(services)

    def add_tls(self, tls: TlsFinding) -> None:
        """Append a TLS metadata observation to the batch."""
        self.tls.append(tls)

    def add_http(self, http: HttpFinding) -> None:
        """Append an HTTP service observation to the batch."""
        self.http.append(http)

    def add_reachability(self, result: ReachabilityResult) -> None:
        """Append a reachability outcome to the batch."""
        self.reachability.append(result)

    def add_change(self, change: LiveChange) -> None:
        """Append a historical change to the batch."""
        self.changes.append(change)

    def add_conflict(self, conflict: DiscoveryConflict) -> None:
        """Append a discovery conflict to the batch."""
        self.conflicts.append(conflict)

    def add_execution(self, summary: LiveExecutionSummary) -> None:
        """Append an execution summary to the batch."""
        self.executions.append(summary)

    def host_count(self) -> int:
        """Return the number of canonical host observations."""
        return len(self.hosts)

    def port_count(self) -> int:
        """Return the number of canonical port observations."""
        return len(self.ports)

    def open_port_count(self) -> int:
        """Return the number of open ports."""
        return sum(1 for port in self.ports if port.state is PortState.OPEN)

    def service_count(self) -> int:
        """Return the number of canonical service observations."""
        return len(self.services)

    def distinct(self) -> int:
        """Return the number of unique observations (by canonical key)."""
        keys = {host.key() for host in self.hosts}
        keys.update(port.key() for port in self.ports)
        keys.update(service.key() for service in self.services)
        return len(keys)

    def total_records(self) -> int:
        """Return the total number of canonical observations in the batch."""
        return len(self.hosts) + len(self.ports) + len(self.services) + len(self.tls) + len(self.http)


# -- observation factories --------------------------------------------------


def make_host(
    address: str,
    *,
    ip_version: int | None = None,
    hostname: str = "",
    state: HostState | str = HostState.UNKNOWN,
    reachable: bool | None = None,
    methods: tuple[ReachabilityMethod | str, ...] = (),
    rtt_ms: int = 0,
    tool_id: str = "",
    source: str = "",
    confidence: float = 1.0,
    target_id: str | None = None,
    execution_id: str = "",
    correlation_id: str = "",
    observed_at: str | None = None,
) -> LiveHost:
    """Build a :class:`LiveHost` with the given address and state."""
    return LiveHost(
        address=address,
        ip_version=ip_version or infer_ip_version(address),
        hostname=hostname,
        state=_parse_host_state(state),
        reachable=reachable,
        methods=tuple(_parse_method(value) for value in methods),
        rtt_ms=rtt_ms,
        tool_id=tool_id,
        source=source,
        confidence=confidence,
        target_id=target_id,
        execution_id=execution_id,
        correlation_id=correlation_id,
        observed_at=observed_at or utcnow_iso(),
    )


def make_port(
    address: str,
    port: int,
    *,
    protocol: TransportProtocol | str = TransportProtocol.TCP,
    state: PortState | str = PortState.OPEN,
    reason: str = "",
    tool_id: str = "",
    source: str = "",
    confidence: float = 1.0,
    target_id: str | None = None,
    execution_id: str = "",
    correlation_id: str = "",
    observed_at: str | None = None,
) -> PortFinding:
    """Build a :class:`PortFinding` with the given address and port."""
    return PortFinding(
        address=address,
        port=port,
        protocol=_parse_protocol(protocol),
        state=_parse_port_state(state),
        reason=reason,
        tool_id=tool_id,
        source=source,
        confidence=confidence,
        target_id=target_id,
        execution_id=execution_id,
        correlation_id=correlation_id,
        observed_at=observed_at or utcnow_iso(),
    )


def make_service(
    address: str,
    port: int,
    service: str,
    *,
    protocol: TransportProtocol | str = TransportProtocol.TCP,
    product: str = "",
    version: str = "",
    extrainfo: str = "",
    banner: str = "",
    fingerprint_method: str = "unknown",
    evidence: tuple[str, ...] = (),
    confidence: float = 1.0,
    tool_id: str = "",
    source: str = "",
    target_id: str | None = None,
    execution_id: str = "",
    correlation_id: str = "",
    observed_at: str | None = None,
) -> ServiceFinding:
    """Build a :class:`ServiceFinding` with the given service name."""
    return ServiceFinding(
        address=address,
        port=port,
        protocol=_parse_protocol(protocol),
        service=service,
        product=product,
        version=version,
        extrainfo=extrainfo,
        banner=banner,
        fingerprint_method=fingerprint_method,
        evidence=tuple(evidence),
        confidence=confidence,
        tool_id=tool_id,
        source=source,
        target_id=target_id,
        execution_id=execution_id,
        correlation_id=correlation_id,
        observed_at=observed_at or utcnow_iso(),
    )


def make_tls(
    address: str,
    port: int,
    *,
    subject: str = "",
    issuer: str = "",
    serial: str = "",
    sha256: str = "",
    san: tuple[str, ...] = (),
    not_before: str = "",
    not_after: str = "",
    tls_version: str = "",
    ciphers: tuple[str, ...] = (),
    tool_id: str = "",
    source: str = "",
    confidence: float = 1.0,
    target_id: str | None = None,
    execution_id: str = "",
    correlation_id: str = "",
    observed_at: str | None = None,
) -> TlsFinding:
    """Build a :class:`TlsFinding` with the given address and port."""
    return TlsFinding(
        address=address,
        port=port,
        subject=subject,
        issuer=issuer,
        serial=serial,
        sha256=sha256,
        san=tuple(san),
        not_before=not_before,
        not_after=not_after,
        tls_version=tls_version,
        ciphers=tuple(ciphers),
        tool_id=tool_id,
        source=source,
        confidence=confidence,
        target_id=target_id,
        execution_id=execution_id,
        correlation_id=correlation_id,
        observed_at=observed_at or utcnow_iso(),
    )


def make_http(
    address: str,
    port: int,
    *,
    scheme: str = "http",
    host: str = "",
    status_code: int | None = None,
    server: str = "",
    title: str = "",
    redirect_target: str = "",
    tech_hints: tuple[str, ...] = (),
    tool_id: str = "",
    source: str = "",
    target_id: str | None = None,
    execution_id: str = "",
    correlation_id: str = "",
    observed_at: str | None = None,
) -> HttpFinding:
    """Build an :class:`HttpFinding` with the given address and port."""
    return HttpFinding(
        address=address,
        port=port,
        scheme=scheme,
        host=host,
        status_code=status_code,
        server=server,
        title=title,
        redirect_target=redirect_target,
        tech_hints=tuple(tech_hints),
        tool_id=tool_id,
        source=source,
        target_id=target_id,
        execution_id=execution_id,
        correlation_id=correlation_id,
        observed_at=observed_at or utcnow_iso(),
    )


def observations_from_payload(
    payload: Mapping[str, Any] | None,
) -> tuple[list[LiveHost], list[PortFinding], list[ServiceFinding], list[TlsFinding], list[HttpFinding]]:
    """Extract canonical observations from a pipeline JSON payload.

    Live host adapters serialise their observations under the ``observations``
    key of the JSON payload they attach to the execution output. Each entry
    carries a ``type`` discriminator (``host``/``port``/``service``/``tls``/
    ``http``). This helper rebuilds the typed records so downstream services
    never touch raw dictionaries.
    """
    if not payload:
        return [], [], [], [], []
    entries = payload.get("observations")
    if not isinstance(entries, list):
        return [], [], [], [], []
    hosts: list[LiveHost] = []
    ports: list[PortFinding] = []
    services: list[ServiceFinding] = []
    tls: list[TlsFinding] = []
    http: list[HttpFinding] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        kind = entry.get("type")
        if kind == OBSERVATION_HOST:
            hosts.append(LiveHost.from_dict(entry))
        elif kind == OBSERVATION_PORT:
            ports.append(PortFinding.from_dict(entry))
        elif kind == OBSERVATION_SERVICE:
            services.append(ServiceFinding.from_dict(entry))
        elif kind == OBSERVATION_TLS:
            tls.append(TlsFinding.from_dict(entry))
        elif kind == OBSERVATION_HTTP:
            http.append(HttpFinding.from_dict(entry))
    return hosts, ports, services, tls, http


# -- parsing helpers --------------------------------------------------------


def infer_ip_version(value: str) -> int:
    """Return the IP protocol version of ``value`` (``4``/``6``)."""
    try:
        return ipaddress.ip_address(value.strip()).version
    except ValueError:
        return 4


def is_ip(value: str) -> bool:
    """Return whether ``value`` parses as an IP address."""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _normalize_address(value: str) -> str:
    """Normalize an IP address to its canonical (compressed) form."""
    candidate = str(value).strip()
    try:
        return ipaddress.ip_address(candidate).compressed
    except ValueError:
        return candidate


def _normalize_hostname(value: str) -> str:
    """Lowercase a hostname and strip its trailing dot."""
    return str(value).strip().lower().rstrip(".")


def _clamp_port(value: int) -> int:
    """Clamp a port number into the valid TCP/UDP range."""
    try:
        port = int(value)
    except (TypeError, ValueError):
        return 0
    return max(1, min(65535, port))


def _parse_host_state(value: object) -> HostState:
    try:
        return HostState(str(value).lower())
    except ValueError:
        return HostState.UNKNOWN


def _parse_port_state(value: object) -> PortState:
    try:
        return PortState(str(value).lower())
    except ValueError:
        return PortState.UNKNOWN


def _parse_protocol(value: object) -> TransportProtocol:
    try:
        return TransportProtocol(str(value).lower())
    except ValueError:
        return TransportProtocol.TCP


def _parse_method(value: object) -> ReachabilityMethod:
    try:
        return ReachabilityMethod(str(value).lower())
    except ValueError:
        return ReachabilityMethod.TCP_CONNECT


def _optional_int(value: object, default: int | None = None) -> int | None:
    if isinstance(value, bool):
        return default
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return default
    return default


def _optional_bool(value: object) -> bool | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("1", "true", "yes")
