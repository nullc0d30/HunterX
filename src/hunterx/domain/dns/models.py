# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""DNS Intelligence canonical domain models.

Pure data contracts for the DNS Intelligence capability: the canonical DNS
record every DNS tool adapter produces, zone, delegation, nameserver and
resolver descriptors, the raw observations and resolutions a run collects, the
analytical findings (wildcards, DNSSEC state, mail infrastructure), the change
and conflict records produced by historical comparison, and the batch that
carries everything back to the application layer. No I/O and no execution here.

The TIDB ``network``/``dns`` entities (:mod:`hunterx.domain.entities.tidb`)
are the persistence projection of these models; this module is the runtime
surface the DNS pipeline is built on.
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


class DnsRecordType(StrEnum):
    """Canonical DNS resource-record types the capability understands."""

    A = "A"
    AAAA = "AAAA"
    CNAME = "CNAME"
    MX = "MX"
    NS = "NS"
    TXT = "TXT"
    SOA = "SOA"
    PTR = "PTR"
    SRV = "SRV"
    CAA = "CAA"
    DS = "DS"
    DNSKEY = "DNSKEY"
    RRSIG = "RRSIG"
    NSEC = "NSEC"
    NSEC3 = "NSEC3"
    TLSA = "TLSA"
    NAPTR = "NAPTR"
    ANY = "ANY"
    OTHER = "OTHER"


#: Record types DNSx can query through its CLI (used by the strategy layer).
DNSX_QUERYABLE: frozenset[DnsRecordType] = frozenset(
    {
        DnsRecordType.A,
        DnsRecordType.AAAA,
        DnsRecordType.CNAME,
        DnsRecordType.MX,
        DnsRecordType.NS,
        DnsRecordType.TXT,
        DnsRecordType.SOA,
        DnsRecordType.PTR,
        DnsRecordType.SRV,
        DnsRecordType.CAA,
        DnsRecordType.DS,
        DnsRecordType.DNSKEY,
        DnsRecordType.ANY,
    }
)


def _parse_record_type(value: object) -> DnsRecordType:
    """Coerce a record-type string into a :class:`DnsRecordType`."""
    name = str(value or "OTHER").strip().upper()
    try:
        return DnsRecordType(name)
    except ValueError:
        return DnsRecordType.OTHER


@dataclass(frozen=True, slots=True)
class DnsTarget:
    """A single DNS intelligence target.

    Attributes:
        value: canonical target identifier (a domain, hostname or IP address).
        target_type: canonical target kind (``domain``, ``host``, ``ip``).
        target_id: owning target record id when the target is persisted.

    """

    value: str
    target_type: str = "domain"
    target_id: str = ""


@dataclass(frozen=True, slots=True)
class DnsRecord:
    """A single canonical DNS resource record observation.

    Attributes:
        name: record owner name, normalized (lowercase, no trailing dot).
        record_type: the resource-record type.
        value: normalized record data (rdata).
        raw_value: the value exactly as observed (preserved verbatim).
        ttl: time-to-live in seconds (``None`` when not observed).
        priority: MX/SRV preference (``None`` when not applicable).
        source: upstream source of the observation (resolver, zone, db...).
        tool_id: the tool that produced the observation.
        resolver: resolver address the query went through.
        observed_at: UTC ISO-8601 observation timestamp.
        execution_id: owning execution id (empty for ad-hoc observations).
        correlation_id: correlation id shared by the run.
        target_id: owning target record id when in-scope.
        validation_status: ``valid``, ``invalid`` or ``unknown``.
        confidence: detection confidence in ``[0, 1]``.
        record_id: stable identifier for this observation.

    """

    name: str
    record_type: DnsRecordType
    value: str
    raw_value: str = ""
    ttl: int | None = None
    priority: int | None = None
    source: str = ""
    tool_id: str = ""
    resolver: str = ""
    observed_at: str = field(default_factory=utcnow_iso)
    execution_id: str = ""
    correlation_id: str = ""
    target_id: str | None = None
    validation_status: str = "unknown"
    confidence: float = 1.0
    record_id: str = field(default_factory=generate_id, kw_only=True)

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise ValueError("dns record name must not be empty")
        object.__setattr__(self, "name", _normalize_name(self.name))
        object.__setattr__(self, "value", str(self.value).strip())

    def key(self) -> str:
        """Return the canonical deduplication key for this record.

        Two records from different tools/resolvers describe the same resource
        record when they share this key, so correlators can merge them.
        """
        return f"dns:{self.name}|{self.record_type.value}|{self.value}"

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe dictionary for pipeline serialization."""
        return {
            "record_id": self.record_id,
            "name": self.name,
            "record_type": self.record_type.value,
            "value": self.value,
            "raw_value": self.raw_value,
            "ttl": self.ttl,
            "priority": self.priority,
            "source": self.source,
            "tool_id": self.tool_id,
            "resolver": self.resolver,
            "observed_at": self.observed_at,
            "execution_id": self.execution_id,
            "correlation_id": self.correlation_id,
            "target_id": self.target_id,
            "validation_status": self.validation_status,
            "confidence": self.confidence,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> DnsRecord:
        """Rebuild a record from a :meth:`to_dict` payload."""
        return cls(
            name=str(payload["name"]),
            record_type=_parse_record_type(payload.get("record_type")),
            value=str(payload.get("value") or ""),
            raw_value=str(payload.get("raw_value") or ""),
            ttl=_optional_int(payload.get("ttl")),
            priority=_optional_int(payload.get("priority")),
            source=str(payload.get("source") or ""),
            tool_id=str(payload.get("tool_id") or ""),
            resolver=str(payload.get("resolver") or ""),
            observed_at=str(payload.get("observed_at") or utcnow_iso()),
            execution_id=str(payload.get("execution_id") or ""),
            correlation_id=str(payload.get("correlation_id") or ""),
            target_id=payload.get("target_id"),
            validation_status=str(payload.get("validation_status") or "unknown"),
            confidence=float(payload.get("confidence") or 1.0),
            record_id=str(payload.get("record_id") or generate_id()),
        )


@dataclass(frozen=True, slots=True)
class DNSZone:
    """Authoritative zone metadata derived from SOA/NS observations.

    Attributes:
        name: zone name (lowercase, no trailing dot).
        primary_ns: primary nameserver from the SOA MNAME.
        admin_mail: administrative contact (SOA RNAME).
        serial: zone serial number.
        refresh: SOA refresh interval in seconds.
        retry: SOA retry interval in seconds.
        expire: SOA expire interval in seconds.
        minimum: SOA minimum TTL in seconds.
        ttl: zone-level TTL in seconds.
        nameservers: authoritative nameserver names.
        observed_at: UTC ISO-8601 observation timestamp.

    """

    name: str
    primary_ns: str = ""
    admin_mail: str = ""
    serial: int | None = None
    refresh: int | None = None
    retry: int | None = None
    expire: int | None = None
    minimum: int | None = None
    ttl: int | None = None
    nameservers: tuple[str, ...] = ()
    observed_at: str = field(default_factory=utcnow_iso)


@dataclass(frozen=True, slots=True)
class Nameserver:
    """A nameserver observed for a zone or delegation.

    Attributes:
        name: nameserver FQDN (lowercase).
        addresses: resolved IP addresses.
        owner_domain: the zone this nameserver is authoritative for.
        is_authoritative: whether the nameserver answered authoritatively.
        observed_at: UTC ISO-8601 observation timestamp.

    """

    name: str
    addresses: tuple[str, ...] = ()
    owner_domain: str = ""
    is_authoritative: bool = True
    observed_at: str = field(default_factory=utcnow_iso)


@dataclass(frozen=True, slots=True)
class DNSDelegation:
    """A delegation of a subdomain to a set of authoritative nameservers.

    Attributes:
        name: delegated subdomain name.
        nameservers: authoritative nameserver names for the delegation.
        glue_records: in-zone glue A/AAAA records.
        is_delegated: whether the subdomain is delegated out of the parent.
        observed_at: UTC ISO-8601 observation timestamp.

    """

    name: str
    nameservers: tuple[str, ...] = ()
    glue_records: tuple[tuple[str, str], ...] = ()
    is_delegated: bool = True
    observed_at: str = field(default_factory=utcnow_iso)


@dataclass(frozen=True, slots=True)
class Resolver:
    """A DNS resolver the capability queries through.

    Attributes:
        address: resolver address (``1.1.1.1`` or ``udp:1.1.1.1:53``).
        protocol: transport (``udp``, ``tcp``, ``dot``, ``doh``).
        rtt_ms: round-trip time of the last probe.
        status: probe outcome (``ok``, ``unreachable``, ``error``).
        error: probe error message when the resolver failed.

    """

    address: str
    protocol: str = "udp"
    rtt_ms: int = 0
    status: str = "ok"
    error: str = ""


@dataclass(frozen=True, slots=True)
class DNSObservation:
    """A single raw answer for a DNS question before normalization.

    Attributes:
        name: queried owner name.
        record_type: queried record type.
        value: answer rdata as observed (may differ from the canonical form).
        ttl: TTL as observed.
        rcode: DNS response code (``NOERROR``, ``NXDOMAIN``, ``SERVFAIL``...).
        resolver: resolver that answered.
        tool_id: tool that produced the observation.
        source: upstream source.
        raw: the full raw response/line this answer came from.
        observed_at: UTC ISO-8601 observation timestamp.
        execution_id: owning execution id.

    """

    name: str
    record_type: DnsRecordType
    value: str = ""
    ttl: int | None = None
    rcode: str = "NOERROR"
    resolver: str = ""
    tool_id: str = ""
    source: str = ""
    raw: str = ""
    observed_at: str = field(default_factory=utcnow_iso)
    execution_id: str = ""


@dataclass(frozen=True, slots=True)
class DNSResolution:
    """The outcome of resolving one name through a resolver.

    Attributes:
        name: the queried name.
        status: resolution status (``resolved``, ``nxdomain``, ``servfail``,
            ``refused``, ``timeout``, ``error``).
        record_types: record types that answered.
        addresses: resolved IP addresses.
        cnames: CNAME chain targets.
        rcode: DNS response code.
        resolver: resolver that answered.
        duration_ms: resolution latency in milliseconds.
        wildcard: whether the answer matched a wildcard pattern.
        error: error message when resolution failed.

    """

    name: str
    status: str = "resolved"
    record_types: tuple[str, ...] = ()
    addresses: tuple[str, ...] = ()
    cnames: tuple[str, ...] = ()
    rcode: str = "NOERROR"
    resolver: str = ""
    duration_ms: int = 0
    wildcard: bool = False
    error: str = ""


@dataclass(frozen=True, slots=True)
class WildcardFinding:
    """A detected wildcard DNS behaviour for a zone.

    Attributes:
        domain: the zone exhibiting wildcard behaviour.
        pattern: the wildcard pattern (``*.example.com`` when detected).
        is_wildcard: whether a wildcard answer was observed.
        affected_names: names that hit the wildcard.
        resolver: resolver the detection was observed through.
        evidence: raw answers that constitute the evidence.
        confidence: detection confidence in ``[0, 1]``.
        observed_at: UTC ISO-8601 observation timestamp.

    """

    domain: str
    pattern: str = ""
    is_wildcard: bool = False
    affected_names: tuple[str, ...] = ()
    resolver: str = ""
    evidence: tuple[str, ...] = ()
    confidence: float = 0.0
    observed_at: str = field(default_factory=utcnow_iso)


@dataclass(frozen=True, slots=True)
class DNSSECInfo:
    """DNSSEC posture of a zone.

    Attributes:
        domain: the zone analysed.
        enabled: whether DNSSEC is enabled (DS + DNSKEY material observed).
        has_ds: DS records observed in the parent.
        has_dnskey: DNSKEY records observed in the zone.
        has_rrsig: RRSIG records observed.
        has_nsec: NSEC records observed.
        has_nsec3: NSEC3 records observed.
        validation_state: ``signed``, ``unsigned``, ``inconsistent`` or ``unknown``.
        inconsistencies: human-readable inconsistencies found.
        records: raw DNSSEC record observations.
        observed_at: UTC ISO-8601 observation timestamp.

    """

    domain: str
    enabled: bool = False
    has_ds: bool = False
    has_dnskey: bool = False
    has_rrsig: bool = False
    has_nsec: bool = False
    has_nsec3: bool = False
    validation_state: str = "unknown"
    inconsistencies: tuple[str, ...] = ()
    records: tuple[DnsRecord, ...] = ()
    observed_at: str = field(default_factory=utcnow_iso)


@dataclass(frozen=True, slots=True)
class MailInfrastructure:
    """Mail routing and policy posture of a domain.

    Attributes:
        domain: the domain analysed.
        mx_hosts: canonical MX exchange hosts (in preference order).
        mx_providers: identified mail providers/infrastructure vendors.
        spf_record: the published SPF TXT record (raw).
        spf_analysis: machine-readable SPF analysis.
        dmarc_record: the published DMARC TXT record (raw).
        dmarc_analysis: machine-readable DMARC analysis.
        dkim_records: discovered DKIM records keyed by selector.
        dkim_selectors: DKIM selectors found.
        provider: primary identified mail provider.
        notes: additional observations.
        observed_at: UTC ISO-8601 observation timestamp.

    """

    domain: str
    mx_hosts: tuple[str, ...] = ()
    mx_providers: tuple[str, ...] = ()
    spf_record: str = ""
    spf_analysis: dict[str, str] = field(default_factory=dict)
    dmarc_record: str = ""
    dmarc_analysis: dict[str, str] = field(default_factory=dict)
    dkim_records: dict[str, str] = field(default_factory=dict)
    dkim_selectors: tuple[str, ...] = ()
    provider: str = ""
    notes: tuple[str, ...] = ()
    observed_at: str = field(default_factory=utcnow_iso)


@dataclass(frozen=True, slots=True)
class DNSChange:
    """A detected difference between historical and current DNS state.

    Attributes:
        name: the record owner name affected.
        record_type: the record type affected.
        change_type: ``new``, ``removed`` or ``changed``.
        old_value: previous value (empty for new records).
        new_value: current value (empty for removed records).
        detected_at: UTC ISO-8601 detection timestamp.
        tool_id: tool that produced the current observation.
        confidence: confidence in the change in ``[0, 1]``.

    """

    name: str
    record_type: DnsRecordType
    change_type: str
    old_value: str = ""
    new_value: str = ""
    detected_at: str = field(default_factory=utcnow_iso)
    tool_id: str = ""
    confidence: float = 1.0


@dataclass(frozen=True, slots=True)
class DNSConflict:
    """A conflicting observation between sources, resolvers or tools.

    Attributes:
        name: the record owner name that conflicted.
        record_type: the record type that conflicted.
        observations: the disagreeing observations (raw values by source).
        conflict_type: ``value``, ``presence`` or ``rcode``.
        selected_value: the canonical value selected.
        selected_source: the source the canonical value came from.
        reason: human-readable explanation of the selection.
        confidence: confidence in the selected value in ``[0, 1]``.
        detected_at: UTC ISO-8601 detection timestamp.

    """

    name: str
    record_type: DnsRecordType
    observations: tuple[dict[str, str], ...] = ()
    conflict_type: str = "value"
    selected_value: str = ""
    selected_source: str = ""
    reason: str = ""
    confidence: float = 0.0
    detected_at: str = field(default_factory=utcnow_iso)


@dataclass(frozen=True, slots=True)
class DnsExecutionSummary:
    """Outcome of running one DNS tool through the execution engine.

    Attributes:
        tool_id: the tool executed.
        status: terminal execution status value.
        records: number of DNS records produced.
        duration_ms: execution duration in milliseconds.
        error: error message when the execution failed.

    """

    tool_id: str
    status: str
    records: int = 0
    duration_ms: int = 0
    error: str = ""


@dataclass(slots=True)
class DnsBatch:
    """The result of one DNS intelligence run.

    Aggregates the correlated records, observations, resolutions, analytical
    findings, changes, conflicts and the run's identity.

    Attributes:
        mission_id: owning mission id (empty for ad-hoc runs).
        correlation_id: correlation id shared by every execution in the run.
        target: the target analysed.
        mode: the execution posture used.
        records: canonical (validated, normalized) DNS records.
        observations: raw observations collected before normalization.
        resolutions: per-name resolution outcomes.
        wildcards: wildcard findings.
        dnssec: DNSSEC analyses keyed by zone.
        mail: mail infrastructure analyses keyed by domain.
        changes: historical changes detected.
        conflicts: conflicting observations recorded.
        executions: per-tool execution summaries.
        created_at: UTC ISO-8601 run timestamp.
        batch_id: stable identifier for this run.

    """

    mission_id: str
    correlation_id: str
    target: DnsTarget
    mode: ReconMode = ReconMode.HYBRID
    records: list[DnsRecord] = field(default_factory=list)
    observations: list[DNSObservation] = field(default_factory=list)
    resolutions: list[DNSResolution] = field(default_factory=list)
    wildcards: list[WildcardFinding] = field(default_factory=list)
    dnssec: dict[str, DNSSECInfo] = field(default_factory=dict)
    mail: dict[str, MailInfrastructure] = field(default_factory=dict)
    changes: list[DNSChange] = field(default_factory=list)
    conflicts: list[DNSConflict] = field(default_factory=list)
    executions: list[DnsExecutionSummary] = field(default_factory=list)
    created_at: str = field(default_factory=utcnow_iso)
    batch_id: str = field(default_factory=generate_id, kw_only=True)

    def add_record(self, record: DnsRecord) -> None:
        """Append a canonical DNS record to the batch."""
        self.records.append(record)

    def add_records(self, records: list[DnsRecord]) -> None:
        """Append several canonical DNS records to the batch."""
        self.records.extend(records)

    def add_observation(self, observation: DNSObservation) -> None:
        """Append a raw observation to the batch."""
        self.observations.append(observation)

    def add_resolution(self, resolution: DNSResolution) -> None:
        """Append a resolution outcome to the batch."""
        self.resolutions.append(resolution)

    def add_execution(self, summary: DnsExecutionSummary) -> None:
        """Append an execution summary to the batch."""
        self.executions.append(summary)

    def by_type(self, record_type: DnsRecordType) -> list[DnsRecord]:
        """Return the records of a single :class:`DnsRecordType`."""
        return [record for record in self.records if record.record_type is record_type]

    def count(self) -> int:
        """Return the number of canonical records in the batch."""
        return len(self.records)

    def distinct(self) -> int:
        """Return the number of unique records (by canonical key)."""
        return len({record.key() for record in self.records})


# -- record factories -------------------------------------------------------


def make_record(
    name: str,
    record_type: DnsRecordType | str,
    value: str,
    *,
    raw_value: str = "",
    ttl: int | None = None,
    priority: int | None = None,
    source: str = "",
    tool_id: str = "",
    resolver: str = "",
    execution_id: str = "",
    correlation_id: str = "",
    target_id: str | None = None,
    confidence: float = 1.0,
    observed_at: str | None = None,
) -> DnsRecord:
    """Build a :class:`DnsRecord` with the given type and value."""
    return DnsRecord(
        name=name,
        record_type=_parse_record_type(record_type),
        value=value,
        raw_value=raw_value or value,
        ttl=ttl,
        priority=priority,
        source=source,
        tool_id=tool_id,
        resolver=resolver,
        execution_id=execution_id,
        correlation_id=correlation_id,
        target_id=target_id,
        confidence=confidence,
        observed_at=observed_at or utcnow_iso(),
    )


def records_from_payload(payload: Mapping[str, Any] | None) -> list[DnsRecord]:
    """Extract canonical DNS records from a pipeline JSON payload.

    DNS adapters serialise their records under the ``dns_records`` key of the
    JSON payload they attach to the execution output. This helper rebuilds the
    typed records so downstream services never touch raw dictionaries.
    """
    if not payload:
        return []
    records = payload.get("dns_records")
    if not isinstance(records, list):
        return []
    return [DnsRecord.from_dict(entry) for entry in records if isinstance(entry, dict)]


# -- normalization helpers --------------------------------------------------


def _normalize_name(name: str) -> str:
    """Lowercase a DNS owner name and strip its trailing dot."""
    return str(name).strip().lower().rstrip(".")


def normalize_hostname(value: str) -> str:
    """Normalize a hostname/domain (lowercase, no trailing dot)."""
    return _normalize_name(value)


def normalize_address(value: str) -> str:
    """Normalize an IP address to its canonical (compressed) form."""
    try:
        return ipaddress.ip_address(value).compressed
    except ValueError:
        return _normalize_name(value)


def _optional_int(value: object) -> int | None:
    """Return an int value or ``None`` when not numeric."""
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return None
    return None
