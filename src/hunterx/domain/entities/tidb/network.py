# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Network Target Intelligence Database entities.

DNS, addressing and service-layer entities: domains, subdomains, hostnames,
IP addresses, CIDR ranges, ASNs, DNS/WHOIS records, certificates, ports and
services. These are the recon graph that future capability waves build upon.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from hunterx.domain.entities.tidb._base import TidbEntity


class PortState(Enum):
    """Observed state of a network port."""

    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    UNKNOWN = "unknown"


class ServiceState(Enum):
    """Observed state of a service."""

    UP = "up"
    DOWN = "down"
    UNKNOWN = "unknown"


class DnsRecordType(Enum):
    """DNS record types persisted by the TIDB."""

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


@dataclass(slots=True)
class Domain(TidbEntity):
    """An authoritative or discovered DNS domain.

    Attributes:
        name: fully-qualified domain name (lowercase).
        target_id: owning target (when in-scope).
        parent_domain_id: parent domain (self-referencing hierarchy).
        is_authoritative: whether this domain is authoritatively delegated.
        registrar: optional registrar name.
        dns_servers: list of authoritative nameservers.
        mx: list of MX exchange hosts.
        txt: list of TXT records.
        dnsssec_enabled: whether DNSSEC is enabled.
        source_tool: tool that discovered the domain.
        confidence: detection confidence in ``[0, 1]``.

    """

    name: str
    target_id: str | None = None
    parent_domain_id: str | None = None
    is_authoritative: bool = False
    registrar: str | None = None
    dns_servers: list[str] = field(default_factory=list)
    mx: list[str] = field(default_factory=list)
    txt: list[str] = field(default_factory=list)
    dnsssec_enabled: bool = False
    source_tool: str | None = None
    confidence: float = 1.0


@dataclass(slots=True)
class Subdomain(TidbEntity):
    """A subdomain discovered under a parent domain.

    Attributes:
        domain_id: parent domain.
        name: subdomain FQDN (lowercase).
        resolution_confidence: confidence that the subdomain resolves.

    """

    domain_id: str
    name: str
    resolution_confidence: float = 1.0


@dataclass(slots=True)
class Hostname(TidbEntity):
    """A host name (domain/subdomain) that resolves to addresses.

    Attributes:
        name: hostname (lowercase).
        target_id: owning target when in-scope.
        is_alive: whether the host responded.
        os_hint: optional guessed operating system.

    """

    name: str
    target_id: str | None = None
    is_alive: bool | None = None
    os_hint: str | None = None


@dataclass(slots=True)
class IPAddress(TidbEntity):
    """A canonical IPv4/IPv6 address.

    Attributes:
        address: canonical string form of the address.
        ip_version: IP protocol version (4 or 6).
        target_id: owning target when in-scope.
        hostname_id: hostname this address resolves from (if known).
        cidr_id: enclosing CIDR range (if known).
        asn_id: owning autonomous system (if known).
        owner_org: owning organisation string.
        geo: optional geo-location map (``{country, city, lat, lon}``).
        is_alive: whether the address responded.

    """

    address: str
    ip_version: int = 4
    target_id: str | None = None
    hostname_id: str | None = None
    cidr_id: str | None = None
    asn_id: str | None = None
    owner_org: str | None = None
    geo: dict[str, object] = field(default_factory=dict)
    is_alive: bool | None = None


@dataclass(slots=True)
class CIDR(TidbEntity):
    """A CIDR network range.

    Attributes:
        network: canonical CIDR notation (e.g. ``10.0.0.0/24``).
        target_id: owning target when in-scope.
        asn_id: owning autonomous system when known.
        owner_org: owning organisation string.

    """

    network: str
    target_id: str | None = None
    asn_id: str | None = None
    owner_org: str | None = None


@dataclass(slots=True)
class ASN(TidbEntity):
    """An Autonomous System number and its registration data.

    Attributes:
        number: ASN number.
        name: AS name.
        org: registered organisation.
        country: registration country code.
        registry: registry (RIPE/ARIN/APNIC/...).

    """

    number: int
    name: str = ""
    org: str | None = None
    country: str | None = None
    registry: str | None = None


@dataclass(slots=True)
class DNSRecord(TidbEntity):
    """A DNS resource record.

    Attributes:
        name: record owner name.
        record_type: record type.
        value: record data (target, text, ...).
        ttl: time-to-live in seconds.
        priority: MX/SRV priority (``None`` when not applicable).
        domain_id: owning domain when known.
        subdomain_id: owning subdomain when known.

    """

    name: str
    record_type: DnsRecordType
    value: str
    ttl: int | None = None
    priority: int | None = None
    domain_id: str | None = None
    subdomain_id: str | None = None


@dataclass(slots=True)
class WHOISRecord(TidbEntity):
    """Raw and parsed WHOIS data for a domain.

    Attributes:
        domain_id: owning domain.
        raw: raw WHOIS text.
        registrar: registrar name.
        created_at_domain: domain creation date (ISO).
        expires_at_domain: domain expiry date (ISO).
        updated_at_domain: domain update date (ISO).
        nameservers: list of nameservers.

    """

    domain_id: str
    raw: str = ""
    registrar: str | None = None
    created_at_domain: str | None = None
    expires_at_domain: str | None = None
    updated_at_domain: str | None = None
    nameservers: list[str] = field(default_factory=list)


@dataclass(slots=True)
class Certificate(TidbEntity):
    """An observed TLS/SSL certificate.

    Attributes:
        hostname_id: hostname the certificate was observed on.
        subject: certificate subject CN.
        issuer: certificate issuer CN.
        serial: serial number.
        sha256: SHA-256 fingerprint.
        not_before: validity start (ISO).
        not_after: validity end (ISO).
        san: list of Subject Alternative Names.
        revoked: whether the certificate is revoked.

    """

    hostname_id: str | None = None
    subject: str | None = None
    issuer: str | None = None
    serial: str | None = None
    sha256: str | None = None
    not_before: str | None = None
    not_after: str | None = None
    san: list[str] = field(default_factory=list)
    revoked: bool = False


@dataclass(slots=True)
class Port(TidbEntity):
    """A network port observed on an IP address.

    Attributes:
        ip_address_id: owning IP address.
        number: port number.
        protocol: transport protocol (``tcp``/``udp``).
        state: observed state.
        banner: optional service banner.
        service_hint: optional guessed service name.

    """

    ip_address_id: str
    number: int
    protocol: str = "tcp"
    state: PortState = PortState.UNKNOWN
    banner: str | None = None
    service_hint: str | None = None


@dataclass(slots=True)
class Protocol(TidbEntity):
    """A transport/application protocol reference.

    Attributes:
        name: protocol name (e.g. ``tcp``, ``http``).
        description: optional description.
        port_hint: commonly associated port.

    """

    name: str
    description: str = ""
    port_hint: int | None = None


@dataclass(slots=True)
class Service(TidbEntity):
    """A service detected on a port.

    Attributes:
        port_id: owning port.
        name: service name.
        software_version: detected version string.
        state: observed state.
        banner: raw banner.
        tls_info: TLS handshake details map.
        confidence: detection confidence in ``[0, 1]``.

    """

    port_id: str
    name: str
    software_version: str | None = None
    state: ServiceState = ServiceState.UNKNOWN
    banner: str | None = None
    tls_info: dict[str, object] = field(default_factory=dict)
    confidence: float = 1.0


@dataclass(slots=True)
class DNSZone(TidbEntity):
    """Authoritative zone metadata derived from SOA/NS observations.

    Attributes:
        name: zone name (lowercase, no trailing dot).
        domain_id: owning domain when known.
        primary_ns: primary nameserver from the SOA MNAME.
        admin_mail: administrative contact (SOA RNAME).
        serial: zone serial number.
        refresh: SOA refresh interval in seconds.
        retry: SOA retry interval in seconds.
        expire: SOA expire interval in seconds.
        minimum: SOA minimum TTL in seconds.
        ttl: zone-level TTL in seconds.

    """

    name: str
    domain_id: str | None = None
    primary_ns: str | None = None
    admin_mail: str | None = None
    serial: int | None = None
    refresh: int | None = None
    retry: int | None = None
    expire: int | None = None
    minimum: int | None = None
    ttl: int | None = None


@dataclass(slots=True)
class DNSDelegation(TidbEntity):
    """A delegation of a subdomain to authoritative nameservers.

    Attributes:
        name: delegated subdomain name.
        subdomain_id: owning subdomain when known.
        nameservers: authoritative nameserver names.
        glue_records: in-zone glue A/AAAA records (name/address pairs).
        is_delegated: whether the subdomain is delegated out of the parent.

    """

    name: str
    subdomain_id: str | None = None
    nameservers: list[str] = field(default_factory=list)
    glue_records: list[tuple[str, str]] = field(default_factory=list)
    is_delegated: bool = True


@dataclass(slots=True)
class Nameserver(TidbEntity):
    """A nameserver observed for a zone or delegation.

    Attributes:
        name: nameserver FQDN (lowercase).
        addresses: resolved IP addresses.
        owner_domain: the zone this nameserver is authoritative for.
        is_authoritative: whether the nameserver answered authoritatively.

    """

    name: str
    addresses: list[str] = field(default_factory=list)
    owner_domain: str | None = None
    is_authoritative: bool = True


@dataclass(slots=True)
class Resolver(TidbEntity):
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


@dataclass(slots=True)
class MXRecord(TidbEntity):
    """A mail exchanger record.

    Attributes:
        name: owner name.
        domain_id: owning domain when known.
        preference: preference value (lower is preferred).
        exchange: exchange hostname.
        ttl: time-to-live in seconds.
        provider: identified mail provider/vendor when known.

    """

    name: str
    domain_id: str | None = None
    preference: int = 10
    exchange: str = ""
    ttl: int | None = None
    provider: str | None = None


@dataclass(slots=True)
class TXTRecord(TidbEntity):
    """A TXT record (SPF, DKIM, verification, arbitrary text).

    Attributes:
        name: owner name.
        domain_id: owning domain when known.
        value: full TXT value (fragments joined).
        ttl: time-to-live in seconds.
        purpose: best-effort classification (``spf``, ``dkim``, ``dmarc``,
            ``verification``, ``other``).

    """

    name: str
    domain_id: str | None = None
    value: str = ""
    ttl: int | None = None
    purpose: str = "other"


@dataclass(slots=True)
class CAARecord(TidbEntity):
    """A certification authority authorization record.

    Attributes:
        name: owner name.
        domain_id: owning domain when known.
        flags: CAA flags byte.
        tag: CAA tag (``issue``, ``issuewild``, ``iodef``).
        value: CAA value.
        ttl: time-to-live in seconds.

    """

    name: str
    domain_id: str | None = None
    flags: int = 0
    tag: str = "issue"
    value: str = ""
    ttl: int | None = None


@dataclass(slots=True)
class SOARecord(TidbEntity):
    """A start-of-authority record.

    Attributes:
        name: zone name.
        domain_id: owning domain when known.
        primary_ns: primary nameserver (MNAME).
        admin_mail: administrative contact (RNAME).
        serial: serial number.
        refresh: refresh interval in seconds.
        retry: retry interval in seconds.
        expire: expire interval in seconds.
        minimum: minimum TTL in seconds.
        ttl: zone-level TTL in seconds.

    """

    name: str
    domain_id: str | None = None
    primary_ns: str | None = None
    admin_mail: str | None = None
    serial: int | None = None
    refresh: int | None = None
    retry: int | None = None
    expire: int | None = None
    minimum: int | None = None
    ttl: int | None = None


@dataclass(slots=True)
class DNSSECRecord(TidbEntity):
    """A DNSSEC material record (DS, DNSKEY, RRSIG, NSEC, NSEC3, TLSA).

    Attributes:
        name: owner name.
        zone_id: owning zone when known.
        record_type: the DNSSEC record type.
        value: full rdata (whitespace collapsed).
        algorithm: DNSKEY/DS algorithm name when parseable.
        key_tag: key tag when present.
        ttl: time-to-live in seconds.
        data: structured parse map when available.

    """

    name: str
    zone_id: str | None = None
    record_type: DnsRecordType = DnsRecordType.DNSKEY
    value: str = ""
    algorithm: str | None = None
    key_tag: int | None = None
    ttl: int | None = None
    data: dict[str, object] = field(default_factory=dict)


@dataclass(slots=True)
class PTRRecord(TidbEntity):
    """A reverse-DNS pointer record.

    Attributes:
        name: PTR owner name (``x.x.x.x.in-addr.arpa`` form).
        ip_address_id: owning IP address when known.
        hostname: canonical hostname the address points to.
        ttl: time-to-live in seconds.

    """

    name: str
    ip_address_id: str | None = None
    hostname: str = ""
    ttl: int | None = None


@dataclass(slots=True)
class DNSObservation(TidbEntity):
    """A single raw DNS answer captured before normalization.

    Attributes:
        name: queried owner name.
        record_type: queried record type.
        value: answer rdata as observed.
        ttl: TTL as observed.
        rcode: DNS response code.
        resolver: resolver that answered.
        tool_id: tool that produced the observation.
        source: upstream source.
        raw: full raw response/line this answer came from.
        execution_id: owning execution id.
        correlation_id: correlation id shared by the run.

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
    execution_id: str = ""
    correlation_id: str = ""


@dataclass(slots=True)
class DNSResolution(TidbEntity):
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
        execution_id: owning execution id.
        correlation_id: correlation id shared by the run.

    """

    name: str
    status: str = "resolved"
    record_types: list[str] = field(default_factory=list)
    addresses: list[str] = field(default_factory=list)
    cnames: list[str] = field(default_factory=list)
    rcode: str = "NOERROR"
    resolver: str = ""
    duration_ms: int = 0
    wildcard: bool = False
    error: str = ""
    execution_id: str = ""
    correlation_id: str = ""


@dataclass(slots=True)
class DNSChange(TidbEntity):
    """A detected difference between historical and current DNS state.

    Attributes:
        name: the record owner name affected.
        record_type: the record type affected.
        change_type: ``new``, ``removed`` or ``changed``.
        old_value: previous value (empty for new records).
        new_value: current value (empty for removed records).
        tool_id: tool that produced the current observation.
        confidence: confidence in the change in ``[0, 1]``.
        mission_id: owning mission id.
        correlation_id: correlation id shared by the run.

    """

    name: str
    record_type: DnsRecordType
    change_type: str
    old_value: str = ""
    new_value: str = ""
    tool_id: str = ""
    confidence: float = 1.0
    mission_id: str = ""
    correlation_id: str = ""


@dataclass(slots=True)
class DNSConflict(TidbEntity):
    """A conflicting DNS observation recorded with full provenance.

    Attributes:
        name: the record owner name that conflicted.
        record_type: the record type that conflicted.
        observations: the disagreeing observations (source/resolver/value).
        conflict_type: ``value``, ``presence`` or ``rcode``.
        selected_value: the canonical value selected.
        selected_source: the source the canonical value came from.
        reason: human-readable explanation of the selection.
        confidence: confidence in the selected value in ``[0, 1]``.
        mission_id: owning mission id.
        correlation_id: correlation id shared by the run.

    """

    name: str
    record_type: DnsRecordType
    observations: list[dict[str, str]] = field(default_factory=list)
    conflict_type: str = "value"
    selected_value: str = ""
    selected_source: str = ""
    reason: str = ""
    confidence: float = 0.0
    mission_id: str = ""
    correlation_id: str = ""


@dataclass(slots=True)
class HostObservation(TidbEntity):
    """A live host reachability observation.

    Attributes:
        address: canonical IP address of the host.
        ip_version: IP protocol version (4 or 6).
        hostname: reverse/known hostname, if any.
        state: host state (``reachable``/``unreachable``/``unknown``).
        reachable: whether the host responded.
        methods: reachability methods that confirmed the host.
        rtt_ms: round-trip time in milliseconds.
        tool_id: tool that produced the observation.
        source: upstream source.
        target_id: owning target when in-scope.
        execution_id: owning execution id.
        correlation_id: correlation id shared by the run.

    """

    address: str
    ip_version: int = 4
    hostname: str = ""
    state: str = "unknown"
    reachable: bool | None = None
    methods: list[str] = field(default_factory=list)
    rtt_ms: int = 0
    tool_id: str = ""
    source: str = ""
    target_id: str | None = None
    execution_id: str = ""
    correlation_id: str = ""


@dataclass(slots=True)
class PortObservation(TidbEntity):
    """A live port state observation.

    Attributes:
        address: IP address the port was observed on.
        port: port number.
        protocol: transport protocol (``tcp``/``udp``).
        state: port state (``open``/``closed``/``filtered``/``unknown``).
        reason: reason string as reported by the tool.
        tool_id: tool that produced the observation.
        source: upstream source.
        target_id: owning target when in-scope.
        execution_id: owning execution id.
        correlation_id: correlation id shared by the run.

    """

    address: str
    port: int
    protocol: str = "tcp"
    state: str = "unknown"
    reason: str = ""
    tool_id: str = ""
    source: str = ""
    target_id: str | None = None
    execution_id: str = ""
    correlation_id: str = ""


@dataclass(slots=True)
class ServiceObservation(TidbEntity):
    """A live service fingerprint observation.

    Attributes:
        address: IP address the service was observed on.
        port: port number.
        protocol: transport protocol.
        service: detected service name.
        product: product/software name.
        software_version: detected version string.
        extrainfo: extra service information.
        banner: raw service banner.
        fingerprint_method: how the fingerprint was derived.
        evidence: evidence strings (CPEs, ...).
        tool_id: tool that produced the observation.
        source: upstream source.
        target_id: owning target when in-scope.
        execution_id: owning execution id.
        correlation_id: correlation id shared by the run.

    """

    address: str
    port: int
    protocol: str = "tcp"
    service: str = ""
    product: str = ""
    software_version: str = ""
    extrainfo: str = ""
    banner: str = ""
    fingerprint_method: str = "unknown"
    evidence: list[str] = field(default_factory=list)
    tool_id: str = ""
    source: str = ""
    target_id: str | None = None
    execution_id: str = ""
    correlation_id: str = ""


@dataclass(slots=True)
class LiveChange(TidbEntity):
    """A detected difference between historical and current live state.

    Attributes:
        kind: affected observation kind (``host``/``port``/``service``/...).
        key: canonical observation key that changed (e.g. ``ip|tcp|22``).
        change_type: ``new``, ``removed`` or ``changed``.
        old_value: previous canonical value (empty for new observations).
        new_value: current canonical value (empty for removed observations).
        tool_id: tool that produced the current observation.
        confidence: confidence in the change in ``[0, 1]``.
        mission_id: owning mission id.
        correlation_id: correlation id shared by the run.

    """

    kind: str
    key: str
    change_type: str
    old_value: str = ""
    new_value: str = ""
    tool_id: str = ""
    confidence: float = 1.0
    mission_id: str = ""
    correlation_id: str = ""


@dataclass(slots=True)
class DiscoveryConflict(TidbEntity):
    """A conflicting live discovery observation with full provenance.

    Attributes:
        kind: affected observation kind (``host``/``port``/``service``/...).
        key: canonical observation key that conflicted.
        observations: the disagreeing observations (source/value).
        conflict_type: ``value`` or ``presence``.
        selected_value: the canonical value selected.
        selected_source: the source the canonical value came from.
        reason: human-readable explanation of the selection.
        confidence: confidence in the selected value in ``[0, 1]``.
        mission_id: owning mission id.
        correlation_id: correlation id shared by the run.

    """

    kind: str
    key: str
    observations: list[dict[str, str]] = field(default_factory=list)
    conflict_type: str = "value"
    selected_value: str = ""
    selected_source: str = ""
    reason: str = ""
    confidence: float = 0.0
    mission_id: str = ""
    correlation_id: str = ""
