# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""ORM models for TIDB network entities (DNS, addressing, ports, services)."""

from __future__ import annotations

from sqlalchemy import (
    JSON,
    Boolean,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from hunterx.infrastructure.db.sql.tidb_models._base import Base, TidbModelMixin


class DomainModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.network.Domain`."""

    __tablename__ = "tidb_domains"

    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    target_id: Mapped[str | None] = mapped_column(String(26), nullable=True, index=True)
    parent_domain_id: Mapped[str | None] = mapped_column(
        String(26), ForeignKey("tidb_domains.id"), nullable=True
    )
    is_authoritative: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    registrar: Mapped[str | None] = mapped_column(String(255), nullable=True)
    dns_servers: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    mx: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    txt: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    dnsssec_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    source_tool: Mapped[str | None] = mapped_column(String(255), nullable=True)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)

    __table_args__ = (UniqueConstraint("name", name="uq_tidb_domains_name"),)


class SubdomainModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.network.Subdomain`."""

    __tablename__ = "tidb_subdomains"

    domain_id: Mapped[str] = mapped_column(
        String(26), ForeignKey("tidb_domains.id"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    resolution_confidence: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)

    __table_args__ = (UniqueConstraint("domain_id", "name", name="uq_tidb_subdomains_domain_name"),)


class HostnameModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.network.Hostname`."""

    __tablename__ = "tidb_hostnames"

    name: Mapped[str] = mapped_column(String(255), nullable=False, unique=True, index=True)
    target_id: Mapped[str | None] = mapped_column(String(26), nullable=True, index=True)
    is_alive: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    os_hint: Mapped[str | None] = mapped_column(String(128), nullable=True)


class IPAddressModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.network.IPAddress`."""

    __tablename__ = "tidb_ip_addresses"

    address: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    ip_version: Mapped[int] = mapped_column(Integer, nullable=False, default=4)
    target_id: Mapped[str | None] = mapped_column(String(26), nullable=True, index=True)
    hostname_id: Mapped[str | None] = mapped_column(
        String(26), ForeignKey("tidb_hostnames.id"), nullable=True, index=True
    )
    cidr_id: Mapped[str | None] = mapped_column(
        String(26), ForeignKey("tidb_cidrs.id"), nullable=True, index=True
    )
    asn_id: Mapped[str | None] = mapped_column(
        String(26), ForeignKey("tidb_asns.id"), nullable=True, index=True
    )
    owner_org: Mapped[str | None] = mapped_column(String(255), nullable=True)
    geo: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)
    is_alive: Mapped[bool | None] = mapped_column(Boolean, nullable=True)


class CIDRModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.network.CIDR`."""

    __tablename__ = "tidb_cidrs"

    network: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    target_id: Mapped[str | None] = mapped_column(String(26), nullable=True, index=True)
    asn_id: Mapped[str | None] = mapped_column(
        String(26), ForeignKey("tidb_asns.id"), nullable=True, index=True
    )
    owner_org: Mapped[str | None] = mapped_column(String(255), nullable=True)


class ASNModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.network.ASN`."""

    __tablename__ = "tidb_asns"

    number: Mapped[int] = mapped_column(Integer, nullable=False, unique=True, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    org: Mapped[str | None] = mapped_column(String(255), nullable=True)
    country: Mapped[str | None] = mapped_column(String(8), nullable=True)
    registry: Mapped[str | None] = mapped_column(String(32), nullable=True)


class DNSRecordModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.network.DNSRecord`."""

    __tablename__ = "tidb_dns_records"

    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    record_type: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    value: Mapped[str] = mapped_column(Text, nullable=False)
    ttl: Mapped[int | None] = mapped_column(Integer, nullable=True)
    priority: Mapped[int | None] = mapped_column(Integer, nullable=True)
    domain_id: Mapped[str | None] = mapped_column(
        String(26), ForeignKey("tidb_domains.id"), nullable=True, index=True
    )
    subdomain_id: Mapped[str | None] = mapped_column(
        String(26), ForeignKey("tidb_subdomains.id"), nullable=True, index=True
    )

    __table_args__ = (
        Index("ix_tidb_dns_records_domain_type", "domain_id", "record_type"),
        Index("ix_tidb_dns_records_name_type", "name", "record_type"),
    )


class WHOISRecordModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.network.WHOISRecord`."""

    __tablename__ = "tidb_whois_records"

    domain_id: Mapped[str] = mapped_column(
        String(26), ForeignKey("tidb_domains.id"), nullable=False, index=True
    )
    raw: Mapped[str] = mapped_column(Text, nullable=False, default="")
    registrar: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at_domain: Mapped[str | None] = mapped_column(String(32), nullable=True)
    expires_at_domain: Mapped[str | None] = mapped_column(String(32), nullable=True)
    updated_at_domain: Mapped[str | None] = mapped_column(String(32), nullable=True)
    nameservers: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)

    __table_args__ = (UniqueConstraint("domain_id", name="uq_tidb_whois_records_domain"),)


class CertificateModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.network.Certificate`."""

    __tablename__ = "tidb_certificates"

    hostname_id: Mapped[str | None] = mapped_column(
        String(26), ForeignKey("tidb_hostnames.id"), nullable=True, index=True
    )
    subject: Mapped[str | None] = mapped_column(String(512), nullable=True)
    issuer: Mapped[str | None] = mapped_column(String(512), nullable=True)
    serial: Mapped[str | None] = mapped_column(String(255), nullable=True)
    sha256: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    not_before: Mapped[str | None] = mapped_column(String(32), nullable=True)
    not_after: Mapped[str | None] = mapped_column(String(32), nullable=True)
    san: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    revoked: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    __table_args__ = (Index("ix_tidb_certificates_hostname_sha256", "hostname_id", "sha256"),)


class PortModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.network.Port`."""

    __tablename__ = "tidb_ports"

    ip_address_id: Mapped[str] = mapped_column(
        String(26), ForeignKey("tidb_ip_addresses.id"), nullable=False, index=True
    )
    number: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    protocol: Mapped[str] = mapped_column(String(8), nullable=False, default="tcp")
    state: Mapped[str] = mapped_column(String(16), nullable=False, default="unknown", index=True)
    banner: Mapped[str | None] = mapped_column(Text, nullable=True)
    service_hint: Mapped[str | None] = mapped_column(String(255), nullable=True)

    __table_args__ = (
        UniqueConstraint("ip_address_id", "number", "protocol", name="uq_tidb_ports_ip_port_proto"),
    )


class ProtocolModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.network.Protocol`."""

    __tablename__ = "tidb_protocols"

    name: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    port_hint: Mapped[int | None] = mapped_column(Integer, nullable=True)


class ServiceModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.network.Service`."""

    __tablename__ = "tidb_services"

    port_id: Mapped[str] = mapped_column(
        String(26), ForeignKey("tidb_ports.id"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    software_version: Mapped[str | None] = mapped_column(String(128), nullable=True)
    state: Mapped[str] = mapped_column(String(16), nullable=False, default="unknown", index=True)
    banner: Mapped[str | None] = mapped_column(Text, nullable=True)
    tls_info: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)


class DNSZoneModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.network.DNSZone`."""

    __tablename__ = "tidb_dns_zones"

    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    domain_id: Mapped[str | None] = mapped_column(
        String(26), ForeignKey("tidb_domains.id"), nullable=True, index=True
    )
    primary_ns: Mapped[str | None] = mapped_column(String(255), nullable=True)
    admin_mail: Mapped[str | None] = mapped_column(String(255), nullable=True)
    serial: Mapped[int | None] = mapped_column(Integer, nullable=True)
    refresh: Mapped[int | None] = mapped_column(Integer, nullable=True)
    retry: Mapped[int | None] = mapped_column(Integer, nullable=True)
    expire: Mapped[int | None] = mapped_column(Integer, nullable=True)
    minimum: Mapped[int | None] = mapped_column(Integer, nullable=True)
    ttl: Mapped[int | None] = mapped_column(Integer, nullable=True)

    __table_args__ = (UniqueConstraint("name", name="uq_tidb_dns_zones_name"),)


class DNSDelegationModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.network.DNSDelegation`."""

    __tablename__ = "tidb_dns_delegations"

    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    subdomain_id: Mapped[str | None] = mapped_column(
        String(26), ForeignKey("tidb_subdomains.id"), nullable=True, index=True
    )
    nameservers: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    glue_records: Mapped[list[tuple[str, str]]] = mapped_column(JSON, nullable=False, default=list)
    is_delegated: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    __table_args__ = (UniqueConstraint("name", name="uq_tidb_dns_delegations_name"),)


class NameserverModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.network.Nameserver`."""

    __tablename__ = "tidb_nameservers"

    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    addresses: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    owner_domain: Mapped[str | None] = mapped_column(String(255), nullable=True)
    is_authoritative: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    __table_args__ = (UniqueConstraint("name", name="uq_tidb_nameservers_name"),)


class ResolverModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.network.Resolver`."""

    __tablename__ = "tidb_resolvers"

    address: Mapped[str] = mapped_column(String(255), nullable=False, unique=True, index=True)
    protocol: Mapped[str] = mapped_column(String(16), nullable=False, default="udp")
    rtt_ms: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="ok", index=True)
    error: Mapped[str] = mapped_column(Text, nullable=False, default="")


class MXRecordModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.network.MXRecord`."""

    __tablename__ = "tidb_mx_records"

    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    domain_id: Mapped[str | None] = mapped_column(
        String(26), ForeignKey("tidb_domains.id"), nullable=True, index=True
    )
    preference: Mapped[int] = mapped_column(Integer, nullable=False, default=10)
    exchange: Mapped[str] = mapped_column(String(255), nullable=False)
    ttl: Mapped[int | None] = mapped_column(Integer, nullable=True)
    provider: Mapped[str | None] = mapped_column(String(128), nullable=True)

    __table_args__ = (
        Index("ix_tidb_mx_records_name_exchange", "name", "exchange"),
    )


class TXTRecordModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.network.TXTRecord`."""

    __tablename__ = "tidb_txt_records"

    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    domain_id: Mapped[str | None] = mapped_column(
        String(26), ForeignKey("tidb_domains.id"), nullable=True, index=True
    )
    value: Mapped[str] = mapped_column(Text, nullable=False)
    ttl: Mapped[int | None] = mapped_column(Integer, nullable=True)
    purpose: Mapped[str] = mapped_column(String(32), nullable=False, default="other", index=True)


class CAARecordModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.network.CAARecord`."""

    __tablename__ = "tidb_caa_records"

    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    domain_id: Mapped[str | None] = mapped_column(
        String(26), ForeignKey("tidb_domains.id"), nullable=True, index=True
    )
    flags: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    tag: Mapped[str] = mapped_column(String(32), nullable=False, default="issue")
    value: Mapped[str] = mapped_column(Text, nullable=False, default="")
    ttl: Mapped[int | None] = mapped_column(Integer, nullable=True)


class SOARecordModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.network.SOARecord`."""

    __tablename__ = "tidb_soa_records"

    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    domain_id: Mapped[str | None] = mapped_column(
        String(26), ForeignKey("tidb_domains.id"), nullable=True, index=True
    )
    primary_ns: Mapped[str | None] = mapped_column(String(255), nullable=True)
    admin_mail: Mapped[str | None] = mapped_column(String(255), nullable=True)
    serial: Mapped[int | None] = mapped_column(Integer, nullable=True)
    refresh: Mapped[int | None] = mapped_column(Integer, nullable=True)
    retry: Mapped[int | None] = mapped_column(Integer, nullable=True)
    expire: Mapped[int | None] = mapped_column(Integer, nullable=True)
    minimum: Mapped[int | None] = mapped_column(Integer, nullable=True)
    ttl: Mapped[int | None] = mapped_column(Integer, nullable=True)


class DNSSECRecordModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.network.DNSSECRecord`."""

    __tablename__ = "tidb_dnssec_records"

    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    zone_id: Mapped[str | None] = mapped_column(
        String(26), ForeignKey("tidb_dns_zones.id"), nullable=True, index=True
    )
    record_type: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    value: Mapped[str] = mapped_column(Text, nullable=False, default="")
    algorithm: Mapped[str | None] = mapped_column(String(32), nullable=True)
    key_tag: Mapped[int | None] = mapped_column(Integer, nullable=True)
    ttl: Mapped[int | None] = mapped_column(Integer, nullable=True)
    data: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)


class PTRRecordModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.network.PTRRecord`."""

    __tablename__ = "tidb_ptr_records"

    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    ip_address_id: Mapped[str | None] = mapped_column(
        String(26), ForeignKey("tidb_ip_addresses.id"), nullable=True, index=True
    )
    hostname: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    ttl: Mapped[int | None] = mapped_column(Integer, nullable=True)


class DNSObservationModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.network.DNSObservation`."""

    __tablename__ = "tidb_dns_observations"

    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    record_type: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    value: Mapped[str] = mapped_column(Text, nullable=False, default="")
    ttl: Mapped[int | None] = mapped_column(Integer, nullable=True)
    rcode: Mapped[str] = mapped_column(String(16), nullable=False, default="NOERROR")
    resolver: Mapped[str] = mapped_column(String(255), nullable=False, default="", index=True)
    tool_id: Mapped[str] = mapped_column(String(128), nullable=False, default="", index=True)
    source: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    raw: Mapped[str] = mapped_column(Text, nullable=False, default="")
    execution_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)


class DNSResolutionModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.network.DNSResolution`."""

    __tablename__ = "tidb_dns_resolutions"

    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="resolved", index=True)
    record_types: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    addresses: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    cnames: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    rcode: Mapped[str] = mapped_column(String(16), nullable=False, default="NOERROR")
    resolver: Mapped[str] = mapped_column(String(255), nullable=False, default="", index=True)
    duration_ms: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    wildcard: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    error: Mapped[str] = mapped_column(Text, nullable=False, default="")
    execution_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)


class DNSChangeModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.network.DNSChange`."""

    __tablename__ = "tidb_dns_changes"

    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    record_type: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    change_type: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    old_value: Mapped[str] = mapped_column(Text, nullable=False, default="")
    new_value: Mapped[str] = mapped_column(Text, nullable=False, default="")
    tool_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)


class DNSConflictModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.network.DNSConflict`."""

    __tablename__ = "tidb_dns_conflicts"

    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    record_type: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    observations: Mapped[list[dict[str, str]]] = mapped_column(JSON, nullable=False, default=list)
    conflict_type: Mapped[str] = mapped_column(String(16), nullable=False, default="value")
    selected_value: Mapped[str] = mapped_column(Text, nullable=False, default="")
    selected_source: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    reason: Mapped[str] = mapped_column(Text, nullable=False, default="")
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)


class HostObservationModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.network.HostObservation`."""

    __tablename__ = "tidb_host_observations"

    address: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    ip_version: Mapped[int] = mapped_column(Integer, nullable=False, default=4)
    hostname: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    state: Mapped[str] = mapped_column(String(16), nullable=False, default="unknown", index=True)
    reachable: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    methods: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    rtt_ms: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    tool_id: Mapped[str] = mapped_column(String(128), nullable=False, default="", index=True)
    source: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    target_id: Mapped[str | None] = mapped_column(String(26), nullable=True, index=True)
    execution_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)


class PortObservationModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.network.PortObservation`."""

    __tablename__ = "tidb_port_observations"

    address: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    port: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    protocol: Mapped[str] = mapped_column(String(8), nullable=False, default="tcp")
    state: Mapped[str] = mapped_column(String(16), nullable=False, default="unknown", index=True)
    reason: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    tool_id: Mapped[str] = mapped_column(String(128), nullable=False, default="", index=True)
    source: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    target_id: Mapped[str | None] = mapped_column(String(26), nullable=True, index=True)
    execution_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)

    __table_args__ = (
        Index("ix_tidb_port_observations_address_port", "address", "port"),
    )


class ServiceObservationModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.network.ServiceObservation`."""

    __tablename__ = "tidb_service_observations"

    address: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    port: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    protocol: Mapped[str] = mapped_column(String(8), nullable=False, default="tcp")
    service: Mapped[str] = mapped_column(String(255), nullable=False, default="", index=True)
    product: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    software_version: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    extrainfo: Mapped[str] = mapped_column(Text, nullable=False, default="")
    banner: Mapped[str] = mapped_column(Text, nullable=False, default="")
    fingerprint_method: Mapped[str] = mapped_column(String(16), nullable=False, default="unknown")
    evidence: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    tool_id: Mapped[str] = mapped_column(String(128), nullable=False, default="", index=True)
    source: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    target_id: Mapped[str | None] = mapped_column(String(26), nullable=True, index=True)
    execution_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)

    __table_args__ = (
        Index("ix_tidb_service_observations_address_port", "address", "port"),
    )


class LiveChangeModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.network.LiveChange`."""

    __tablename__ = "tidb_live_changes"

    kind: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    key: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    change_type: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    old_value: Mapped[str] = mapped_column(Text, nullable=False, default="")
    new_value: Mapped[str] = mapped_column(Text, nullable=False, default="")
    tool_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)


class DiscoveryConflictModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.network.DiscoveryConflict`."""

    __tablename__ = "tidb_discovery_conflicts"

    kind: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    key: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    observations: Mapped[list[dict[str, str]]] = mapped_column(JSON, nullable=False, default=list)
    conflict_type: Mapped[str] = mapped_column(String(16), nullable=False, default="value")
    selected_value: Mapped[str] = mapped_column(Text, nullable=False, default="")
    selected_source: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    reason: Mapped[str] = mapped_column(Text, nullable=False, default="")
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
