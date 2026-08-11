# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Acceptance tests for the network-mapping & attack-surface topology capability.

End-to-end scenario: seed canonical TIDB intelligence (as produced by Sprint
007–009), run a full topology build, verify the derived attack-surface
topology, query interfaces, history, views and the ``topology.*`` event stream
through the assembled platform.
"""

from __future__ import annotations

from hunterx.domain.entities.target import Target, TargetKind
from hunterx.domain.entities.tidb.network import (
    ASN,
    CIDR,
    Certificate,
    DNSRecord,
    DnsRecordType,
    Domain,
    Hostname,
    IPAddress,
    MXRecord,
    Nameserver,
    Port,
    PortState,
    Service,
    Subdomain,
)
from hunterx.domain.topology.scope import TopologyScopePolicy
from hunterx.platform.assembler import build_platform


def _seed_tidb(platform) -> None:
    """Seed canonical TIDB entities mirroring Sprint 007-009 output."""
    stores = platform.tidb
    domain = Domain(
        name="example.com",
        target_id="t1",
        dns_servers=["ns1.example.com", "ns2.example.com"],
        mx=["mx1.example.com"],
        source_tool="subfinder",
    )
    sub = Subdomain(domain_id=domain.id, name="api.example.com")
    host = Hostname(name="api.example.com", target_id="t1")
    ip = IPAddress(address="93.184.216.34", hostname_id=host.id, target_id="t1")
    cidr = CIDR(network="93.184.216.0/24")
    asn = ASN(number=15169, name="GOOGLE")
    ip.cidr_id = cidr.id
    ip.asn_id = asn.id
    port = Port(ip_address_id=ip.id, number=443, protocol="tcp", state=PortState.OPEN)
    service = Service(port_id=port.id, name="https", confidence=0.95)
    cert = Certificate(hostname_id=host.id, subject="*.example.com", sha256="aa:bb", san=["api.example.com"])
    ns = Nameserver(name="ns1.example.com", owner_domain="example.com")
    mx = MXRecord(name="example.com", domain_id=domain.id, exchange="mx1.example.com")
    dns = DNSRecord(name="api.example.com", record_type=DnsRecordType.A, value="93.184.216.34")

    stores.repository_for(Domain).save(domain)
    stores.repository_for(Subdomain).save(sub)
    stores.repository_for(Hostname).save(host)
    stores.repository_for(IPAddress).save(ip)
    stores.repository_for(CIDR).save(cidr)
    stores.repository_for(ASN).save(asn)
    stores.repository_for(Port).save(port)
    stores.repository_for(Service).save(service)
    stores.repository_for(Certificate).save(cert)
    stores.repository_for(Nameserver).save(ns)
    stores.repository_for(MXRecord).save(mx)
    stores.repository_for(DNSRecord).save(dns)


class TestTopologyAcceptance:
    def test_attack_surface_topoology_intelligence_flow(self) -> None:
        platform = build_platform()
        _seed_tidb(platform)
        platform.topology_service._scope = TopologyScopePolicy(
            authorized_domains={"example.com"}, allow_third_party=True
        )

        batch = platform.topology_service.run(
            mission_id="acceptance-mission",
            target_key="domain:example.com",
            target_id="t1",
            targets=[Target(kind=TargetKind.DOMAIN, value="example.com", target_id="t1")],
        )

        # 1. Correct, correlated topology
        assert batch.status == "completed"
        rel_types = {edge.rel_type.value for edge in batch.relationships}
        expected = {
            "resolves_to",
            "part_of",
            "exposes",
            "serves",
            "uses",
            "certificate_for",
            "delegated_to",
            "mails_to",
            "announced_by",
            "belongs_to",
            "discovered_by",
        }
        assert expected.issubset(rel_types)

        # 2. Deduplicated + provenance preserved
        keys = [edge.key for edge in batch.relationships]
        assert len(keys) == len(set(keys))
        assert all(edge.sources for edge in batch.relationships if edge.rel_type.value == "resolves_to")

        # 3. Queryable through the defined interfaces
        q = platform.topology_query_service
        assert any(
            entry["key"] == "domain:example.com"
            for entry in q.neighbors("hostname:api.example.com")
        )
        path = q.shortest_path("domain:example.com", "port:443/tcp")
        assert path and path[0] == "domain:example.com"
        surface = q.attack_surface()
        assert surface["node_count"] > 0
        network = q.network_graph()
        assert network["view"] == "network"

        # 4. Historical & temporal
        history = q.historical_relationships()
        assert any(change["key"] for change in history)

        # 5. Persisted in the canonical TIDB (single source of truth)
        from hunterx.domain.entities.tidb.topology import TopologyRelationship

        persisted = list(platform.tidb.repository_for(TopologyRelationship).stream())
        assert persisted and all(p.relationship_key for p in persisted)

    def test_incremental_second_build_is_stable(self) -> None:
        platform = build_platform()
        _seed_tidb(platform)
        platform.topology_service._scope = TopologyScopePolicy(
            authorized_domains={"example.com"}, allow_third_party=True
        )

        first = platform.topology_service.run(
            mission_id="inc-mission",
            target_key="domain:example.com",
            target_id="t1",
        )
        second = platform.topology_service.run(
            mission_id="inc-mission",
            target_key="domain:example.com",
            target_id="t1",
            mode="incremental",
        )
        assert {e.key for e in second.relationships} == {e.key for e in first.relationships}
        assert not [c for c in second.changes if c.change_type == "new"]

    def test_scope_boundary_prevents_expansion(self) -> None:
        platform = build_platform()
        _seed_tidb(platform)
        platform.topology_service._scope = TopologyScopePolicy(
            authorized_domains={"example.com"}, allow_third_party=False
        )
        batch = platform.topology_service.run(
            mission_id="scope-mission",
            target_key="domain:example.com",
            target_id="t1",
        )
        # Every persisted edge must be in-scope when third-party is disallowed
        out_of_scope = [e for e in batch.relationships if not e.in_scope]
        assert not out_of_scope
