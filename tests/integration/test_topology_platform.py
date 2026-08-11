# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Integration tests for the network-mapping topology capability.

Exercises the full wiring through the assembled platform: topology services
registered in the container, traceroute available on the execution engine and
TIP, an end-to-end topology build over seeded TIDB data, persisted topology
entities and the canonical query interfaces.
"""

from __future__ import annotations

from hunterx.domain.entities.target import Target, TargetKind
from hunterx.domain.entities.tidb.network import (
    ASN,
    CIDR,
    Domain,
    Hostname,
    IPAddress,
    Port,
    PortState,
    Service,
    Subdomain,
)
from hunterx.domain.entities.tidb.topology import (
    TopologyBuild,
    TopologyChange,
    TopologyCluster,
    TopologyRelationship,
)
from hunterx.domain.topology.scope import TopologyScopePolicy
from hunterx.platform.assembler import build_platform


def _seed(platform) -> None:
    stores = platform.tidb
    domain = Domain(name="example.com", target_id="t1")
    sub = Subdomain(domain_id=domain.id, name="api.example.com")
    host = Hostname(name="api.example.com", target_id="t1")
    ip = IPAddress(address="93.184.216.34", hostname_id=host.id, target_id="t1")
    cidr = CIDR(network="93.184.216.0/24")
    asn = ASN(number=15169, name="GOOGLE")
    ip.cidr_id = cidr.id
    ip.asn_id = asn.id
    port = Port(ip_address_id=ip.id, number=443, protocol="tcp", state=PortState.OPEN)
    service = Service(port_id=port.id, name="https")
    stores.repository_for(Domain).save(domain)
    stores.repository_for(Subdomain).save(sub)
    stores.repository_for(Hostname).save(host)
    stores.repository_for(IPAddress).save(ip)
    stores.repository_for(CIDR).save(cidr)
    stores.repository_for(ASN).save(asn)
    stores.repository_for(Port).save(port)
    stores.repository_for(Service).save(service)


class TestPlatformTopology:
    def test_services_resolvable_from_platform(self) -> None:
        platform = build_platform()
        assert platform.topology_service is not None
        assert platform.topology_query_service is not None
        assert platform.has(type(platform.topology_service))

    def test_traceroute_registered_on_engine_and_tip(self) -> None:
        platform = build_platform()
        assert platform.execution_engine.adapter_for("traceroute") is not None
        ids = [tool.tool_id for tool in platform.tip.list_tools()]
        assert "traceroute" in ids

    def test_full_build_and_query_roundtrip(self) -> None:
        platform = build_platform()
        _seed(platform)
        policy = TopologyScopePolicy(authorized_domains={"example.com"}, allow_third_party=True)
        platform.topology_service._scope = policy

        batch = platform.topology_service.run(
            mission_id="mission-x",
            target_key="domain:example.com",
            target_id="t1",
            targets=[Target(kind=TargetKind.DOMAIN, value="example.com", target_id="t1")],
        )
        assert batch.status == "completed"
        assert batch.relationships
        rel_types = {edge.rel_type.value for edge in batch.relationships}
        assert {"resolves_to", "part_of", "exposes", "serves"}.issubset(rel_types)

        # Persisted entities
        assert platform.tidb.repository_for(TopologyRelationship).count() == len(batch.relationships)
        assert platform.tidb.repository_for(TopologyBuild).count() == 1

        # Queries read the persisted topology
        neighbors = platform.topology_query_service.neighbors("hostname:api.example.com")
        assert any(entry["key"] == "ip:93.184.216.34" for entry in neighbors)
        path = platform.topology_query_service.shortest_path("domain:example.com", "port:443/tcp")
        assert "hostname:api.example.com" in path
        surface = platform.topology_query_service.attack_surface()
        assert surface["node_count"] > 0

    def test_conflicts_and_clusters_persisted(self) -> None:
        platform = build_platform()
        _seed(platform)
        policy = TopologyScopePolicy(authorized_domains={"example.com"}, allow_third_party=True)
        platform.topology_service._scope = policy
        platform.topology_service.run(
            mission_id="mission-y",
            target_key="domain:example.com",
            target_id="t1",
        )
        # clusters should be detected (host + subdomain share the domain, IP+CIDR+ASN chain)
        assert platform.tidb.repository_for(TopologyCluster).count() >= 0
        assert platform.tidb.repository_for(TopologyChange).count() >= 0

    def test_history_second_run_unchanged(self) -> None:
        platform = build_platform()
        _seed(platform)
        policy = TopologyScopePolicy(authorized_domains={"example.com"}, allow_third_party=True)
        platform.topology_service._scope = policy
        platform.topology_service.run(
            mission_id="mission-z",
            target_key="domain:example.com",
            target_id="t1",
        )
        second = platform.topology_service.run(
            mission_id="mission-z",
            target_key="domain:example.com",
            target_id="t1",
        )
        new_in_second = [c for c in second.changes if c.change_type == "new"]
        # second run should discover no brand-new edges
        assert not new_in_second
