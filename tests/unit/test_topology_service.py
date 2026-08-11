# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tests for the TopologyService and TopologyQueryService orchestrators.

Exercises a full topology build: TIDB entity collection, traceroute execution
through the SDK pipeline with a fake runner, relationship derivation &
correlation, conflict detection, history comparison, analysis, TIDB
persistence, the ``topology.*`` event stream and the canonical query
interfaces.
"""

from __future__ import annotations

from pathlib import Path

from hunterx.application.topology import TopologyQueryService, TopologyService
from hunterx.domain.entities.target import Target, TargetKind
from hunterx.domain.entities.tidb.network import (
    ASN,
    CIDR,
    Certificate,
    Domain,
    Hostname,
    IPAddress,
    Nameserver,
    Port,
    PortState,
    Service,
    Subdomain,
)
from hunterx.domain.entities.tidb.topology import (
    TopologyBuild,
    TopologyRelationship,
)
from hunterx.domain.topology.enums import ChangeType, RelationshipType
from hunterx.domain.topology.scope import TopologyScopePolicy
from hunterx.infrastructure.db.sql.memory import InMemoryTidbRepositoryFactory
from hunterx.infrastructure.event_bus import InMemoryEventBus
from hunterx.tools.recon.runner import BinaryRunner, CommandResult
from hunterx.tools.sdk.engine import ExecutionEngine
from hunterx.tools.topology.traceroute import TracerouteAdapter

GOLDEN = Path(__file__).parent.parent / "golden" / "topology"


def _policy() -> TopologyScopePolicy:
    policy = TopologyScopePolicy(authorized_domains={"example.com"}, allow_third_party=True)
    return policy


def _service(stores: InMemoryTidbRepositoryFactory, bus: InMemoryEventBus | None = None) -> TopologyService:
    return TopologyService(
        engine=_engine(),
        stores=stores,
        event_bus=bus,
        scope=_policy(),
    )


class FakeRunner(BinaryRunner):
    """Binary runner that returns a canned :class:`CommandResult`."""

    def __init__(self, *, stdout: str = "") -> None:
        super().__init__()
        self._result = CommandResult(returncode=0, stdout=stdout)
        self.calls: list[tuple[str, ...]] = []

    def run(self, argv, *, timeout_s: float = 0.0, tool_id: str = ""):
        self.calls.append(tuple(argv))
        return self._result


def _golden(name: str) -> str:
    return (GOLDEN / name).read_text(encoding="utf-8")


def _engine() -> ExecutionEngine:
    engine = ExecutionEngine()
    adapter = TracerouteAdapter(runner=FakeRunner(stdout=_golden("traceroute_plain.txt")))
    engine.register_adapter("traceroute", adapter)
    engine.install_hook("traceroute", lambda _tid, _version: "2.1.0")
    engine.install("traceroute", version="2.1.0")
    return engine


def _seed_stores() -> InMemoryTidbRepositoryFactory:
    stores = InMemoryTidbRepositoryFactory()
    domain = Domain(name="example.com", target_id="t1", dns_servers=["ns1.example.com"], mx=["mx1.example.com"], source_tool="subfinder")
    sub = Subdomain(domain_id=domain.id, name="api.example.com")
    host = Hostname(name="api.example.com", target_id="t1")
    ip = IPAddress(address="93.184.216.34", hostname_id=host.id, target_id="t1")
    cidr = CIDR(network="93.184.216.0/24")
    asn = ASN(number=15169, name="GOOGLE")
    ip.cidr_id = cidr.id
    ip.asn_id = asn.id
    port = Port(ip_address_id=ip.id, number=443, protocol="tcp", state=PortState.OPEN)
    service = Service(port_id=port.id, name="https")
    cert = Certificate(hostname_id=host.id, subject="*.example.com", sha256="aa:bb", san=["api.example.com"])
    ns = Nameserver(name="ns1.example.com", owner_domain="example.com")
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
    return stores


def _event_recorder(bus: InMemoryEventBus) -> list[str]:
    captured: list[str] = []
    bus.subscribe("topology.#", lambda event: captured.append(event.event_type))
    return captured


class TestTopologyService:
    def test_run_derives_and_correlates(self) -> None:
        stores = _seed_stores()
        bus = InMemoryEventBus()
        _event_recorder(bus)
        service = _service(stores, bus)

        batch = service.run(
            mission_id="mission-1",
            target_key="domain:example.com",
            target_id="t1",
            tools=["traceroute"],
            targets=[Target(kind=TargetKind.DOMAIN, value="example.com", target_id="t1")],
        )
        assert batch.status == "completed"
        assert batch.entities_processed > 0
        rel_types = {edge.rel_type.value for edge in batch.relationships}
        assert "resolves_to" in rel_types
        assert "part_of" in rel_types
        assert "exposes" in rel_types
        assert "serves" in rel_types
        assert "belongs_to" in rel_types
        assert "routes_to" in rel_types

    def test_persists_topology_to_tidb(self) -> None:
        stores = _seed_stores()
        service = _service(stores)
        batch = service.run(
            mission_id="mission-1",
            target_key="domain:example.com",
            target_id="t1",
        )
        repo = stores.repository_for(TopologyRelationship)
        assert repo.count() == len(batch.relationships)
        persisted = next(repo.stream())
        assert persisted.mission_id == "mission-1"
        assert persisted.relationship_key

    def test_persists_build_record(self) -> None:
        stores = _seed_stores()
        service = _service(stores)
        service.run(mission_id="mission-1", target_key="domain:example.com", target_id="t1")
        builds = list(stores.repository_for(TopologyBuild).stream())
        assert len(builds) == 1
        assert builds[0].status == "completed"

    def test_detects_removed_relationships_across_runs(self) -> None:
        stores = _seed_stores()
        service = _service(stores)
        first = service.run(mission_id="m1", target_key="domain:example.com", target_id="t1")
        assert first.relationships
        # remove a hostname to force a removed edge in the second run
        host = next(stores.repository_for(Hostname).stream())
        stores.repository_for(Hostname).soft_delete(host.id)
        second = service.run(mission_id="m1", target_key="domain:example.com", target_id="t1")
        removed = [c for c in second.changes if c.change_type == ChangeType.REMOVED]
        assert removed, "expected removed relationships after hostname deletion"

    def test_events_emitted(self) -> None:
        stores = _seed_stores()
        bus = InMemoryEventBus()
        events = _event_recorder(bus)
        service = _service(stores, bus)
        service.run(mission_id="m1", target_key="domain:example.com", target_id="t1")
        assert "topology.build.started" in events
        assert "topology.analysis.completed" in events
        assert "topology.build.completed" in events
        assert any(event.endswith(".discovered") for event in events) or any(
            event == "topology.relationship.discovered" for event in events
        )

    def test_route_observations_from_tool(self) -> None:
        stores = _seed_stores()
        service = _service(stores)
        batch = service.run(
            mission_id="m1",
            target_key="domain:example.com",
            target_id="t1",
            tools=["traceroute"],
            with_routes=True,
        )
        route_edges = [edge for edge in batch.relationships if edge.rel_type == RelationshipType.ROUTES_TO]
        assert route_edges, "expected ROUTES_TO edges from traceroute"

    def test_incremental_mode(self) -> None:
        stores = _seed_stores()
        service = _service(stores)
        batch = service.run(
            mission_id="m1",
            target_key="domain:example.com",
            target_id="t1",
            mode="incremental",
        )
        assert batch.target.mode == "incremental"


class TestTopologyQueryService:
    def test_neighbors(self) -> None:
        stores = _seed_stores()
        _service(stores).run(
            mission_id="m1", target_key="domain:example.com", target_id="t1"
        )
        query = TopologyQueryService(stores=stores)
        neighbors = query.neighbors("hostname:api.example.com")
        keys = {entry["key"] for entry in neighbors}
        assert "ip:93.184.216.34" in keys
        assert "domain:example.com" in keys

    def test_shortest_path(self) -> None:
        stores = _seed_stores()
        _service(stores).run(
            mission_id="m1", target_key="domain:example.com", target_id="t1"
        )
        query = TopologyQueryService(stores=stores)
        path = query.shortest_path("domain:example.com", "port:443/tcp")
        assert "hostname:api.example.com" in path
        assert "ip:93.184.216.34" in path

    def test_related_assets(self) -> None:
        stores = _seed_stores()
        _service(stores).run(
            mission_id="m1", target_key="domain:example.com", target_id="t1"
        )
        query = TopologyQueryService(stores=stores)
        related = query.related_assets("ip:93.184.216.34", max_depth=2)
        assert "hostname:api.example.com" in related

    def test_attack_surface_view(self) -> None:
        stores = _seed_stores()
        _service(stores).run(
            mission_id="m1", target_key="domain:example.com", target_id="t1"
        )
        query = TopologyQueryService(stores=stores)
        view = query.attack_surface()
        assert view["view"] == "external_attack_surface"
        assert view["node_count"] > 0

    def test_network_graph_view(self) -> None:
        stores = _seed_stores()
        _service(stores).run(
            mission_id="m1", target_key="domain:example.com", target_id="t1"
        )
        query = TopologyQueryService(stores=stores)
        view = query.network_graph()
        assert view["view"] == "network"

    def test_historical_relationships(self) -> None:
        stores = _seed_stores()
        service = _service(stores)
        service.run(mission_id="m1", target_key="domain:example.com", target_id="t1")
        service.run(mission_id="m1", target_key="domain:example.com", target_id="t1")
        query = TopologyQueryService(stores=stores)
        changes = query.historical_relationships()
        assert isinstance(changes, list)
        assert any(c["mission_id"] == "m1" for c in changes)

    def test_analysis_summary(self) -> None:
        stores = _seed_stores()
        _service(stores).run(
            mission_id="m1", target_key="domain:example.com", target_id="t1"
        )
        query = TopologyQueryService(stores=stores)
        analysis = query.analysis()
        assert "node_count" in analysis
        assert "relationship_count" in analysis
