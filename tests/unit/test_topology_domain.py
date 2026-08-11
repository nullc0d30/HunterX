# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tests for the topology domain layer.

Covers entity resolution & normalization, relationship correlation &
deduplication, conflict preservation, temporal history, analysis, path finding,
graph views, scope enforcement and the TIDB-derivation rules.
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
from hunterx.domain.topology.analysis import TopologyAnalyzer
from hunterx.domain.topology.confidence import TopologyConfidenceEngine
from hunterx.domain.topology.conflicts import TopologyConflictResolver
from hunterx.domain.topology.correlator import TopologyCorrelator
from hunterx.domain.topology.deriver import RelationshipDeriver
from hunterx.domain.topology.enums import (
    ChangeType,
    ClusterType,
    ConflictType,
    EntityKind,
    RelationshipType,
)
from hunterx.domain.topology.graph import TopologyGraph
from hunterx.domain.topology.history import TopologyHistory
from hunterx.domain.topology.keys import (
    entity_key,
    normalize_domain,
    normalize_hostname,
    normalize_ip,
    relationship_key,
)
from hunterx.domain.topology.models import (
    GraphRelationship,
    RelationshipObservation,
    TopologyEntity,
    TopologySourceData,
)
from hunterx.domain.topology.normalizer import TopologyNormalizer
from hunterx.domain.topology.paths import TopologyPathFinder
from hunterx.domain.topology.resolver import EntityResolver
from hunterx.domain.topology.scope import TopologyScopeEnforcer, TopologyScopePolicy
from hunterx.domain.topology.strategy import TopologyStrategyBuilder
from hunterx.domain.topology.validator import TopologyValidator
from hunterx.domain.topology.views import TopologyViewBuilder


def _node(kind: str, name: str) -> TopologyEntity:
    return TopologyEntity(kind=kind, name=name)


def _obs(
    rel_type: str,
    source: TopologyEntity,
    target: TopologyEntity,
    *,
    source_name: str = "tidb",
    confidence: float = 1.0,
    observed_at: str = "2026-01-01T00:00:00+00:00",
) -> RelationshipObservation:
    return RelationshipObservation(
        rel_type=rel_type,
        source=source,
        target=target,
        source_name=source_name,
        confidence=confidence,
        observed_at=observed_at,
    )


class TestNormalizerAndResolver:
    def test_hostname_normalization(self) -> None:
        assert normalize_hostname("WWW.Example.COM.") == "www.example.com"
        assert normalize_domain("Example.COM") == "example.com"

    def test_ip_normalization(self) -> None:
        assert normalize_ip("2001:0DB8:0:0:0:0:0:1") == "2001:db8::1"
        assert normalize_ip("1.2.3.4") == "1.2.3.4"

    def test_entity_key(self) -> None:
        assert entity_key("hostname", "www.example.com") == "hostname:www.example.com"

    def test_relationship_key(self) -> None:
        assert (
            relationship_key("resolves_to", "hostname:www.example.com", "ip:93.184.216.34")
            == "resolves_to:hostname:www.example.com|ip:93.184.216.34"
        )

    def test_resolver_deduplicates(self) -> None:
        resolver = EntityResolver()
        first = resolver.resolve("hostname", "WWW.Example.COM")
        second = resolver.resolve("hostname", "www.example.com.")
        assert first.key == second.key
        assert resolver.resolve("ip", "2001:0DB8::1").key == "ip:2001:db8::1"

    def test_resolver_does_not_merge_dissimilar(self) -> None:
        resolver = EntityResolver()
        a = resolver.resolve("hostname", "www.example.com")
        b = resolver.resolve("hostname", "wwwexample.com")
        assert a.key != b.key

    def test_normalizer_entity(self) -> None:
        normalizer = TopologyNormalizer()
        node = normalizer.normalize_entity(EntityKind.IP, "2001:0DB8::1")
        assert node.key == "ip:2001:db8::1"


class TestDeriver:
    def _data(self) -> TopologySourceData:
        domain = Domain(name="example.com", target_id="t1", dns_servers=["ns1.example.com"], mx=["mx1.example.com"], source_tool="subfinder")
        sub = Subdomain(domain_id=domain.id, name="api.example.com")
        host = Hostname(name="api.example.com", target_id="t1")
        ip = IPAddress(address="93.184.216.34", hostname_id=host.id, cidr_id=None, asn_id=None, target_id="t1")
        cidr = CIDR(network="93.184.216.0/24")
        asn = ASN(number=15169, name="GOOGLE")
        ip.cidr_id = cidr.id
        ip.asn_id = asn.id
        port = Port(ip_address_id=ip.id, number=443, protocol="tcp", state=PortState.OPEN)
        service = Service(port_id=port.id, name="https")
        cert = Certificate(hostname_id=host.id, subject="*.example.com", sha256="aa:bb", san=["www.example.com", "api.example.com"])
        dns = DNSRecord(name="api.example.com", record_type=DnsRecordType.A, value="93.184.216.34")
        ns = Nameserver(name="ns1.example.com", owner_domain="example.com")
        mx = MXRecord(name="example.com", domain_id=domain.id, exchange="mx1.example.com")
        target = Target(kind=TargetKind.DOMAIN, value="example.com", target_id="t1")
        return TopologySourceData(
            targets=[target],
            domains=[domain],
            subdomains=[sub],
            hostnames=[host],
            ip_addresses=[ip],
            cidrs=[cidr],
            asns=[asn],
            ports=[port],
            services=[service],
            certificates=[cert],
            nameservers=[ns],
            mx_records=[mx],
            dns_records=[dns],
        )

    def test_derives_expected_relationships(self) -> None:
        data = self._data()
        observations = RelationshipDeriver().derive(data)
        keys = {obs.rel_type.value for obs in observations}
        assert RelationshipType.PART_OF.value in keys          # subdomain→domain
        assert RelationshipType.RESOLVES_TO.value in keys      # hostname→ip
        assert RelationshipType.EXPOSES.value in keys          # ip→port
        assert RelationshipType.SERVES.value in keys           # port→service
        assert RelationshipType.USES.value in keys             # hostname→cert
        assert RelationshipType.CERTIFICATE_FOR.value in keys  # cert→san
        assert RelationshipType.DELEGATED_TO.value in keys     # domain→ns
        assert RelationshipType.MAILS_TO.value in keys         # domain→mx
        assert RelationshipType.DISCOVERED_BY.value in keys    # source_tool
        assert RelationshipType.BELONGS_TO.value in keys       # target
        assert RelationshipType.ANNOUNCED_BY.value in keys     # ip→asn

    def test_derives_part_of_for_hostname_suffix(self) -> None:
        data = self._data()
        observations = RelationshipDeriver().derive(data)
        part_of = [
            obs
            for obs in observations
            if obs.rel_type == RelationshipType.PART_OF
            and obs.source.kind == EntityKind.HOSTNAME
            and obs.target.name == "example.com"
        ]
        assert part_of, "hostname api.example.com should be PART_OF example.com"

    def test_derives_technology_uses_relationships(self) -> None:
        from hunterx.domain.entities.tidb.technology import TechnologyObservation as TidbTechObservation

        data = self._data()
        data.technology_observations = [
            TidbTechObservation(
                asset="api.example.com",
                asset_type="hostname",
                canonical_name="Nginx",
                software_version="1.24.0",
                category="web-server",
                family="web-server",
                tool_id="httpx",
            ),
            TidbTechObservation(
                asset="api.example.com",
                asset_type="hostname",
                canonical_name="Cloudflare",
                category="cdn",
                family="cdn",
                tool_id="httpx",
            ),
        ]
        observations = RelationshipDeriver().derive(data)
        uses = [
            obs
            for obs in observations
            if obs.rel_type == RelationshipType.USES
            and obs.source.kind == EntityKind.HOSTNAME
            and obs.target.kind == EntityKind.WEB_SERVER
            and obs.target.name == "Nginx"
        ]
        assert uses, "hostname should USE Nginx web-server technology"
        cdn = [
            obs
            for obs in observations
            if obs.rel_type == RelationshipType.USES
            and obs.target.kind == EntityKind.CDN
            and obs.target.name == "Cloudflare"
        ]
        assert cdn, "hostname should USE Cloudflare CDN technology"
        assert uses[0].evidence["version"] == "1.24.0"

    def test_deriver_records_provenance(self) -> None:
        data = self._data()
        observations = RelationshipDeriver().derive(data)
        assert all(obs.source_name for obs in observations)
        assert all(obs.evidence for obs in observations)


class TestValidator:
    def test_self_loop_rejected(self) -> None:
        node = _node("hostname", "a.example.com")
        obs = _obs("resolves_to", node, node)
        errors = TopologyValidator().validate(obs)
        assert any("self-loop" in error for error in errors)

    def test_valid_observation_passes(self) -> None:
        obs = _obs("resolves_to", _node("hostname", "a.example.com"), _node("ip", "1.2.3.4"))
        assert TopologyValidator().validate(obs) == []

    def test_part_of_ip_inside_cidr(self) -> None:
        obs = _obs("part_of", _node("ip", "10.0.0.5"), _node("cidr", "10.0.0.0/8"))
        assert TopologyValidator().validate(obs) == []

    def test_part_of_ip_outside_cidr_rejected(self) -> None:
        obs = _obs("part_of", _node("ip", "11.0.0.5"), _node("cidr", "10.0.0.0/8"))
        errors = TopologyValidator().validate(obs)
        assert any("not inside" in error for error in errors)

    def test_validate_all_partitions(self) -> None:
        valid = _obs("resolves_to", _node("hostname", "a.example.com"), _node("ip", "1.2.3.4"))
        invalid = _obs("resolves_to", _node("hostname", "a.example.com"), _node("hostname", "a.example.com"))
        ok, bad = TopologyValidator().validate_all([valid, invalid])
        assert len(ok) == 1
        assert len(bad) == 1


class TestCorrelator:
    def test_deduplicates_duplicate_edges(self) -> None:
        host = _node("hostname", "a.example.com")
        ip = _node("ip", "1.2.3.4")
        observations = [
            _obs("resolves_to", host, ip, source_name="subfinder", observed_at="2026-01-01T00:00:00+00:00"),
            _obs("resolves_to", host, ip, source_name="nmap", observed_at="2026-01-02T00:00:00+00:00"),
        ]
        edges = TopologyCorrelator().correlate(observations)
        assert len(edges) == 1
        edge = edges[0]
        assert set(edge.sources) == {"subfinder", "nmap"}
        assert edge.first_seen == "2026-01-01T00:00:00+00:00"
        assert edge.last_seen == "2026-01-02T00:00:00+00:00"

    def test_preserves_separate_edges(self) -> None:
        host = _node("hostname", "a.example.com")
        ip1 = _node("ip", "1.2.3.4")
        ip2 = _node("ip", "5.6.7.8")
        edges = TopologyCorrelator().correlate(
            [_obs("resolves_to", host, ip1), _obs("resolves_to", host, ip2)]
        )
        assert len(edges) == 2

    def test_confidence_combines(self) -> None:
        host = _node("hostname", "a.example.com")
        ip = _node("ip", "1.2.3.4")
        edges = TopologyCorrelator().correlate(
            [_obs("resolves_to", host, ip, source_name="tidb", confidence=0.8)]
        )
        assert 0.8 <= edges[0].confidence <= 0.99

    def test_scope_enforcer_flags_third_party(self) -> None:
        policy = TopologyScopePolicy(authorized_domains={"example.com"}, allow_third_party=True)
        enforcer = TopologyScopeEnforcer(policy)
        observations = [
            _obs("resolves_to", _node("hostname", "a.example.com"), _node("ip", "1.2.3.4"))
        ]
        edges = TopologyCorrelator(scope=enforcer).correlate(observations)
        assert edges[0].in_scope is True  # one endpoint authorized


class TestConflicts:
    def test_conflicting_rel_types_detected(self) -> None:
        host = _node("hostname", "a.example.com")
        ip = _node("ip", "1.2.3.4")
        observations = [
            _obs("resolves_to", host, ip, source_name="tidb:ip"),
            _obs("hosted_on", host, ip, source_name="tidb:certificate"),
        ]
        conflicts = TopologyConflictResolver().detect(observations)
        assert len(conflicts) == 1
        conflict = conflicts[0]
        assert conflict.conflict_type == ConflictType.RELATIONSHIP_TYPE
        assert conflict.selected_value in {"resolves_to", "hosted_on"}
        assert conflict.reason

    def test_no_conflict_for_identical(self) -> None:
        host = _node("hostname", "a.example.com")
        ip = _node("ip", "1.2.3.4")
        observations = [
            _obs("resolves_to", host, ip, source_name="tidb"),
            _obs("resolves_to", host, ip, source_name="nmap"),
        ]
        assert TopologyConflictResolver().detect(observations) == []


class TestHistory:
    def _edge(self, rel: str, src: str, dst: str, *, first: str = "2026-01-01T00:00:00+00:00", last: str = "2026-01-01T00:00:00+00:00") -> GraphRelationship:
        return GraphRelationship(
            rel_type=rel,
            source=_node("hostname", src),
            target=_node("ip", dst),
            first_seen=first,
            last_seen=last,
        )

    def test_new_relationship_detected(self) -> None:
        current = {"k": self._edge("resolves_to", "a.example.com", "1.2.3.4")}
        _, changes = TopologyHistory().diff({}, current)
        assert len(changes) == 1
        assert changes[0].change_type == ChangeType.NEW

    def test_removed_relationship_detected(self) -> None:
        previous = {"k": self._edge("resolves_to", "a.example.com", "1.2.3.4")}
        _, changes = TopologyHistory().diff(previous, {})
        assert len(changes) == 1
        assert changes[0].change_type == ChangeType.REMOVED

    def test_first_seen_preserved_across_generations(self) -> None:
        previous = {"k": self._edge("resolves_to", "a.example.com", "1.2.3.4", first="2026-01-01T00:00:00+00:00", last="2026-01-01T00:00:00+00:00")}
        current = {"k": self._edge("resolves_to", "a.example.com", "1.2.3.4", first="2026-02-01T00:00:00+00:00", last="2026-02-01T00:00:00+00:00")}
        merged, changes = TopologyHistory().diff(previous, current)
        assert merged[0].first_seen == "2026-01-01T00:00:00+00:00"
        assert merged[0].last_seen == "2026-02-01T00:00:00+00:00"


class TestAnalyzer:
    def _edges(self) -> list[GraphRelationship]:
        host1 = _node("hostname", "a.example.com")
        host2 = _node("hostname", "b.example.com")
        ip = _node("ip", "1.2.3.4")
        return [
            GraphRelationship(rel_type="resolves_to", source=host1, target=ip),
            GraphRelationship(rel_type="resolves_to", source=host2, target=ip),
        ]

    def test_same_ip_cluster_detected(self) -> None:
        analysis = TopologyAnalyzer().analyze(self._edges(), now="2026-06-01T00:00:00+00:00")
        same_ip = [c for c in analysis.clusters if c.cluster_type == ClusterType.SAME_IP]
        assert same_ip
        assert same_ip[0].entity_keys == ["hostname:a.example.com", "hostname:b.example.com"]

    def test_shared_ip_edge_emitted(self) -> None:
        analysis = TopologyAnalyzer().analyze(self._edges(), now="2026-06-01T00:00:00+00:00")
        shared = [e for e in analysis.shared_relationships if e.rel_type == RelationshipType.SHARES_IP_WITH]
        assert len(shared) == 1

    def test_density(self) -> None:
        analysis = TopologyAnalyzer().analyze(self._edges(), now="2026-06-01T00:00:00+00:00")
        assert analysis.node_count == 3
        assert analysis.density > 0


class TestGraphAndPaths:
    def _graph(self) -> TopologyGraph:
        domain = _node("domain", "example.com")
        host = _node("hostname", "www.example.com")
        ip = _node("ip", "1.2.3.4")
        port = _node("port", "443/tcp")
        graph = TopologyGraph()
        graph.add(GraphRelationship(rel_type="part_of", source=host, target=domain))
        graph.add(GraphRelationship(rel_type="resolves_to", source=host, target=ip))
        graph.add(GraphRelationship(rel_type="exposes", source=ip, target=port))
        return graph

    def test_neighbors(self) -> None:
        graph = self._graph()
        neighbors = graph.neighbors("hostname:www.example.com")
        keys = {entry["key"] for entry in neighbors}
        assert keys == {"domain:example.com", "ip:1.2.3.4"}

    def test_descendants_and_ancestors(self) -> None:
        graph = self._graph()
        assert graph.descendants("hostname:www.example.com") == {
            "ip:1.2.3.4",
            "domain:example.com",
            "port:443/tcp",
        }
        assert graph.ancestors("port:443/tcp") == {"ip:1.2.3.4", "hostname:www.example.com"}

    def test_shortest_path(self) -> None:
        finder = TopologyPathFinder(self._graph())
        path = finder.shortest_path("domain:example.com", "port:443/tcp")
        assert path == ["domain:example.com", "hostname:www.example.com", "ip:1.2.3.4", "port:443/tcp"]

    def test_shortest_path_unreachable(self) -> None:
        graph = self._graph()
        graph.add(GraphRelationship(rel_type="resolves_to", source=_node("hostname", "x.example.com"), target=_node("ip", "9.9.9.9")))
        finder = TopologyPathFinder(graph)
        assert finder.shortest_path("hostname:x.example.com", "domain:example.com") == []

    def test_related_assets(self) -> None:
        finder = TopologyPathFinder(self._graph())
        related = finder.related_assets("ip:1.2.3.4", max_depth=2)
        assert "hostname:www.example.com" in related

    def test_shared_infrastructure_query(self) -> None:
        host1 = _node("hostname", "a.example.com")
        host2 = _node("hostname", "b.example.com")
        graph = TopologyGraph()
        graph.add(GraphRelationship(rel_type="shares_ip_with", source=host1, target=host2))
        edges = TopologyPathFinder(graph).shared_infrastructure(["hostname:a.example.com"])
        assert len(edges) == 1


class TestViews:
    def _relationships(self) -> list[GraphRelationship]:
        return [
            GraphRelationship(
                rel_type="resolves_to",
                source=_node("hostname", "www.example.com"),
                target=_node("ip", "1.2.3.4"),
            ),
            GraphRelationship(
                rel_type="exposes",
                source=_node("ip", "1.2.3.4"),
                target=_node("port", "443/tcp"),
            ),
        ]

    def test_asset_inventory_graph(self) -> None:
        view = TopologyViewBuilder().asset_inventory_graph(self._relationships())
        assert view["view"] == "asset_inventory"
        assert view["node_count"] == 3
        assert view["relationship_count"] == 2

    def test_network_graph_filters(self) -> None:
        view = TopologyViewBuilder().network_graph(self._relationships())
        assert view["view"] == "network"
        assert view["relationship_count"] == 1  # only exposes

    def test_service_graph(self) -> None:
        view = TopologyViewBuilder().service_graph(self._relationships())
        assert view["relationship_count"] == 1

    def test_external_attack_surface_excludes_out_of_scope(self) -> None:
        in_scope = GraphRelationship(
            rel_type="resolves_to",
            source=_node("hostname", "www.example.com"),
            target=_node("ip", "1.2.3.4"),
            in_scope=True,
        )
        out_scope = GraphRelationship(
            rel_type="resolves_to",
            source=_node("hostname", "www.example.com"),
            target=_node("ip", "9.9.9.9"),
            in_scope=False,
        )
        view = TopologyViewBuilder().external_attack_surface([in_scope, out_scope])
        assert view["relationship_count"] == 1

    def test_shared_infrastructure_view(self) -> None:
        from hunterx.domain.topology.models import TopologyCluster

        c = TopologyCluster(name="same_ip:1.2.3.4", cluster_type=ClusterType.SAME_IP, entity_keys=["hostname:a.example.com"])
        view = TopologyViewBuilder().shared_infrastructure([c], [])
        assert view["clusters"][0]["name"] == "same_ip:1.2.3.4"


class TestScope:
    def test_domain_authorized(self) -> None:
        policy = TopologyScopePolicy(authorized_domains={"example.com"})
        assert policy.allows(EntityKind.HOSTNAME, "www.example.com")
        assert not policy.allows(EntityKind.HOSTNAME, "www.attacker.com")

    def test_third_party_ip_not_promoted(self) -> None:
        policy = TopologyScopePolicy(authorized_domains={"example.com"}, authorized_cidrs=["1.2.3.0/24"], allow_third_party=True)
        enforcer = TopologyScopeEnforcer(policy)
        decision = enforcer.check(EntityKind.IP, "9.9.9.9")
        assert decision.in_scope is False
        assert decision.promotes is False

    def test_cidr_authorized(self) -> None:
        policy = TopologyScopePolicy(authorized_cidrs=["10.0.0.0/8"])
        assert policy.allows(EntityKind.IP, "10.1.2.3")


class TestStrategyBuilder:
    def test_defaults(self) -> None:
        strategy = TopologyStrategyBuilder().build(target_key="domain:example.com")
        assert strategy.target_key == "domain:example.com"
        assert "resolves_to" in strategy.relationship_types
        assert strategy.confidence_threshold == 0.5

    def test_mode_enum_accepted(self) -> None:
        from hunterx.domain.topology.enums import TopologyMode

        strategy = TopologyStrategyBuilder().build(target_key="d", mode=TopologyMode.INCREMENTAL)
        assert strategy.mode == "incremental"


class TestConfidence:
    def test_combine(self) -> None:
        engine = TopologyConfidenceEngine()
        assert engine.combine([1.0]) == 0.99
        assert engine.combine([0.5, 0.5]) > 0.7
        assert engine.combine([]) == 0.0

    def test_decay(self) -> None:
        engine = TopologyConfidenceEngine()
        assert engine.decay(1.0, age_days=0) == 1.0
        assert engine.decay(1.0, age_days=90, half_life_days=90) < 1.0

    def test_is_stale(self) -> None:
        engine = TopologyConfidenceEngine()
        assert engine.is_stale(last_seen="2020-01-01T00:00:00+00:00", now="2026-01-01T00:00:00+00:00", max_age_days=90)


class TestTidbBridge:
    def test_graph_relationship_to_tidb(self) -> None:
        edge = GraphRelationship(
            rel_type="resolves_to",
            source=_node("hostname", "www.example.com"),
            target=_node("ip", "1.2.3.4"),
            sources=["tidb"],
        )
        tidb = edge.to_tidb()
        assert tidb.rel_type == "resolves_to"
        assert tidb.source_key == "hostname:www.example.com"
        assert tidb.relationship_key == "resolves_to:hostname:www.example.com|ip:1.2.3.4"

    def test_graph_relationship_from_tidb(self) -> None:
        edge = GraphRelationship(
            rel_type="resolves_to",
            source=_node("hostname", "www.example.com"),
            target=_node("ip", "1.2.3.4"),
        )
        tidb = edge.to_tidb()
        restored = GraphRelationship.from_tidb(tidb)
        assert restored.key == edge.key
        assert restored.rel_type == RelationshipType.RESOLVES_TO
