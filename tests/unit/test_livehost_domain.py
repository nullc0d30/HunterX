# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tests for the Live Host & Service Discovery domain: models, normalization,
validation, confidence, scope, correlation, conflicts, history and strategy."""

from __future__ import annotations

import pytest

from hunterx.domain.livehost.confidence import LiveConfidenceEngine, LiveConfidencePolicy
from hunterx.domain.livehost.conflicts import LiveConflictResolver
from hunterx.domain.livehost.correlator import LiveCorrelator, correlate_observations
from hunterx.domain.livehost.history import LiveHistory
from hunterx.domain.livehost.models import (
    DiscoveryConflict,
    HostState,
    HttpFinding,
    LiveBatch,
    LiveHost,
    LiveTarget,
    PortFinding,
    PortState,
    ReachabilityMethod,
    ServiceFinding,
    TlsFinding,
    TransportProtocol,
    make_host,
    make_http,
    make_port,
    make_service,
    make_tls,
    observations_from_payload,
)
from hunterx.domain.livehost.normalizer import LiveNormalizer
from hunterx.domain.livehost.scope import LiveScopeEnforcer, LiveScopePolicy
from hunterx.domain.livehost.strategy import LiveStrategyBuilder
from hunterx.domain.livehost.validator import LiveValidator
from hunterx.domain.recon.models import ReconMode


def _host(address: str = "1.2.3.4", **kwargs: object) -> LiveHost:
    return make_host(address, **kwargs)


def _port(address: str = "1.2.3.4", port: int = 22, **kwargs: object) -> PortFinding:
    return make_port(address, port, **kwargs)


def _raw_port(port: int) -> PortFinding:
    """Build a :class:`PortFinding` bypassing ``__init__`` validation/clamping.

    Used to exercise the validator's defensive bounds checks that the model's
    clamping normally prevents from being reached.
    """
    finding = PortFinding.__new__(PortFinding)
    _set = object.__setattr__
    _set(finding, "address", "1.2.3.4")
    _set(finding, "port", port)
    _set(finding, "protocol", TransportProtocol.TCP)
    _set(finding, "state", PortState.OPEN)
    _set(finding, "reason", "")
    _set(finding, "tool_id", "")
    _set(finding, "source", "")
    _set(finding, "confidence", 1.0)
    _set(finding, "target_id", None)
    _set(finding, "observed_at", "2026-01-01T00:00:00Z")
    _set(finding, "execution_id", "")
    _set(finding, "correlation_id", "")
    _set(finding, "record_id", "raw")
    return finding


class TestLiveHostModel:
    def test_address_normalized_and_compressed(self) -> None:
        host = make_host(" 2001:0db8::0001 ")
        assert host.address == "2001:db8::1"
        assert host.ip_version == 6

    def test_empty_address_rejected(self) -> None:
        with pytest.raises(ValueError):
            LiveHost(address="   ")

    def test_key_is_host_address(self) -> None:
        a = _host("1.2.3.4")
        b = _host("1.2.3.4", tool_id="nmap")
        assert a.key() == b.key() == "host:1.2.3.4"

    def test_dict_round_trip(self) -> None:
        host = _host("1.2.3.4", state=HostState.REACHABLE, reachable=True, methods=(ReachabilityMethod.ICMP,))
        restored = LiveHost.from_dict(host.to_dict())
        assert restored == host

    def test_make_host_infers_ip_version(self) -> None:
        assert _host("10.0.0.1").ip_version == 4
        assert _host("::1").ip_version == 6


class TestPortFindingModel:
    def test_port_clamped(self) -> None:
        assert _port(port=70000).port == 65535
        assert _port(port=0).port == 1

    def test_key(self) -> None:
        a = _port(port=22)
        b = _port(port=22, tool_id="naabu")
        assert a.key() == b.key() == "port:1.2.3.4|tcp|22"

    def test_dict_round_trip(self) -> None:
        port = _port(port=443, state=PortState.FILTERED, reason="no-response")
        assert PortFinding.from_dict(port.to_dict()) == port

    def test_protocol_coerced_to_enum(self) -> None:
        port = make_port("1.2.3.4", 53, protocol="udp")
        assert port.protocol is TransportProtocol.UDP


class TestServiceFindingModel:
    def test_service_lowercased(self) -> None:
        service = make_service("1.2.3.4", 22, " SSH ")
        assert service.service == "ssh"

    def test_key_includes_service(self) -> None:
        a = make_service("1.2.3.4", 22, "ssh")
        b = make_service("1.2.3.4", 22, "ssh", tool_id="nmap")
        assert a.key() == b.key() == "service:1.2.3.4|tcp|22|ssh"

    def test_dict_round_trip_preserves_banner(self) -> None:
        service = make_service("1.2.3.4", 22, "ssh", banner="SSH-2.0-OpenSSH_8.9", evidence=("x", "y"))
        assert ServiceFinding.from_dict(service.to_dict()) == service


class TestTlsAndHttpModels:
    def test_sha256_lowercased(self) -> None:
        tls = make_tls("1.2.3.4", 443, sha256="AB" * 32)
        assert tls.sha256 == "ab" * 32

    def test_tls_dict_round_trip(self) -> None:
        tls = make_tls("1.2.3.4", 443, san=("a.example.com", "b.example.com"), ciphers=("TLS_AES_128",))
        assert TlsFinding.from_dict(tls.to_dict()) == tls

    def test_http_dict_round_trip(self) -> None:
        http = make_http("1.2.3.4", 80, status_code=200, server="nginx", tech_hints=("nginx", "http2"))
        restored = HttpFinding.from_dict(http.to_dict())
        assert restored == http
        assert restored.confidence == 1.0

    def test_observations_from_payload_dispatch(self) -> None:
        payload = {
            "observations": [
                _host("1.2.3.4").to_dict(),
                _port(port=22).to_dict(),
                make_service("1.2.3.4", 22, "ssh").to_dict(),
                make_tls("1.2.3.4", 443).to_dict(),
                make_http("1.2.3.4", 80).to_dict(),
                {"type": "bogus", "x": 1},
                "not-a-dict",
            ]
        }
        hosts, ports, services, tls, http = observations_from_payload(payload)
        assert len(hosts) == 1
        assert len(ports) == 1
        assert len(services) == 1
        assert len(tls) == 1
        assert len(http) == 1
        assert observations_from_payload(None) == ([], [], [], [], [])
        assert observations_from_payload({"observations": "nope"}) == ([], [], [], [], [])


class TestLiveBatch:
    def test_counts(self) -> None:
        batch = LiveBatch(mission_id="m1", correlation_id="c1", target=LiveTarget(value="1.2.3.4"))
        batch.add_host(_host("1.2.3.4"))
        batch.add_ports([_port(port=22), _port(port=80)])
        batch.add_service(make_service("1.2.3.4", 22, "ssh"))
        assert batch.host_count() == 1
        assert batch.port_count() == 2
        assert batch.open_port_count() == 2
        assert batch.service_count() == 1
        assert batch.distinct() == 4
        assert batch.total_records() == 4


class TestLiveNormalizer:
    def test_host_normalization_idempotent(self) -> None:
        normalizer = LiveNormalizer()
        host = _host("1.2.3.4", methods=(ReachabilityMethod.ICMP, ReachabilityMethod.ICMP), rtt_ms=5)
        once = normalizer.normalize_host(host)
        twice = normalizer.normalize_host(once)
        assert once == twice
        assert once.methods == (ReachabilityMethod.ICMP,)

    def test_ipv6_host_version_fixed(self) -> None:
        host = LiveHost(address="2001:db8::1", ip_version=4)
        normalized = LiveNormalizer().normalize_host(host)
        assert normalized.ip_version == 6

    def test_confidences_clamped(self) -> None:
        normalizer = LiveNormalizer()
        assert normalizer.normalize_port(_port(confidence=2.0)).confidence == 1.0
        assert normalizer.normalize_service(make_service("1.2.3.4", 22, "ssh", confidence=-1)).confidence == 0.0

    def test_service_whitespace_collapsed(self) -> None:
        service = make_service("1.2.3.4", 22, "ssh", product="  OpenSSH   9.0 ")
        normalized = LiveNormalizer().normalize_service(service)
        assert normalized.product == "OpenSSH 9.0"

    def test_normalize_batch_in_place(self) -> None:
        batch = LiveBatch(mission_id="m", correlation_id="c", target=LiveTarget(value="1.2.3.4"))
        batch.add_host(_host("1.2.3.4", methods=(ReachabilityMethod.ICMP, ReachabilityMethod.ICMP)))
        LiveNormalizer().normalize_batch(batch)
        assert batch.hosts[0].methods == (ReachabilityMethod.ICMP,)


class TestLiveValidator:
    def test_valid_host(self) -> None:
        result = LiveValidator().validate_host(_host("1.2.3.4"))
        assert result.valid
        assert result.status == "valid"

    def test_invalid_address_rejected(self) -> None:
        host = make_host("not-an-ip")
        assert not LiveValidator().validate_host(host).valid

    def test_mismatched_ip_version_rejected(self) -> None:
        host = LiveHost(address="2001:db8::1", ip_version=4)
        assert not LiveValidator().validate_host(host).valid

    def test_reachability_state_consistency(self) -> None:
        host = make_host("1.2.3.4", state=HostState.UNREACHABLE, reachable=True)
        assert not LiveValidator().validate_host(host).valid

    def test_port_bounds(self) -> None:
        validator = LiveValidator()
        assert validator.validate_port(_port(port=1)).valid
        assert not validator.validate_port(_raw_port(0)).valid
        assert not validator.validate_port(_raw_port(65536)).valid

    def test_service_needs_identity(self) -> None:
        assert not LiveValidator().validate_service(make_service("1.2.3.4", 22, "")).valid

    def test_unknown_fingerprint_method_rejected(self) -> None:
        service = make_service("1.2.3.4", 22, "ssh", fingerprint_method="bogus")
        assert not LiveValidator().validate_service(service).valid

    def test_tls_sha256_shape(self) -> None:
        assert LiveValidator().validate_tls(make_tls("1.2.3.4", 443, sha256="ab" * 32)).valid
        assert not LiveValidator().validate_tls(make_tls("1.2.3.4", 443, sha256="zz")).valid

    def test_http_scheme_and_status(self) -> None:
        assert LiveValidator().validate_http(make_http("1.2.3.4", 80, status_code=200)).valid
        assert not LiveValidator().validate_http(make_http("1.2.3.4", 80, scheme="ftp")).valid
        assert not LiveValidator().validate_http(make_http("1.2.3.4", 80, status_code=999)).valid

    def test_validate_observation_dispatch(self) -> None:
        validator = LiveValidator()
        assert validator.validate_observation(_host("1.2.3.4")).kind == "host"
        assert validator.validate_observation(_port(port=22)).kind == "port"
        assert validator.validate_observation(object()).kind == "unknown"


class TestLiveConfidenceEngine:
    def test_tool_base_reliability(self) -> None:
        engine = LiveConfidenceEngine()
        nmap_port = _port(port=22, tool_id="nmap")
        unknown_port = _port(port=22, tool_id="mystery")
        assert engine.observation_confidence(nmap_port) > engine.observation_confidence(unknown_port)

    def test_open_port_scores_above_filtered(self) -> None:
        engine = LiveConfidenceEngine()
        open_port = _port(port=22, state=PortState.OPEN, tool_id="nmap")
        filtered_port = _port(port=22, state=PortState.FILTERED, tool_id="nmap")
        assert engine.observation_confidence(open_port) > engine.observation_confidence(filtered_port)

    def test_reachability_method_factors(self) -> None:
        engine = LiveConfidenceEngine()
        syn = _host("1.2.3.4", methods=(ReachabilityMethod.TCP_SYN,), tool_id="nmap")
        dns = _host("1.2.3.4", methods=(ReachabilityMethod.DNS,), tool_id="nmap")
        assert engine.observation_confidence(syn) > engine.observation_confidence(dns)

    def test_merged_confidence_corroboration(self) -> None:
        engine = LiveConfidenceEngine()
        single = [_port(port=22, tool_id="nmap")]
        corroborated = [_port(port=22, tool_id="nmap"), _port(port=22, tool_id="naabu")]
        assert engine.merged_confidence(corroborated) > engine.merged_confidence(single)
        assert engine.merged_confidence([]) == 0.0

    def test_validation_factor(self) -> None:
        engine = LiveConfidenceEngine()
        good = make_service("1.2.3.4", 22, "ssh", tool_id="nmap")
        bad = make_service("1.2.3.4", 22, "ssh", tool_id="nmap")
        assert engine.observation_confidence(good) >= engine.observation_confidence(bad)

    def test_historical_and_freshness(self) -> None:
        engine = LiveConfidenceEngine()
        stable = engine.historical_confidence(0.9, observations=10, stable=True)
        unstable = engine.historical_confidence(0.9, observations=1, stable=False)
        assert stable > unstable
        fresh = engine.freshness_confidence(0.9, age_hours=0)
        stale = engine.freshness_confidence(0.9, age_hours=48)
        assert fresh >= stale

    def test_policy_unknown_defaults(self) -> None:
        policy = LiveConfidencePolicy()
        assert policy.base_for("unknown") == 0.2
        assert policy.validation_factor("nope") == 0.5


class TestLiveScope:
    def test_no_restrictions_allows_anything(self) -> None:
        enforcer = LiveScopeEnforcer()
        assert enforcer.allows_address("8.8.8.8").allowed
        assert enforcer.allows_port(80).allowed

    def test_address_scope(self) -> None:
        enforcer = LiveScopeEnforcer(LiveScopePolicy(root_cidrs=frozenset({"10.0.0.0/8"})))
        assert enforcer.allows_address("10.1.2.3").allowed
        assert not enforcer.allows_address("192.168.1.1").allowed

    def test_excluded_network_and_ip(self) -> None:
        policy = LiveScopePolicy(root_cidrs=frozenset({"10.0.0.0/8"}), excluded_cidrs=frozenset({"10.0.1.0/24"}))
        enforcer = LiveScopeEnforcer(policy)
        assert not enforcer.allows_address("10.0.1.5").allowed
        assert enforcer.allows_address("10.0.2.5").allowed

    def test_name_scope(self) -> None:
        enforcer = LiveScopeEnforcer(LiveScopePolicy(roots=frozenset({"example.com"})))
        assert enforcer.allows_name("api.example.com").allowed
        assert not enforcer.allows_name("example.org").allowed
        assert not enforcer.allows_name("evil-example.com").allowed

    def test_excluded_ports(self) -> None:
        enforcer = LiveScopeEnforcer(LiveScopePolicy(excluded_ports=frozenset({22})))
        assert not enforcer.allows_port(22).allowed
        assert enforcer.allows_port(80).allowed

    def test_cidr_must_be_subnet_of_authorized(self) -> None:
        enforcer = LiveScopeEnforcer(LiveScopePolicy(root_cidrs=frozenset({"10.0.0.0/16"})))
        assert enforcer.allows_cidr("10.0.1.0/24").allowed
        assert not enforcer.allows_cidr("10.1.0.0/16").allowed
        assert not enforcer.allows_cidr("not-a-cidr").allowed

    def test_allows_target_dispatch(self) -> None:
        enforcer = LiveScopeEnforcer(LiveScopePolicy(root_cidrs=frozenset({"10.0.0.0/8"})))
        assert enforcer.allows_target(LiveTarget(value="10.1.2.3", target_type="ip")).allowed
        assert enforcer.allows_target(LiveTarget(value="10.0.0.0/16", target_type="cidr")).allowed
        assert not enforcer.allows_target(LiveTarget(value="172.16.0.1", target_type="ip")).allowed

    def test_filter_observations(self) -> None:
        enforcer = LiveScopeEnforcer(LiveScopePolicy(root_cidrs=frozenset({"10.0.0.0/8"})))
        filtered = enforcer.filter_observations([_host("10.0.0.1"), _host("8.8.8.8")])
        assert len(filtered) == 1
        assert filtered[0].address == "10.0.0.1"

    def test_hostname_observation_checked(self) -> None:
        enforcer = LiveScopeEnforcer(LiveScopePolicy(roots=frozenset({"example.com"})))
        host = make_host("1.2.3.4", hostname="api.example.com")
        assert enforcer.allows_observation(host).allowed
        out = make_host("1.2.3.4", hostname="other.com")
        assert not enforcer.allows_observation(out).allowed

    def test_to_scope_mirror(self) -> None:
        policy = LiveScopePolicy(roots=frozenset({"example.com"}), root_cidrs=frozenset({"10.0.0.0/8"}))
        scope = policy.to_scope()
        assert "example.com" in scope.roots
        assert "10.0.0.0/8" in scope.includes


class TestLiveCorrelator:
    def test_corroborating_hosts_merge(self) -> None:
        a = _host("1.2.3.4", methods=(ReachabilityMethod.TCP_CONNECT,), tool_id="nmap", source="nmap")
        b = _host("1.2.3.4", methods=(ReachabilityMethod.ICMP,), tool_id="masscan", source="masscan")
        result = LiveCorrelator().correlate(hosts=[a, b])
        assert len(result.hosts) == 1
        assert len(result.hosts[0].methods) == 2
        assert result.merged >= 1

    def test_conflicting_port_states(self) -> None:
        open_port = _port(port=22, state=PortState.OPEN, tool_id="nmap", source="nmap")
        filtered = _port(port=22, state=PortState.FILTERED, tool_id="masscan", source="masscan")
        result = correlate_observations(ports=[open_port, filtered])
        assert len(result.ports) == 1
        assert len(result.conflicts) == 1
        conflict = result.conflicts[0]
        assert conflict.kind == "port"
        assert conflict.key == "1.2.3.4|tcp|22"
        assert conflict.selected == "open"
        assert len(conflict.observations) == 2

    def test_same_state_merges_without_conflict(self) -> None:
        a = _port(port=22, tool_id="nmap", source="nmap")
        b = _port(port=22, tool_id="naabu", source="naabu")
        result = correlate_observations(ports=[a, b])
        assert len(result.ports) == 1
        assert result.conflicts == ()

    def test_service_fingerprint_conflict(self) -> None:
        v1 = make_service("1.2.3.4", 80, "http", product="nginx", version="1.18", tool_id="nmap")
        v2 = make_service("1.2.3.4", 80, "http", product="nginx", version="1.20", tool_id="masscan")
        result = correlate_observations(services=[v1, v2])
        assert len(result.conflicts) == 1
        assert result.conflicts[0].kind == "service"

    def test_tls_certificate_conflict(self) -> None:
        t1 = make_tls("1.2.3.4", 443, sha256="ab" * 32, tool_id="nmap")
        t2 = make_tls("1.2.3.4", 443, sha256="cd" * 32, tool_id="masscan")
        result = correlate_observations(tls=[t1, t2])
        assert len(result.conflicts) == 1
        assert result.conflicts[0].kind == "tls"

    def test_scope_filters_out_of_scope(self) -> None:
        scope = LiveScopePolicy(root_cidrs=frozenset({"10.0.0.0/8"}))
        out = _port(address="8.8.8.8", port=80)
        inn = _port(address="10.0.0.1", port=80)
        result = LiveCorrelator(scope=scope).correlate(ports=[out, inn])
        assert len(result.ports) == 1
        assert result.scoped_out == 1

    def test_corroboration_raises_merged_confidence(self) -> None:
        engine = LiveConfidenceEngine()
        single = [_port(port=22, tool_id="nmap")]
        merged = [_port(port=22, tool_id="nmap"), _port(port=22, tool_id="naabu")]
        assert engine.merged_confidence(merged) > engine.merged_confidence(single)


class TestLiveConflictResolver:
    def test_most_confident_strategy(self) -> None:
        resolver = LiveConflictResolver()
        conflict = DiscoveryConflict(kind="port", key="x", selected="open")
        a = _port(port=22, state=PortState.OPEN, tool_id="nmap")
        b = _port(port=22, state=PortState.FILTERED, tool_id="tcp-connect")
        selected = resolver.select(conflict, [a, b])
        assert selected.state is PortState.OPEN

    def test_most_recent_strategy(self) -> None:
        resolver = LiveConflictResolver(strategy="most-recent")
        conflict = DiscoveryConflict(kind="port", key="x", selected="open")
        a = _port(port=22, state=PortState.OPEN, observed_at="2026-01-01T00:00:00Z")
        b = _port(port=22, state=PortState.FILTERED, observed_at="2026-06-01T00:00:00Z")
        selected = resolver.select(conflict, [a, b])
        assert selected.state is PortState.FILTERED

    def test_unknown_strategy_rejected(self) -> None:
        with pytest.raises(ValueError):
            LiveConflictResolver(strategy="all-values")

    def test_empty_candidates_rejected(self) -> None:
        with pytest.raises(ValueError):
            LiveConflictResolver().select(DiscoveryConflict(kind="port", key="x", selected="open"), [])


class TestLiveHistory:
    def test_port_state_change_detected(self) -> None:
        historical = [_port(port=22, state=PortState.CLOSED, observed_at="2026-01-01T00:00:00Z")]
        current = [_port(port=22, state=PortState.OPEN, observed_at="2026-02-01T00:00:00Z")]
        comparison = LiveHistory().compare(historical, current)
        assert len(comparison.changes) == 1
        change = comparison.changes[0]
        assert change.change_type == "changed"
        assert change.previous == "closed"
        assert change.current == "open"
        assert change.kind == "port"

    def test_added_and_removed(self) -> None:
        history = LiveHistory()
        historical = [_port(port=22)]
        current = [_port(port=22), _port(port=80)]
        comparison = history.compare(historical, current)
        kinds = {change.change_type for change in comparison.changes}
        assert kinds == {"added"}

        comparison = history.compare(current, historical)
        kinds = {change.change_type for change in comparison.changes}
        assert kinds == {"removed"}

    def test_service_fingerprint_change(self) -> None:
        historical = [make_service("1.2.3.4", 80, "http", product="nginx", version="1.18")]
        current = [make_service("1.2.3.4", 80, "http", product="nginx", version="1.20")]
        comparison = LiveHistory().compare(historical, current)
        assert comparison.changes[0].change_type == "changed"

    def test_summarize_and_by_kind(self) -> None:
        history = LiveHistory()
        comparison = history.compare(
            [_port(port=22), make_tls("1.2.3.4", 443, sha256="ab" * 32)],
            [_port(port=22), _port(port=80)],
        )
        summary = history.summarize(comparison)
        assert summary["added"] >= 1
        assert summary["removed"] >= 1
        assert history.by_kind(comparison, "port") == [change for change in comparison.changes if change.kind == "port"]

    def test_unchanged_counter(self) -> None:
        comparison = LiveHistory().compare(
            [_port(port=22), _port(port=80)],
            [_port(port=22), _port(port=80)],
        )
        assert comparison.unchanged == 2
        assert comparison.changes == ()


class TestLiveStrategyBuilder:
    def test_target_kind_inference(self) -> None:
        builder = LiveStrategyBuilder()
        assert builder.build("10.0.0.1").target_kind == "ip"
        assert builder.build("10.0.0.0/24").target_kind == "cidr"
        assert builder.build("example.com").target_kind == "domain"
        assert builder.build("db.internal").target_kind == "domain"

    def test_active_mode_defaults(self) -> None:
        strategy = LiveStrategyBuilder().build("10.0.0.1", mode=ReconMode.HYBRID)
        assert strategy.with_service_detection
        assert strategy.with_tls
        assert strategy.with_http
        assert strategy.tools == ("nmap", "masscan", "naabu", "tcp-connect")

    def test_passive_mode_fails_closed(self) -> None:
        strategy = LiveStrategyBuilder().build("10.0.0.1", mode=ReconMode.PASSIVE)
        assert strategy.tools == ()
        assert not strategy.with_service_detection
        assert not strategy.with_tls

    def test_explicit_ports_and_features(self) -> None:
        strategy = LiveStrategyBuilder().build("10.0.0.1", ports=(80, 443), with_http=False)
        assert strategy.ports == (80, 443)
        assert not strategy.with_http
        assert strategy.max_concurrency >= 1

    def test_explicit_tools_override_defaults(self) -> None:
        strategy = LiveStrategyBuilder().build("10.0.0.1", tools=("nmap",))
        assert strategy.tools == ("nmap",)

    def test_invalid_protocol_coerced_to_tcp(self) -> None:
        strategy = LiveStrategyBuilder().build("10.0.0.1", protocol="sctp")
        assert strategy.protocol == "tcp"
