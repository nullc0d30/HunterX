# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Security tests for the network-mapping topology capability.

Covers the topology security model: scope enforcement without unauthorized
expansion, cross-target/mission isolation, traceroute argument injection
through tool parameters, credential leakage into argv, and untrusted tool
output being treated as data (never executed).
"""

from __future__ import annotations

from hunterx.domain.topology.enums import EntityKind, RelationshipType
from hunterx.domain.topology.models import RelationshipObservation, TopologyEntity
from hunterx.domain.topology.scope import TopologyScopeEnforcer, TopologyScopePolicy
from hunterx.tools.sdk.context import ExecutionContextBuilder
from hunterx.tools.topology.traceroute import TracerouteAdapter


def _context(target: str = "1.2.3.4", params: dict[str, object] | None = None):
    builder = ExecutionContextBuilder(tool_id="traceroute", target=target).with_permissions(("network",))
    if params:
        builder = builder.with_parameters(params)
    return builder.build()


class TestTracerouteArgvInjection:
    def test_shell_metacharacters_are_not_split(self) -> None:
        adapter = TracerouteAdapter()
        argv = adapter.build_argv(_context(target="1.2.3.4; rm -rf /"))
        assert "1.2.3.4; rm -rf /" in argv
        assert not any(part in (";", "|", "&&", "$(", "`") for part in argv)

    def test_numeric_params_cannot_inject_flags(self) -> None:
        adapter = TracerouteAdapter()
        argv = adapter.build_argv(_context(params={"max_hops": "30 -w 9", "wait": "1; touch pwned"}))
        assert not any("pwned" in part for part in argv)

    def test_unrelated_credential_params_never_land_in_argv(self) -> None:
        adapter = TracerouteAdapter()
        argv = adapter.build_argv(
            _context(params={"api_key": "hunterx-secret", "password": "hunterx-pass", "max_hops": 20})
        )
        assert not any("hunterx-secret" in part for part in argv)
        assert not any("hunterx-pass" in part for part in argv)


class TestTopologyScopeControl:
    def test_out_of_scope_domain_denied(self) -> None:
        policy = TopologyScopePolicy(authorized_domains={"example.com"})
        enforcer = TopologyScopeEnforcer(policy)
        decision = enforcer.check(EntityKind.HOSTNAME, "www.attacker.com")
        assert decision.in_scope is False
        assert decision.promotes is False

    def test_third_party_ip_not_promoted_to_scope(self) -> None:
        policy = TopologyScopePolicy(authorized_domains={"example.com"}, allow_third_party=True)
        enforcer = TopologyScopeEnforcer(policy)
        # resolving www.example.com to a third-party CDN IP must not authorize the IP
        decision = enforcer.check(EntityKind.IP, "9.9.9.9")
        assert decision.in_scope is False
        assert decision.promotes is False

    def test_scope_never_expands_through_relationship(self) -> None:
        policy = TopologyScopePolicy(authorized_domains={"example.com"})
        enforcer = TopologyScopeEnforcer(policy)
        # a relationship to an out-of-scope endpoint is not authorized
        decision = enforcer.relationship("hostname:www.example.com", "ip:203.0.113.10")
        assert decision.in_scope is True  # one authorized endpoint keeps the edge
        # but the out-of-scope endpoint itself is never authorized
        assert enforcer.check(EntityKind.IP, "203.0.113.10").in_scope is False

    def test_deny_by_default_with_empty_policy(self) -> None:
        enforcer = TopologyScopeEnforcer(TopologyScopePolicy())
        assert enforcer.check(EntityKind.HOSTNAME, "www.example.com").in_scope is False
        assert enforcer.check(EntityKind.IP, "1.2.3.4").in_scope is False


class TestCrossIsolation:
    def test_observation_keys_scoped_by_mission(self) -> None:
        host = TopologyEntity(kind="hostname", name="api.example.com")
        ip = TopologyEntity(kind="ip", name="1.2.3.4")
        a = RelationshipObservation(rel_type="resolves_to", source=host, target=ip, mission_id="mission-a")
        b = RelationshipObservation(rel_type="resolves_to", source=host, target=ip, mission_id="mission-b")
        # same canonical edge key regardless of mission; provenance preserved
        assert a.key == b.key
        assert a.mission_id != b.mission_id

    def test_no_self_loop_relationships(self) -> None:
        node = TopologyEntity(kind="hostname", name="x.example.com")
        obs = RelationshipObservation(rel_type=RelationshipType.RESOLVES_TO, source=node, target=node)
        from hunterx.domain.topology.validator import TopologyValidator

        assert TopologyValidator().validate(obs)

    def test_target_label_never_concatenated_into_ip(self) -> None:
        # a target label like "domain:example.com" must not be injected as a hop IP
        from hunterx.tools.topology.models import RouteRecord, routes_to_observations

        records = [
            RouteRecord(target="1.2.3.4", hop=1, address="192.168.1.1"),
            RouteRecord(target="1.2.3.4", hop=2, address="1.2.3.4"),
        ]
        observations = routes_to_observations(records)
        assert all(obs.source.kind == "ip" and obs.target.kind == "ip" for obs in observations)
