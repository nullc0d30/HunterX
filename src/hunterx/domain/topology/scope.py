# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Topology scope policy and enforcement.

Scope control is a hard requirement of the network-mapping capability: a
relationship is only incorporated into the canonical graph when its source data
is authorized and in-scope, and discovering new infrastructure (e.g. an IP or a
third-party CDN) never expands the scan scope. The policy is deliberately
deny-by-default.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

from hunterx.domain.topology.enums import EntityKind
from hunterx.domain.topology.keys import is_ip, normalize_domain


@dataclass(slots=True)
class TopologyScopePolicy:
    """Authorized roots for a topology build.

    Attributes:
        authorized_domains: registrable domains explicitly authorized.
        authorized_cidrs: CIDR networks authorized for IP-layer edges.
        authorized_ips: individual IPs authorized.
        authorized_target_ids: owning target ids authorized.
        allow_third_party: keep third-party (out-of-scope) endpoints as
            dangling references without promoting them to scan scope.
        max_hop_depth: maximum BFS hop depth for queries/paths (0 = unbounded).

    """

    authorized_domains: set[str] = field(default_factory=set)
    authorized_cidrs: list[str] = field(default_factory=list)
    authorized_ips: set[str] = field(default_factory=set)
    authorized_target_ids: set[str] = field(default_factory=set)
    allow_third_party: bool = True
    max_hop_depth: int = 0

    @property
    def _cidr_networks(self) -> list[ipaddress._BaseNetwork]:
        return [ipaddress.ip_network(net, strict=False) for net in self.authorized_cidrs]

    def add_domain(self, domain: str) -> None:
        """Authorize a registrable domain."""
        self.authorized_domains.add(normalize_domain(domain))

    def add_cidr(self, network: str) -> None:
        """Authorize a CIDR network."""
        self.authorized_cidrs.append(str(ipaddress.ip_network(network, strict=False)))

    def allows(self, kind: EntityKind | str, name: str) -> bool:
        """Return ``True`` when the entity is inside the authorized scope."""
        kind_enum = EntityKind(kind if isinstance(kind, str) else kind.value)
        name = (name or "").strip()
        if kind_enum in (EntityKind.DOMAIN, EntityKind.SUBDOMAIN, EntityKind.HOSTNAME, EntityKind.MX):
            host = normalize_domain(name)
            return any(host == root or host.endswith("." + root) for root in self.authorized_domains)
        if kind_enum == EntityKind.IP:
            if not is_ip(name):
                return False
            ip = ipaddress.ip_address(name)
            if name in self.authorized_ips:
                return True
            return any(ip in net for net in self._cidr_networks)
        if kind_enum == EntityKind.CIDR:
            return bool(self.authorized_cidrs)
        if kind_enum in (EntityKind.PORT, EntityKind.SERVICE):
            # Port/service nodes are never scope roots; they inherit scope from
            # their parent IP. They are treated as in-scope only when a parent
            # relation already passed; here we return False and rely on the
            # enforcer's transitive rule.
            return False
        if kind_enum in (EntityKind.CERTIFICATE, EntityKind.NAMESERVER, EntityKind.ASN, EntityKind.TOOL):
            return False
        if kind_enum in (EntityKind.ORGANIZATION, EntityKind.PROGRAM, EntityKind.TARGET):
            return False
        if kind_enum == EntityKind.ROUTE:
            return False
        if kind_enum == EntityKind.DNS_RECORD:
            return False
        return False

    def allows_target(self, target_id: str | None) -> bool:
        """Return ``True`` when a target id is authorized."""
        if not target_id:
            return False
        return target_id in self.authorized_target_ids


@dataclass(slots=True)
class ScopeDecision:
    """Result of enforcing scope on a node or relationship.

    Attributes:
        in_scope: whether the node is fully authorized.
        reason: human-readable explanation.
        promotes: whether the node is new scan scope (must never happen).

    """

    in_scope: bool
    reason: str
    promotes: bool = False


class TopologyScopeEnforcer:
    """Decide whether entities and relationships belong to the authorized scope."""

    def __init__(self, policy: TopologyScopePolicy) -> None:
        self._policy = policy

    @property
    def policy(self) -> TopologyScopePolicy:
        """Return the policy backing this enforcer."""
        return self._policy

    def check(self, kind: EntityKind | str, name: str) -> ScopeDecision:
        """Return the scope decision for a single entity."""
        kind_enum = EntityKind(kind if isinstance(kind, str) else kind.value)
        if kind_enum in (EntityKind.PORT, EntityKind.SERVICE, EntityKind.CERTIFICATE, EntityKind.DNS_RECORD):
            return ScopeDecision(True, f"{kind_enum.value} nodes are derived; scope follows their parents")
        if self._policy.allows(kind_enum, name):
            return ScopeDecision(True, "authorized root or within authorized range")
        if kind_enum in (EntityKind.IP, EntityKind.HOSTNAME) and self._policy.allow_third_party:
            return ScopeDecision(False, "third-party endpoint; retained as reference only")
        return ScopeDecision(False, "not authorized")

    def relationship(self, source: str, target: str) -> ScopeDecision:
        """Return whether a source→target pair is in-scope.

        A relationship is in-scope when at least one endpoint is authorized and
        the relationship never promotes the other endpoint into scan scope.
        """
        source_allows = self._policy.allows(*_split_key(source))
        target_allows = self._policy.allows(*_split_key(target))
        if source_allows or target_allows:
            return ScopeDecision(True, "at least one endpoint is authorized; no scope expansion")
        return ScopeDecision(False, "neither endpoint is authorized")


def _split_key(key: str) -> tuple[str, str]:
    kind, _, name = key.partition(":")
    return kind, name
