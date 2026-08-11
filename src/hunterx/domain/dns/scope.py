# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Scope enforcement for DNS intelligence.

Decides whether a DNS name or address may be collected, queried or persisted
based on the mission's authorized targets, excluded names and excluded
networks. The enforcer is pure and deterministic: the same inputs always yield
the same decision, with a human-readable reason for every denial.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from hunterx.domain.dns.models import DnsRecord, normalize_hostname
from hunterx.domain.value_objects.scope import Scope


@dataclass(frozen=True, slots=True)
class ScopePolicy:
    """The DNS scope policy for a mission.

    Attributes:
        roots: authorized root domains (e.g. ``example.com``). A name is in
            scope when it is a root or a descendant of a root.
        root_cidrs: authorized CIDRs whose addresses may be collected.
        excludes: names that are explicitly out of scope (exact or suffix).
        excluded_cidrs: networks whose addresses are out of scope.
        excluded_ip: individual out-of-scope addresses.

    """

    roots: frozenset[str] = frozenset()
    root_cidrs: frozenset[str] = frozenset()
    excludes: frozenset[str] = frozenset()
    excluded_cidrs: frozenset[str] = frozenset()
    excluded_ip: frozenset[str] = frozenset()

    def to_scope(self) -> Scope:
        """Return a :class:`Scope` mirror of this policy for generic use."""
        return Scope(
            roots=tuple(sorted(self.roots)),
            includes=tuple(sorted(self.root_cidrs)),
            excludes=tuple(sorted(self.excludes)) + tuple(sorted(self.excluded_cidrs)) + tuple(sorted(self.excluded_ip)),
        )


@dataclass(frozen=True, slots=True)
class ScopeDecision:
    """The outcome of a scope check.

    Attributes:
        allowed: whether the resource is in scope.
        reason: human-readable explanation of the decision.

    """

    allowed: bool
    reason: str = ""

    def __bool__(self) -> bool:
        return self.allowed


class ScopeEnforcer:
    """Evaluate names and addresses against a :class:`ScopePolicy`."""

    def __init__(self, policy: ScopePolicy | None = None) -> None:
        self._policy = policy or ScopePolicy()
        self._root_networks = _compile_networks(policy.root_cidrs) if policy else []
        self._excluded_networks = _compile_networks(policy.excluded_cidrs) if policy else []
        self._excluded_ips = _compile_ips(policy.excluded_ip) if policy else []

    @property
    def policy(self) -> ScopePolicy:
        """Return the active policy."""
        return self._policy

    def allows_name(self, name: str) -> ScopeDecision:
        """Return whether ``name`` is an in-scope domain/subdomain."""
        normalized = normalize_hostname(name)
        if _is_ip(normalized):
            return self.allows_address(normalized)
        if _is_excluded(normalized, self._policy.excludes):
            return ScopeDecision(False, f"'{normalized}' matches an excluded name")
        if not self._policy.roots:
            return ScopeDecision(True, "no root domains configured")
        if _matches_root(normalized, self._policy.roots):
            return ScopeDecision(True, f"'{normalized}' is within an authorized root")
        return ScopeDecision(False, f"'{normalized}' is not within any authorized root")

    def allows_address(self, address: str) -> ScopeDecision:
        """Return whether ``address`` is an in-scope address."""
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            return ScopeDecision(False, f"'{address}' is not a valid address")
        if _ip_in_networks(ip, self._excluded_networks) or ip.compressed in self._excluded_ips:
            return ScopeDecision(False, f"'{address}' matches an excluded network/address")
        if not self._root_networks:
            return ScopeDecision(True, "no CIDR restrictions configured")
        if _ip_in_networks(ip, self._root_networks):
            return ScopeDecision(True, f"'{address}' is within an authorized CIDR")
        return ScopeDecision(False, f"'{address}' is not within any authorized CIDR")

    def allows_record(self, record: DnsRecord) -> ScopeDecision:
        """Return whether a record may be persisted (owner name + value in scope)."""
        name_decision = self.allows_name(record.name)
        if not name_decision.allowed:
            return name_decision
        if _is_ip(record.value):
            value_decision = self.allows_address(record.value)
            if not value_decision.allowed:
                return value_decision
        return ScopeDecision(True, f"'{record.name}' is in scope")

    def filter_records(self, records: Iterable[DnsRecord]) -> list[DnsRecord]:
        """Return only the records allowed by this policy."""
        return [record for record in records if self.allows_record(record).allowed]

    def allowed_names(self, names: Iterable[str]) -> list[str]:
        """Return only the in-scope names from ``names``."""
        return [name for name in names if self.allows_name(name).allowed]


def _compile_networks(cidrs: Iterable[str]) -> list[ipaddress._BaseNetwork[Any]]:
    """Compile CIDR strings into network objects, ignoring invalid input."""
    networks: list[ipaddress._BaseNetwork[Any]] = []
    for cidr in cidrs:
        try:
            networks.append(ipaddress.ip_network(cidr, strict=False))
        except ValueError:
            continue
    return networks


def _compile_ips(addresses: Iterable[str]) -> frozenset[str]:
    """Compile a set of canonical addresses, ignoring invalid input."""
    return frozenset(
        ipaddress.ip_address(address).compressed
        for address in addresses
        if _is_ip(address)
    )


def _ip_in_networks(ip: ipaddress._BaseAddress, networks: Iterable[ipaddress._BaseNetwork[Any]]) -> bool:
    """Return whether an address falls within any network."""
    return any(ip in network for network in networks)


def _is_ip(value: str) -> bool:
    """Return whether ``value`` parses as an IP address."""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _matches_root(name: str, roots: Iterable[str]) -> bool:
    """Return whether ``name`` equals or is a descendant of a root."""
    lowered = name.lower().rstrip(".")
    for root in roots:
        root_norm = normalize_hostname(root)
        if lowered == root_norm or lowered.endswith("." + root_norm):
            return True
    return False


def _is_excluded(name: str, excludes: Iterable[str]) -> bool:
    """Return whether ``name`` matches an exact exclusion or its suffix."""
    lowered = name.lower().rstrip(".")
    for excluded in excludes:
        excluded_norm = normalize_hostname(excluded)
        if lowered == excluded_norm or lowered.endswith("." + excluded_norm):
            return True
    return False
