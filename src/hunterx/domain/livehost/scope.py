# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Scope enforcement for Live Host & Service Discovery.

Decides whether a host, address, CIDR, name or port may be scanned, collected
or persisted based on the mission's authorized targets, excluded networks,
excluded names and excluded ports. The enforcer is pure and deterministic: the
same inputs always yield the same decision, with a human-readable reason for
every denial.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from hunterx.domain.livehost.models import (
    HttpFinding,
    LiveHost,
    LiveTarget,
    PortFinding,
    ServiceFinding,
    TlsFinding,
)
from hunterx.domain.value_objects.scope import Scope


@dataclass(frozen=True, slots=True)
class LiveScopePolicy:
    """The live discovery scope policy for a mission.

    Attributes:
        roots: authorized root domains (e.g. ``example.com``). A hostname is in
            scope when it is a root or a descendant of a root.
        root_cidrs: authorized CIDRs whose addresses may be scanned/persisted.
        excludes: hostnames that are explicitly out of scope (exact or suffix).
        excluded_cidrs: networks whose addresses are out of scope.
        excluded_ip: individual out-of-scope addresses.
        excluded_ports: ports that must never be scanned regardless of target.

    """

    roots: frozenset[str] = frozenset()
    root_cidrs: frozenset[str] = frozenset()
    excludes: frozenset[str] = frozenset()
    excluded_cidrs: frozenset[str] = frozenset()
    excluded_ip: frozenset[str] = frozenset()
    excluded_ports: frozenset[int] = frozenset()

    def to_scope(self) -> Scope:
        """Return a :class:`Scope` mirror of this policy for generic use."""
        return Scope(
            roots=tuple(sorted(self.roots)),
            includes=tuple(sorted(self.root_cidrs)),
            excludes=tuple(sorted(self.excludes))
            + tuple(sorted(self.excluded_cidrs))
            + tuple(sorted(self.excluded_ip)),
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


class LiveScopeEnforcer:
    """Evaluate targets, addresses, names and ports against a policy."""

    def __init__(self, policy: LiveScopePolicy | None = None) -> None:
        self._policy = policy or LiveScopePolicy()
        self._root_networks = _compile_networks(policy.root_cidrs) if policy else []
        self._excluded_networks = _compile_networks(policy.excluded_cidrs) if policy else []
        self._excluded_ips = _compile_ips(policy.excluded_ip) if policy else []

    @property
    def policy(self) -> LiveScopePolicy:
        """Return the active policy."""
        return self._policy

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

    def allows_name(self, name: str) -> ScopeDecision:
        """Return whether ``name`` is an in-scope domain/subdomain/hostname."""
        normalized = _normalize_name(name)
        if _is_ip(normalized):
            return self.allows_address(normalized)
        if _is_excluded(normalized, self._policy.excludes):
            return ScopeDecision(False, f"'{normalized}' matches an excluded name")
        if not self._policy.roots:
            return ScopeDecision(True, "no root domains configured")
        if _matches_root(normalized, self._policy.roots):
            return ScopeDecision(True, f"'{normalized}' is within an authorized root")
        return ScopeDecision(False, f"'{normalized}' is not within any authorized root")

    def allows_port(self, port: int) -> ScopeDecision:
        """Return whether ``port`` may be scanned (not explicitly excluded)."""
        if port in self._policy.excluded_ports:
            return ScopeDecision(False, f"port {port} is explicitly excluded")
        return ScopeDecision(True, f"port {port} is not excluded")

    def allows_target(self, target: LiveTarget) -> ScopeDecision:
        """Return whether a whole discovery target is in scope."""
        value = target.value.strip()
        if "/" in value:
            return self.allows_cidr(value)
        if _is_ip(value):
            return self.allows_address(value)
        return self.allows_name(value)

    def allows_cidr(self, cidr: str) -> ScopeDecision:
        """Return whether ``cidr`` is entirely within an authorized network.

        A CIDR is only scannable when every address it covers is authorized, so
        the capability never sweeps beyond the mission's boundaries.
        """
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            return ScopeDecision(False, f"'{cidr}' is not a valid CIDR")
        if _overlaps(network, self._excluded_networks):
            return ScopeDecision(False, f"'{cidr}' overlaps an excluded network")
        if not self._root_networks:
            return ScopeDecision(True, "no CIDR restrictions configured")
        if _subnet_of_any(network, self._root_networks):
            return ScopeDecision(True, f"'{cidr}' is within an authorized CIDR")
        return ScopeDecision(False, f"'{cidr}' is not within any authorized CIDR")

    def allows_observation(self, observation: object) -> ScopeDecision:
        """Return whether an observation may be persisted."""
        if isinstance(observation, LiveHost):
            address = self.allows_address(observation.address)
            if not address.allowed:
                return address
            if observation.hostname:
                return self.allows_name(observation.hostname)
            return ScopeDecision(True, f"'{observation.address}' is in scope")
        if isinstance(observation, (PortFinding, ServiceFinding, TlsFinding, HttpFinding)):
            address = self.allows_address(observation.address)
            if not address.allowed:
                return address
            return self.allows_port(observation.port)
        return ScopeDecision(False, "unknown observation kind")

    def filter_observations(self, observations: Iterable[object]) -> list[object]:
        """Return only the observations allowed by this policy."""
        return [observation for observation in observations if self.allows_observation(observation).allowed]


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
    return frozenset(ipaddress.ip_address(address).compressed for address in addresses if _is_ip(address))


def _ip_in_networks(ip: ipaddress._BaseAddress, networks: Iterable[ipaddress._BaseNetwork[Any]]) -> bool:
    """Return whether an address falls within any network."""
    return any(ip in network for network in networks)


def _overlaps(network: ipaddress._BaseNetwork[Any], networks: Iterable[ipaddress._BaseNetwork[Any]]) -> bool:
    """Return whether a network overlaps any of the given networks."""
    return any(network.overlaps(other) for other in networks)


def _subnet_of_any(network: ipaddress._BaseNetwork[Any], networks: Iterable[ipaddress._BaseNetwork[Any]]) -> bool:
    """Return whether ``network`` is a subnet of any of the given networks.

    ``subnet_of`` raises for mixed IPv4/IPv6 comparisons; those are treated as
    non-matching.
    """
    for other in networks:
        try:
            if network.subnet_of(other):
                return True
        except TypeError:
            continue
    return False


def _is_ip(value: str) -> bool:
    """Return whether ``value`` parses as an IP address."""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _normalize_name(value: str) -> str:
    """Lowercase a hostname and strip its trailing dot."""
    return str(value).strip().lower().rstrip(".")


def _matches_root(name: str, roots: Iterable[str]) -> bool:
    """Return whether ``name`` equals or is a descendant of a root."""
    lowered = name.lower().rstrip(".")
    for root in roots:
        root_norm = _normalize_name(root)
        if lowered == root_norm or lowered.endswith("." + root_norm):
            return True
    return False


def _is_excluded(name: str, excludes: Iterable[str]) -> bool:
    """Return whether ``name`` matches an exact exclusion or its suffix."""
    lowered = name.lower().rstrip(".")
    for excluded in excludes:
        excluded_norm = _normalize_name(excluded)
        if lowered == excluded_norm or lowered.endswith("." + excluded_norm):
            return True
    return False
