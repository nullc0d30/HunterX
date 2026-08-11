# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Cloud intelligence scope enforcement.

The scope policy mirrors the recon/web/auth policies: authorized roots, CIDRs,
IPs, exclusions and URL patterns. Scope is enforced at target admission and per
observation so discovered cloud intelligence never expands a mission beyond its
authorized boundary.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from hunterx.domain.cloud.models import ASSET_DOMAIN, ASSET_HOSTNAME, ASSET_IP, ASSET_URL, CloudTarget
from hunterx.domain.value_objects.scope import Scope


@dataclass(frozen=True, slots=True)
class CloudScopePolicy:
    """Authorized target boundary for cloud intelligence.

    Attributes:
        roots: authorized root domains.
        root_cidrs: authorized network ranges.
        excludes: out-of-scope hostnames/domains.
        excluded_cidrs: out-of-scope network ranges.
        excluded_ip: out-of-scope IP addresses.
        excluded_url_patterns: out-of-scope URL substrings.
        deny_by_default: when ``True`` require an explicit root match.
        fail_open_empty_policy: when ``True`` an empty policy allows everything.

    """

    roots: frozenset[str] = frozenset()
    root_cidrs: frozenset[str] = frozenset()
    excludes: frozenset[str] = frozenset()
    excluded_cidrs: frozenset[str] = frozenset()
    excluded_ip: frozenset[str] = frozenset()
    excluded_url_patterns: frozenset[str] = frozenset()
    deny_by_default: bool = False
    fail_open_empty_policy: bool = True

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
    """The result of a scope check."""

    allowed: bool
    reason: str = ""

    def __bool__(self) -> bool:
        return self.allowed


class CloudScopeEnforcer:
    """Enforce the cloud scope policy on targets and observations."""

    def __init__(self, policy: CloudScopePolicy | None = None) -> None:
        self._policy = policy or CloudScopePolicy()
        self._excluded_networks = _compile_networks(self._policy.excluded_cidrs)
        self._authorized_networks = _compile_networks(self._policy.root_cidrs)
        self._excluded_ips = {str(ip) for ip in self._policy.excluded_ip}
        self._empty = not (
            self._policy.roots or self._authorized_networks or self._excluded_networks or self._excluded_ips
        )

    @property
    def policy(self) -> CloudScopePolicy:
        """Return the enforced scope policy."""
        return self._policy

    def allows_target(self, target: CloudTarget) -> ScopeDecision:
        """Check whether a cloud intelligence target is authorized."""
        if target.target_type == ASSET_URL:
            return self.allows_url(target.value)
        if target.target_type == ASSET_IP:
            return self.allows_address(target.value)
        return self.allows_name(target.value, target_type=target.target_type)

    def allows_address(self, address: str) -> ScopeDecision:
        """Check whether an IP/network is authorized."""
        candidate = str(address).strip()
        try:
            network = ipaddress.ip_network(candidate, strict=False)
        except ValueError:
            return ScopeDecision(False, "not a valid IP address or network")
        if _network_in(network, self._excluded_networks):
            return ScopeDecision(False, "address is excluded")
        if not self._authorized_networks and self._policy.fail_open_empty_policy:
            return ScopeDecision(True, "no authorized networks configured (fail-open)")
        if self._policy.deny_by_default:
            return ScopeDecision(False, "deny-by-default without an authorized network")
        return ScopeDecision(True, "no authorized networks configured")

    def allows_name(self, name: str, *, target_type: str = ASSET_HOSTNAME) -> ScopeDecision:
        """Check whether a hostname/domain is authorized."""
        candidate = str(name).strip().lower().rstrip(".")
        if not candidate:
            return ScopeDecision(False, "empty name")
        if _is_ip(candidate):
            return self.allows_address(candidate)
        for excluded in self._policy.excludes:
            lowered = excluded.lower()
            if candidate == lowered or candidate.endswith(f".{lowered.lstrip('.')}"):
                return ScopeDecision(False, "name is excluded")
        if self._policy.deny_by_default and not self._policy.roots:
            return ScopeDecision(False, "deny-by-default without authorized roots")
        if not self._policy.roots and self._policy.fail_open_empty_policy:
            return ScopeDecision(True, "no authorized roots configured (fail-open)")
        for root in self._policy.roots:
            lowered = root.lower().lstrip(".")
            if candidate == lowered or candidate.endswith(f".{lowered}"):
                return ScopeDecision(True, "name matches an authorized root")
        return ScopeDecision(False, "name is not within an authorized root")

    def allows_url(self, url: str) -> ScopeDecision:
        """Check whether a URL is authorized (host + pattern exclusions)."""
        from urllib.parse import urlsplit

        candidate = str(url).strip()
        try:
            parts = urlsplit(candidate if "://" in candidate else f"https://{candidate}")
        except ValueError:
            return ScopeDecision(False, "malformed URL")
        host = (parts.hostname or "").lower()
        decision = self.allows_name(host, target_type=ASSET_DOMAIN)
        if not decision.allowed:
            return decision
        lowered = candidate.lower()
        for pattern in self._policy.excluded_url_patterns:
            if str(pattern).lower() in lowered:
                return ScopeDecision(False, "URL matches an excluded pattern")
        return ScopeDecision(True, "URL host is authorized")

    def allows_observation(self, observation: Any) -> ScopeDecision:
        """Check whether an observation's origin is authorized for persistence.

        Observations are scoped by their ``target_key`` first (every analyzer
        record carries the admitted target); the ``origin`` attribute is used
        as a fallback. Observations with neither are treated as allowed
        (fail-open), mirroring the empty-policy behaviour; the target admission
        gate remains the authoritative boundary.
        """
        target_key = getattr(observation, "target_key", "")
        if target_key:
            return self.allows_name(str(target_key))
        origin = getattr(observation, "origin", None)
        if origin:
            return self.allows_url(origin) if "://" in str(origin) else self.allows_name(str(origin))
        return ScopeDecision(True, "observation has no scoped origin (fail-open)")

    def filter_observations(self, observations: Iterable[Any]) -> list[Any]:
        """Return only observations allowed by scope."""
        return [obs for obs in observations if self.allows_observation(obs).allowed]


def _compile_networks(cidrs: Iterable[str]) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for cidr in cidrs:
        try:
            networks.append(ipaddress.ip_network(str(cidr), strict=False))
        except ValueError:
            continue
    return networks


def _network_in(
    network: ipaddress.IPv4Network | ipaddress.IPv6Network,
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network],
) -> bool:
    for candidate in networks:
        if network.version != candidate.version:
            continue
        if network.subnet_of(candidate) or candidate.subnet_of(network):  # type: ignore[arg-type]
            return True
    return False


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False
