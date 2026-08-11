# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Scope enforcement for authorization intelligence.

Decides whether a hostname, domain, IP or URL may be analysed or persisted
based on the mission's authorized targets, excluded names, excluded addresses
and excluded URL patterns. The enforcer is pure and deterministic: the same
inputs always yield the same decision, with a human-readable reason for every
denial.

Discovered authorization intelligence is never used to silently expand scope:
the enforcer authorizes the *asset* being analysed, never the roles, resources
or administrative surfaces found on it.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from hunterx.domain.authorization.models import (
    ASSET_HOSTNAME,
    ASSET_IP,
    ASSET_URL,
    AuthorizationTarget,
)
from hunterx.domain.value_objects.scope import Scope


@dataclass(frozen=True, slots=True)
class AuthorizationScopePolicy:
    """The authorization intelligence scope policy for a mission.

    Attributes:
        roots: authorized root domains (e.g. ``example.com``). A hostname is in
            scope when it is a root or a descendant of a root.
        root_cidrs: authorized CIDRs whose addresses may be analysed.
        excludes: hostnames/domains explicitly out of scope (exact or suffix).
        excluded_cidrs: networks whose addresses are out of scope.
        excluded_ip: individual out-of-scope addresses.
        excluded_url_patterns: URL substrings that are out of scope.

    """

    roots: frozenset[str] = frozenset()
    root_cidrs: frozenset[str] = frozenset()
    excludes: frozenset[str] = frozenset()
    excluded_cidrs: frozenset[str] = frozenset()
    excluded_ip: frozenset[str] = frozenset()
    excluded_url_patterns: frozenset[str] = frozenset()

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
        allowed: whether the asset is in scope.
        reason: human-readable explanation of the decision.

    """

    allowed: bool
    reason: str = ""

    def __bool__(self) -> bool:
        return self.allowed


class AuthorizationScopeEnforcer:
    """Evaluate assets and observations against an authorization scope policy."""

    def __init__(self, policy: AuthorizationScopePolicy | None = None) -> None:
        self._policy = policy or AuthorizationScopePolicy()
        self._root_networks = _compile_networks(self._policy.root_cidrs)
        self._excluded_networks = _compile_networks(self._policy.excluded_cidrs)
        self._excluded_ips = frozenset(_canonical_ip(address) for address in self._policy.excluded_ip if _is_ip(address))

    @property
    def policy(self) -> AuthorizationScopePolicy:
        """Return the active policy."""
        return self._policy

    def allows_asset(self, asset: str, asset_type: str = ASSET_HOSTNAME) -> ScopeDecision:
        """Return whether ``asset`` may be analysed."""
        if asset_type == ASSET_URL:
            return self.allows_url(asset)
        if asset_type == ASSET_IP:
            return self.allows_address(asset)
        return self.allows_name(asset)

    def allows_target(self, target: AuthorizationTarget) -> ScopeDecision:
        """Return whether a whole authorization target is in scope."""
        return self.allows_asset(target.value, target.target_type)

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

    def allows_url(self, url: str) -> ScopeDecision:
        """Return whether ``url`` is in scope (host in scope and no exclusion)."""
        host = _url_host(url)
        if host:
            decision = self.allows_name(host)
            if not decision.allowed:
                return decision
        for pattern in self._policy.excluded_url_patterns:
            if pattern and pattern.lower() in url.lower():
                return ScopeDecision(False, f"'{url}' matches an excluded URL pattern")
        return ScopeDecision(True, f"'{url}' is in scope")

    def allows_observation(self, observation: Any) -> ScopeDecision:
        """Return whether an observation may be persisted.

        The origin (or the asset, when no origin is attached) is checked; a
        discovered role/resource on an external host is never used to expand
        scope.
        """
        origin = str(getattr(observation, "origin", "") or "")
        if origin:
            return self.allows_url(origin) if "://" in origin else self.allows_name(origin)
        asset = str(getattr(observation, "asset", "") or getattr(observation, "url", "") or "")
        if not asset:
            return ScopeDecision(False, "observation has no resolvable origin/asset")
        return self.allows_url(asset) if "://" in asset else self.allows_name(asset)

    def filter_observations(self, observations: Iterable[Any]) -> list[Any]:
        """Return only the observations allowed by this policy."""
        return [observation for observation in observations if self.allows_observation(observation).allowed]


def _compile_networks(cidrs: Iterable[str]) -> list[ipaddress._BaseNetwork[Any]]:
    networks: list[ipaddress._BaseNetwork[Any]] = []
    for cidr in cidrs:
        try:
            networks.append(ipaddress.ip_network(cidr, strict=False))
        except ValueError:
            continue
    return networks


def _ip_in_networks(ip: ipaddress._BaseAddress, networks: Iterable[ipaddress._BaseNetwork[Any]]) -> bool:
    return any(ip in network for network in networks)


def _canonical_ip(value: str) -> str:
    try:
        return ipaddress.ip_address(value).compressed
    except ValueError:
        return str(value).strip()


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _normalize_name(value: str) -> str:
    return str(value).strip().lower().rstrip(".")


def _matches_root(name: str, roots: Iterable[str]) -> bool:
    lowered = name.lower().rstrip(".")
    for root in roots:
        root_norm = _normalize_name(root)
        if lowered == root_norm or lowered.endswith("." + root_norm):
            return True
    return False


def _is_excluded(name: str, excludes: Iterable[str]) -> bool:
    lowered = name.lower().rstrip(".")
    for excluded in excludes:
        excluded_norm = _normalize_name(excluded)
        if lowered == excluded_norm or lowered.endswith("." + excluded_norm):
            return True
    return False


def _url_host(url: str) -> str:
    candidate = str(url).strip().lower()
    if not candidate.startswith(("http://", "https://")):
        return _normalize_name(candidate)
    try:
        from urllib.parse import urlparse

        return _normalize_name(urlparse(candidate).hostname or "")
    except ValueError:  # pragma: no cover - defensive
        return ""
