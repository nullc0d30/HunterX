# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Scope enforcement for API intelligence.

Decides whether a hostname, domain, IP or URL may be analysed or persisted
based on the mission's authorized roots, exclusions and excluded URL patterns.
The enforcer is pure and deterministic: the same inputs always yield the same
decision, with a human-readable reason for every denial.

Discovered API intelligence is never used to silently expand scope: the
enforcer authorizes the *asset* being analysed, not the API surface found on
it. Spec fetching is restricted to the in-scope target origin.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from hunterx.domain.api.models import ApiTarget
from hunterx.domain.value_objects.scope import Scope


@dataclass(frozen=True, slots=True)
class ApiScopePolicy:
    """The API intelligence scope policy for a mission.

    Attributes:
        roots: authorized root domains/CIDRs (a hostname is in scope when it is
            a root or a descendant of a root, or when its address is inside an
            authorized CIDR).
        excludes: hostnames/domains explicitly out of scope (exact or suffix).
        excluded_cidrs: networks whose addresses are out of scope.
        excluded_ip: individual out-of-scope addresses.
        excluded_url_patterns: URL substrings that are out of scope.
        fail_open_empty_policy: whether an empty policy allows targets.

    """

    roots: frozenset[str] = frozenset()
    root_cidrs: frozenset[str] = frozenset()
    excludes: frozenset[str] = frozenset()
    excluded_cidrs: frozenset[str] = frozenset()
    excluded_ip: frozenset[str] = frozenset()
    excluded_url_patterns: frozenset[str] = frozenset()
    fail_open_empty_policy: bool = True

    @classmethod
    def from_scope(cls, scope: Scope | None) -> ApiScopePolicy:
        """Build a policy from a mission :class:`Scope`."""
        if scope is None:
            return cls(fail_open_empty_policy=True)
        roots = tuple(scope.roots or ()) + tuple(scope.includes or ())
        domains, cidrs = _split_roots(roots)
        return cls(
            roots=frozenset(domains),
            root_cidrs=frozenset(cidrs),
            excludes=frozenset(scope.excludes or ()),
            excluded_cidrs=frozenset(),
            excluded_ip=frozenset(),
            excluded_url_patterns=frozenset(),
            fail_open_empty_policy=True,
        )

    @classmethod
    def from_fields(
        cls,
        *,
        roots: Iterable[str] = (),
        root_cidrs: Iterable[str] = (),
        excludes: Iterable[str] = (),
        excluded_cidrs: Iterable[str] = (),
        excluded_ip: Iterable[str] = (),
        excluded_url_patterns: Iterable[str] = (),
        fail_open_empty_policy: bool = True,
    ) -> ApiScopePolicy:
        """Build a policy directly from field values (defaults fail-open)."""
        return cls(
            roots=frozenset(item for item in roots if item),
            root_cidrs=frozenset(item for item in root_cidrs if item),
            excludes=frozenset(item for item in excludes if item),
            excluded_cidrs=frozenset(item for item in excluded_cidrs if item),
            excluded_ip=frozenset(item for item in excluded_ip if item),
            excluded_url_patterns=frozenset(item for item in excluded_url_patterns if item),
            fail_open_empty_policy=fail_open_empty_policy,
        )

    def is_empty(self) -> bool:
        """Return whether no authorization rules are configured."""
        return not (self.roots or self.root_cidrs or self.excludes)


@dataclass(frozen=True, slots=True)
class ScopeDecision:
    """The result of a scope check.

    Attributes:
        allowed: whether the target is in scope.
        reason: human-readable explanation of the decision.

    """

    allowed: bool
    reason: str = ""

    def __bool__(self) -> bool:
        return self.allowed


class ApiScopeEnforcer:
    """Pure deterministic scope enforcement for API intelligence.

    Usage::

        enforcer = ApiScopeEnforcer(policy)
        decision = enforcer.allows_target(ApiTarget(value="api.example.com", target_type="hostname"))
        decision = enforcer.allows_observation(origin_key="https://api.example.com")
    """

    def __init__(self, policy: ApiScopePolicy | None = None) -> None:
        if policy is None:
            policy = ApiScopePolicy()
        self._policy = policy
        self._normalized_excludes = {self._normalize_hostname(item) for item in policy.excludes if item}
        self._normalized_ip = {self._normalize_hostname(item) for item in policy.excluded_ip if item}
        self._excluded_cidr_networks = _parse_networks(policy.excluded_cidrs)
        self._root_cidr_networks = _parse_networks(getattr(policy, "root_cidrs", ()))

    @property
    def policy(self) -> ApiScopePolicy:
        """Return the policy in force."""
        return self._policy

    def allows_target(self, target: ApiTarget | Any) -> ScopeDecision:
        """Decide whether a mission target may be analysed."""
        if isinstance(target, dict):
            target = ApiTarget(
                value=str(target.get("value") or ""),
                target_type=str(target.get("target_type") or "hostname"),
                target_id=str(target.get("target_id") or ""),
            )
        value = str(target.value or "").strip().lower()
        if not value:
            return ScopeDecision(False, "empty target")

        candidate = self._normalize_hostname(value)
        if self._policy.excludes or self._policy.excluded_cidrs or self._policy.excluded_ip:
            for pattern in self._policy.excluded_url_patterns:
                if pattern and pattern.lower() in value:
                    return ScopeDecision(False, f"excluded URL pattern: {pattern}")
            if candidate in self._normalized_excludes or candidate in self._normalized_ip:
                return ScopeDecision(False, "explicitly excluded")
            if self._in_networks(value, self._excluded_cidr_networks):
                return ScopeDecision(False, "excluded CIDR")

        if self._policy.is_empty() and self._policy.fail_open_empty_policy:
            return ScopeDecision(True, "empty policy; fail-open")

        for root in self._policy.roots:
            normalized_root = self._normalize_hostname(root)
            if candidate == normalized_root or candidate.endswith(f".{normalized_root}"):
                return ScopeDecision(True, f"authorized root: {root}")
        if self._in_networks(value, self._root_cidr_networks):
            return ScopeDecision(True, "authorized CIDR")

        return ScopeDecision(False, "not in authorized scope")

    def allows_observation(self, origin_key: str | None = None, *, path: str = "") -> ScopeDecision:
        """Decide whether an observation origin may be persisted."""
        if not origin_key:
            return ScopeDecision(False, "empty origin")
        target = ApiTarget(value=origin_key, target_type="url")
        return self.allows_target(target)

    def _in_networks(self, value: str, networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network]) -> bool:
        if not networks:
            return False
        candidate = self._host_from_value(value)
        try:
            address = ipaddress.ip_address(candidate)
        except ValueError:
            return False
        return any(address in network for network in networks)

    def _normalize_hostname(self, value: str) -> str:
        host = self._host_from_value(value)
        return host.rstrip(".").lower()

    def _host_from_value(self, value: str) -> str:
        candidate = value.strip().lower()
        for scheme in ("https://", "http://", "ws://", "wss://"):
            if candidate.startswith(scheme):
                candidate = candidate[len(scheme) :]
        return candidate.split("/", 1)[0].split(":", 1)[0]


def _parse_networks(values: Iterable[str]) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for value in values:
        try:
            networks.append(ipaddress.ip_network(value, strict=False))
        except ValueError:
            continue
    return networks


def _split_roots(roots: Iterable[str]) -> tuple[list[str], list[str]]:
    """Split mission roots into domains and CIDR networks."""
    domains: list[str] = []
    cidrs: list[str] = []
    for item in roots:
        candidate = str(item or "").strip()
        if not candidate:
            continue
        if "/" in candidate and candidate.replace("/", "").replace(".", "").replace(":", "").isdigit():
            cidrs.append(candidate)
        else:
            domains.append(candidate)
    return domains, cidrs
