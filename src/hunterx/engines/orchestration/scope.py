# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Mission scope guard.

The scope guard executes before every tool task. It checks the target, asset,
endpoint, protocol, port, hostname, IP, cloud resource, URL and redirect
target against the mission scope and classifies any discovered identifier as
in-scope, out-of-scope, requires-authorization or unknown. Out-of-scope and
requires-authorization identifiers are never acted upon; the decision is
persisted and surfaced as an event.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlparse

from hunterx.domain.orchestration.enums import ScopeClassification
from hunterx.domain.orchestration.models import MissionScope


def _strip_scheme(value: str) -> str:
    """Strip an optional ``scheme://`` prefix from a host identifier."""
    if "://" in value:
        parsed = urlparse(value)
        return parsed.netloc or parsed.path
    return value.split("/", 1)[0]


def _is_ip(value: str) -> bool:
    """Return ``True`` when ``value`` is a valid IP address."""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _is_cidr(value: str) -> bool:
    """Return ``True`` when ``value`` is a valid CIDR network."""
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        return False


def _hostname_matches(pattern: str, host: str) -> bool:
    """Match ``host`` against a scope pattern.

    Patterns support an optional leading ``*.`` wildcard (matches the bare
    label and every subdomain). A plain pattern matches the host exactly or as
    a registrable root suffix (``example.com`` matches ``a.example.com``).
    """
    pattern = _strip_scheme(pattern).strip(".").lower()
    host = host.strip(".").lower()
    if not pattern or not host:
        return False
    if pattern == host:
        return True
    if pattern.startswith("*."):
        suffix = pattern[2:]
        return host == suffix or host.endswith("." + suffix)
    return host == pattern or host.endswith("." + pattern)


def _cidr_contains(cidr: str, address: str) -> bool:
    """Return ``True`` when ``address`` falls inside ``cidr``."""
    try:
        return ipaddress.ip_address(address) in ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False


@dataclass(frozen=True, slots=True)
class ScopeDecision:
    """A scope-guard decision for a task target.

    Attributes:
        allowed: whether the task may proceed.
        classification: canonical :class:`ScopeClassification`.
        reason: human-readable justification.
        identifier: the identifier that was checked.
        redirected: whether the identifier arrived via a redirect.

    """

    allowed: bool
    classification: ScopeClassification
    reason: str = ""
    identifier: str = ""
    redirected: bool = False

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-safe representation."""
        return {
            "allowed": self.allowed,
            "classification": self.classification.value,
            "reason": self.reason,
            "identifier": self.identifier,
            "redirected": self.redirected,
        }


class MissionScopeGuard:
    """Unified, fail-closed scope guard for mission tasks.

    The guard is fail-closed when a scope has roots or excludes configured:
    identifiers that cannot be positively matched are classified
    ``OUT_OF_SCOPE``. Redirect targets are only allowed when the redirect
    destination is itself inside the scope (never expanded by discovery).
    """

    _HOST_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$", re.IGNORECASE)

    def __init__(self, scope: MissionScope | None = None) -> None:
        self._scope = scope or MissionScope()
        self._decisions: list[ScopeDecision] = []

    @property
    def scope(self) -> MissionScope:
        """Return the scope this guard enforces."""
        return self._scope

    @property
    def decisions(self) -> list[ScopeDecision]:
        """Return every decision the guard has recorded."""
        return list(self._decisions)

    def decides(self, identifier: str, *, redirected: bool = False) -> ScopeDecision:
        """Classify and decide on a task identifier.

        Args:
            identifier: the target/asset/endpoint identifier.
            redirected: whether the identifier came from a redirect.

        Returns:
            A :class:`ScopeDecision`. The decision is recorded for audit.

        """
        identifier = identifier.strip()
        normalized = _strip_scheme(identifier)

        decision = self._classify(identifier, normalized, redirected)
        self._decisions.append(decision)
        return decision

    def allows(self, identifier: str, *, redirected: bool = False) -> bool:
        """Return ``True`` when a task on ``identifier`` is permitted."""
        return self.decides(identifier, redirected=redirected).allowed

    def classify(self, identifier: str) -> ScopeClassification:
        """Classify an identifier without recording a decision."""
        identifier = identifier.strip()
        normalized = _strip_scheme(identifier)
        return self._classification(identifier, normalized)

    # -- classification -----------------------------------------------------

    def _classify(self, identifier: str, normalized: str, redirected: bool) -> ScopeDecision:
        classification = self._classification(identifier, normalized)
        allowed = classification is ScopeClassification.IN_SCOPE
        reason = self._reason(classification)
        return ScopeDecision(
            allowed=allowed,
            classification=classification,
            reason=reason,
            identifier=identifier,
            redirected=redirected,
        )

    def _classification(self, identifier: str, normalized: str) -> ScopeClassification:
        scope = self._scope
        has_rules = bool(scope.roots or scope.includes or scope.excludes)

        if identifier in scope.excludes or normalized in scope.excludes:
            return ScopeClassification.OUT_OF_SCOPE

        if _is_cidr(normalized):
            if any(_cidr_contains(entry, normalized.split("/")[0]) for entry in scope.roots if _is_cidr(entry)):
                return ScopeClassification.IN_SCOPE
            if any(entry == normalized for entry in scope.roots):
                return ScopeClassification.IN_SCOPE
            if any(_cidr_contains(entry, normalized.split("/")[0]) for entry in scope.includes if _is_cidr(entry)):
                return ScopeClassification.IN_SCOPE
            return ScopeClassification.OUT_OF_SCOPE

        if _is_ip(normalized):
            if any(_cidr_contains(entry, normalized) for entry in scope.roots if _is_cidr(entry)):
                return ScopeClassification.IN_SCOPE
            if any(_cidr_contains(entry, normalized) for entry in scope.includes if _is_cidr(entry)):
                return ScopeClassification.IN_SCOPE
            if normalized in scope.roots or normalized in scope.includes:
                return ScopeClassification.IN_SCOPE
            return ScopeClassification.OUT_OF_SCOPE

        host = self._host(normalized)
        if host:
            if any(host == _strip_scheme(e) for e in scope.excludes):
                return ScopeClassification.OUT_OF_SCOPE
            if any(_hostname_matches(e, host) for e in scope.roots) or any(
                _hostname_matches(e, host) for e in scope.includes
            ):
                return ScopeClassification.IN_SCOPE
            if not has_rules:
                return ScopeClassification.REQUIRES_AUTHORIZATION

        return ScopeClassification.OUT_OF_SCOPE

    @staticmethod
    def _host(value: str) -> str:
        """Extract a hostname from an identifier when possible."""
        if _is_ip(value) or _is_cidr(value):
            return ""
        candidate = value.split("/", 1)[0]
        candidate = candidate.split(":", 1)[0]
        candidate = candidate.strip("[]").lower()
        if MissionScopeGuard._HOST_PATTERN.match(candidate):
            return candidate
        return ""

    @staticmethod
    def _reason(classification: ScopeClassification) -> str:
        return {
            ScopeClassification.IN_SCOPE: "identifier is authorized by mission scope",
            ScopeClassification.OUT_OF_SCOPE: "identifier is outside the authorized scope",
            ScopeClassification.REQUIRES_AUTHORIZATION: "identifier requires explicit authorization",
            ScopeClassification.UNKNOWN: "identifier classification is unknown",
        }[classification]


def classification_of(decision: ScopeDecision) -> ScopeClassification:
    """Return the classification of a scope decision (alias helper)."""
    return decision.classification
