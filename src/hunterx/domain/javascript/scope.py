# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Scope enforcement for JavaScript intelligence.

Decides whether a domain or URL referenced by a script may be collected,
reported or persisted, based on the mission's authorized root domains and
exclusions. The enforcer is pure and deterministic, and every denial carries a
human-readable reason.
"""

from __future__ import annotations

import urllib.parse
from collections.abc import Iterable
from dataclasses import dataclass


def normalize_domain(value: str) -> str:
    """Lowercase a domain and strip a trailing dot."""
    return str(value or "").strip().lower().rstrip(".")


def normalize_url(value: str) -> str:
    """Normalize a URL for comparison: lowercase scheme/host, drop fragment."""
    stripped = str(value or "").strip()
    if not stripped:
        return ""
    if stripped.startswith("//"):
        stripped = "https:" + stripped
    if "://" not in stripped:
        return stripped
    try:
        parsed = urllib.parse.urlsplit(stripped)
        host = (parsed.hostname or "").lower()
        port = parsed.port
        netloc = host if port is None else f"{host}:{port}"
        return urllib.parse.urlunsplit((parsed.scheme.lower(), netloc, parsed.path, parsed.query, ""))
    except ValueError:
        return stripped


@dataclass(frozen=True, slots=True)
class JSScopePolicy:
    """The JavaScript scope policy for a mission.

    Attributes:
        roots: authorized root domains (a referenced domain is in scope when
            it equals or is a descendant of a root).
        excludes: domains explicitly out of scope (exact or suffix).
        strict: when ``True``, domains outside the roots are rejected; when
            ``False``, out-of-root domains are kept as third-party references.

    """

    roots: frozenset[str] = frozenset()
    excludes: frozenset[str] = frozenset()
    strict: bool = False


@dataclass(frozen=True, slots=True)
class JSScopeDecision:
    """The outcome of a scope check.

    Attributes:
        allowed: whether the resource is in scope.
        reason: human-readable explanation of the decision.

    """

    allowed: bool
    reason: str = ""

    def __bool__(self) -> bool:
        return self.allowed


class JSScopeEnforcer:
    """Evaluate domains and URLs against a :class:`JSScopePolicy`."""

    def __init__(self, policy: JSScopePolicy | None = None) -> None:
        self._policy = policy or JSScopePolicy()
        self._roots = frozenset(normalize_domain(root) for root in self._policy.roots if root)
        self._excludes = frozenset(normalize_domain(ex) for ex in self._policy.excludes if ex)

    @property
    def policy(self) -> JSScopePolicy:
        """Return the active policy."""
        return self._policy

    def allows_domain(self, domain: str) -> JSScopeDecision:
        """Return whether ``domain`` may be collected/reported."""
        normalized = normalize_domain(domain)
        if not normalized:
            return JSScopeDecision(False, "empty domain")
        if _matches_exclusion(normalized, self._excludes):
            return JSScopeDecision(False, f"'{normalized}' matches an excluded domain")
        if not self._roots:
            return JSScopeDecision(True, "no root domains configured")
        if _matches_root(normalized, self._roots):
            return JSScopeDecision(True, f"'{normalized}' is within an authorized root")
        if self._policy.strict:
            return JSScopeDecision(False, f"'{normalized}' is not within any authorized root")
        return JSScopeDecision(True, f"'{normalized}' is a third-party domain (strict scope disabled)")

    def allows_url(self, url: str) -> JSScopeDecision:
        """Return whether a URL may be collected/reported."""
        host = _host_of_url(url)
        if not host:
            return JSScopeDecision(False, f"'{url}' has no host")
        return self.allows_domain(host)

    def filter_domains(self, domains: Iterable[str]) -> list[str]:
        """Return only the in-scope domains from ``domains``."""
        return [domain for domain in domains if self.allows_domain(domain).allowed]

    def classify_domain(self, domain: str) -> str:
        """Return ``same-origin`` | ``same-organization`` | ``third-party``."""
        normalized = normalize_domain(domain)
        decision = self.allows_domain(normalized)
        if not decision.allowed:
            return "out-of-scope"
        if not self._roots:
            return "unknown"
        if _matches_root(normalized, self._roots):
            return "same-origin"
        return "third-party"


def _host_of_url(url: str) -> str:
    """Return the hostname of ``url`` or ``""``."""
    normalized = url
    if url.startswith("//"):
        normalized = "https:" + url
    if "://" not in normalized:
        return ""
    try:
        return normalize_domain(urllib.parse.urlsplit(normalized).hostname or "")
    except ValueError:
        return ""


def _matches_root(name: str, roots: Iterable[str]) -> bool:
    lowered = name.rstrip(".")
    return any(lowered == root or lowered.endswith("." + root) for root in roots)


def _matches_exclusion(name: str, excludes: Iterable[str]) -> bool:
    lowered = name.rstrip(".")
    return any(lowered == excluded or lowered.endswith("." + excluded) for excluded in excludes)
