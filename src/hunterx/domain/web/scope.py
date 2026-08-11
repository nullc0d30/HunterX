# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Web crawling scope policy and enforcement.

Mirrors the technology-fingerprinting scope posture: the policy is
fail-closed — a crawl is only authorized against hosts that match a configured
root. Exclusion rules (hosts, path patterns, extensions) always win. Scope is
never expanded by discovered redirect targets or external infrastructure; those
are recorded as observations but never fetched.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import re
from dataclasses import dataclass, field

from hunterx.domain.web.urls import URLNormalizer


@dataclass(slots=True)
class WebScopePolicy:
    """Configured scope for a web crawl.

    Attributes:
        roots: authorized hosts (``example.com``), domains or full origins.
        root_cidrs: authorized network ranges (``203.0.113.0/24``).
        root_ips: authorized IP addresses.
        excludes: hostnames/domains excluded regardless of root match.
        excluded_path_patterns: glob patterns matched against paths (e.g.
            ``/admin/*``, ``*/logout``).
        excluded_extensions: file extensions never fetched (``.zip``, ``.bak``).
        exclude_params: query parameter names never treated as interesting.
        allowed_schemes: schemes a fetch may use.
        max_depth: maximum crawl depth from the seed (0 = seed only).
        follow_subdomains: whether sibling subdomains of a root are in scope.
        respect_robots: whether robots.txt is honored in active crawls.

    """

    roots: tuple[str, ...] = field(default_factory=tuple)
    root_cidrs: tuple[str, ...] = field(default_factory=tuple)
    root_ips: tuple[str, ...] = field(default_factory=tuple)
    excludes: tuple[str, ...] = field(default_factory=tuple)
    excluded_path_patterns: tuple[str, ...] = field(default_factory=tuple)
    excluded_extensions: tuple[str, ...] = field(default_factory=tuple)
    exclude_params: tuple[str, ...] = field(default_factory=tuple)
    allowed_schemes: tuple[str, ...] = ("http", "https")
    max_depth: int = 3
    follow_subdomains: bool = True
    respect_robots: bool = True

    def is_empty(self) -> bool:
        """Return ``True`` when no root restricts the scope."""
        return not self.roots and not self.root_cidrs and not self.root_ips


@dataclass(frozen=True, slots=True)
class WebScopeDecision:
    """Result of a scope check for one URL.

    Attributes:
        allowed: whether the URL may be crawled.
        reason: why the URL is allowed or rejected.
        in_scope_host: whether the host belongs to the scope (redirects to
            external hosts still have ``in_scope_host=False``).
        depth: the crawl depth the URL sits at.

    """

    allowed: bool
    reason: str
    in_scope_host: bool = False
    depth: int = 0


class WebScopeEnforcer:
    """Enforce a :class:`WebScopePolicy` against URLs and hosts.

    Fail-closed: with no configured roots nothing is allowed. Host matching
    honors explicit origins (``https://app.example.com``), exact hosts,
    domain suffixes and, when ``follow_subdomains`` is set, subdomains of a
    root domain.
    """

    def __init__(self, policy: WebScopePolicy | None = None) -> None:
        self.policy = policy or WebScopePolicy()
        self._normalizer = URLNormalizer()
        self._path_regexes = tuple(
            re.compile(fnmatch.translate(pattern)) for pattern in self.policy.excluded_path_patterns
        )
        self._excluded_extensions = tuple(
            ext.lower().lstrip(".") for ext in self.policy.excluded_extensions
        )

    # -- host matching ------------------------------------------------------

    def allows_host(self, host: str) -> bool:
        """Return ``True`` when ``host`` is inside the configured scope."""
        host = (host or "").strip().rstrip(".").lower()
        if not host:
            return False
        if self.policy.is_empty():
            return False
        if any(_host_matches(pattern, host) for pattern in self.policy.excludes):
            return False
        for root in self.policy.roots:
            root = root.strip().rstrip(".").lower()
            if not root:
                continue
            if "://" in root:
                parsed = self._normalizer.parse(root)
                if _host_matches(parsed.host, host):
                    return True
                continue
            if _host_matches(root, host):
                return True
        return False

    def allows_ip(self, address: str) -> bool:
        """Return ``True`` when ``address`` is inside a configured range or IP."""
        try:
            probe = ipaddress.ip_address(address)
        except ValueError:
            return False
        for cidr in self.policy.root_cidrs:
            try:
                network = ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                continue
            if probe in network:
                return True
        return address in self.policy.root_ips

    # -- URL matching -------------------------------------------------------

    def allows_url(self, url: str, *, depth: int = 0) -> WebScopeDecision:
        """Decide whether ``url`` may be crawled under the policy."""
        try:
            parsed = self._normalizer.parse(url)
        except ValueError as error:
            return WebScopeDecision(False, str(error))
        if parsed.scheme not in self.policy.allowed_schemes:
            return WebScopeDecision(False, f"scheme '{parsed.scheme}' is not allowed")
        if not self.allows_host(parsed.host) and not self.allows_ip(parsed.host):
            return WebScopeDecision(
                False,
                f"host '{parsed.host}' is out of scope",
                in_scope_host=False,
                depth=depth,
            )
        if depth > self.policy.max_depth:
            return WebScopeDecision(
                False,
                f"depth {depth} exceeds maximum {self.policy.max_depth}",
                in_scope_host=True,
                depth=depth,
            )
        path = parsed.path.lower()
        for regex in self._path_regexes:
            if regex.match(path):
                return WebScopeDecision(
                    False,
                    f"path '{parsed.path}' is excluded",
                    in_scope_host=True,
                    depth=depth,
                )
        extension = path.rsplit("/", 1)[-1].rsplit(".", 1)[-1].lower()
        if "." in path.rsplit("/", 1)[-1] and extension in self._excluded_extensions:
            return WebScopeDecision(
                False,
                f"extension '.{extension}' is excluded",
                in_scope_host=True,
                depth=depth,
            )
        return WebScopeDecision(True, "in scope", in_scope_host=True, depth=depth)

    def decides(self, url: str, *, depth: int = 0) -> WebScopeDecision:
        """Alias for :meth:`allows_url` (fail-closed)."""
        return self.allows_url(url, depth=depth)

    def allows_target(self, value: str, target_type: str = "") -> WebScopeDecision:
        """Return whether a whole crawl target is in scope.

        A bare host/domain/URL target must be covered by the configured roots;
        with no roots configured the policy is fail-closed and nothing is
        allowed. ``target_type`` hints at the interpretation (``url`` parses the
        value as a URL, everything else treats it as a host/domain/address).
        """
        value = (value or "").strip()
        if not value:
            return WebScopeDecision(False, "empty crawl target")
        if self.policy.is_empty():
            return WebScopeDecision(False, "no scope roots configured; crawl is fail-closed")
        if target_type == "url" or "://" in value:
            try:
                parsed = self._normalizer.parse(value)
            except ValueError as error:
                return WebScopeDecision(False, str(error))
            if parsed.scheme not in self.policy.allowed_schemes:
                return WebScopeDecision(False, f"scheme '{parsed.scheme}' is not allowed")
            if not self.allows_host(parsed.host) and not self.allows_ip(parsed.host):
                return WebScopeDecision(
                    False,
                    f"host '{parsed.host}' is out of scope",
                    in_scope_host=False,
                )
            return WebScopeDecision(True, f"'{value}' is in scope", in_scope_host=True)
        if self.allows_ip(value):
            return WebScopeDecision(True, f"'{value}' is in scope", in_scope_host=True)
        if self.allows_host(value):
            return WebScopeDecision(True, f"'{value}' is in scope", in_scope_host=True)
        return WebScopeDecision(False, f"'{value}' is out of scope", in_scope_host=False)


def _host_matches(pattern: str, host: str) -> bool:
    """Return ``True`` when ``host`` matches a root/exclude pattern.

    A bare pattern matches exactly and, when the pattern is a registrable
    domain-like value, its subdomains. Patterns with a leading ``*.`` use
    wildcard semantics.
    """
    if pattern == host:
        return True
    if pattern.startswith("*."):
        suffix = pattern[2:]
        return host.endswith("." + suffix) or host == suffix
    return host.endswith("." + pattern)
