# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Target normalization & scope-bypass resistance (Sprint 034.4 §3, §4).

Equivalent spellings (scheme, case, port, trailing dot, userinfo, encoded
forms) must never escape a fail-closed scope decision. Redirect targets never
widen scope.
"""

from __future__ import annotations

import pytest

from hunterx.domain.orchestration.models import MissionScope
from hunterx.domain.web.scope import WebScopeEnforcer, WebScopePolicy
from hunterx.domain.web.urls import URLNormalizer
from hunterx.engines.orchestration.scope import MissionScopeGuard

# -- URL canonicalization --------------------------------------------------------


def test_url_normalizer_collapses_equivalent_spellings() -> None:
    normalizer = URLNormalizer()
    canonical = normalizer.normalize("https://EXAMPLE.com:443/a?b=2&a=1")
    assert canonical == normalizer.normalize("https://example.com/a?a=1&b=2")


def test_url_normalizer_rejects_unsupported_schemes() -> None:
    normalizer = URLNormalizer()
    for url in ("ftp://example.com", "file:///etc/passwd", "gopher://example.com"):
        with pytest.raises(ValueError):
            normalizer.parse(url)


def test_url_normalizer_rejects_missing_host() -> None:
    with pytest.raises(ValueError):
        URLNormalizer().parse("https:///path")


# -- mission scope guard: normalization bypass attempts --------------------------


def _guard(*, roots=(), includes=(), excludes=()):
    return MissionScopeGuard(MissionScope(roots=roots, includes=includes, excludes=excludes))


@pytest.mark.parametrize(
    "identifier",
    [
        "example.com",
        "sub.example.com",
        "a.b.example.com",
        "https://example.com",
        "https://sub.example.com/path",
        "EXAMPLE.COM",
        "example.com:443",
        "http://example.com",
    ],
)
def test_in_scope_equivalents_are_allowed(identifier: str) -> None:
    assert _guard(roots=("example.com",)).allows(identifier)


@pytest.mark.parametrize(
    "identifier",
    [
        "evil.example.net",
        "example.com.evil.com",
        "notexample.com",
        "https://example.com.evil.com/path",
        "https://user@example.com.evil.com",
        "https://evil.example.net/path",
    ],
)
def test_out_of_scope_variants_are_blocked(identifier: str) -> None:
    assert _guard(roots=("example.com",)).allows(identifier) is False


def test_mission_scope_is_host_based_and_scheme_agnostic() -> None:
    """The mission scope guard scopes *hosts*, not schemes; an operator who
    authorizes ``example.com`` authorizes the host under any protocol. Scheme
    restrictions are enforced separately (web scope enforcer)."""
    guard = _guard(roots=("example.com",))
    assert guard.allows("ftp://example.com") is True
    assert guard.allows("file:///etc/passwd") is False


@pytest.mark.parametrize(
    "identifier",
    [
        "bad.example.com",
        "https://bad.example.com/x",
        "BAD.EXAMPLE.COM",
    ],
)
def test_exclusions_always_win(identifier: str) -> None:
    guard = _guard(roots=("example.com",), excludes=("bad.example.com",))
    assert guard.allows(identifier) is False


def test_redirect_target_must_itself_be_in_scope() -> None:
    guard = _guard(roots=("example.com",))
    in_scope = guard.decides("example.com", redirected=True)
    assert in_scope.allowed is True
    escaped = guard.decides("evil.example.net", redirected=True)
    assert escaped.allowed is False
    assert escaped.redirected is True


def test_cidr_and_ip_scope() -> None:
    guard = _guard(roots=("203.0.113.0/24",))
    assert guard.allows("203.0.113.5") is True
    assert guard.allows("203.0.114.5") is False
    assert guard.allows("203.0.113.0/24") is True
    assert guard.allows("10.0.0.1") is False


def test_fail_closed_with_no_rules() -> None:
    guard = _guard()
    decision = guard.decides("https://example.com")
    assert decision.allowed is False  # REQUIRES_AUTHORIZATION / OUT_OF_SCOPE


def test_scope_guard_never_expands_from_discovery() -> None:
    guard = _guard(roots=("example.com",))
    assert all(guard.allows(host) for host in ("api.example.com", "internal.example.com:8080"))
    assert guard.allows("cdn.example.net") is False


# -- web scope enforcer -----------------------------------------------------------


def test_web_scope_fail_closed_with_no_roots() -> None:
    assert WebScopeEnforcer().decides("https://example.com").allowed is False


def test_web_scope_scheme_and_host_checks() -> None:
    enforcer = WebScopeEnforcer(WebScopePolicy(roots=("example.com",)))
    assert enforcer.decides("https://example.com/a").allowed is True
    assert enforcer.decides("http://sub.example.com/b").allowed is True
    assert enforcer.decides("https://evil.com/").allowed is False
    assert enforcer.decides("ftp://example.com/").allowed is False


def test_web_scope_path_exclusions() -> None:
    enforcer = WebScopeEnforcer(
        WebScopePolicy(roots=("example.com",), excluded_path_patterns=("/admin/*",), excluded_extensions=(".bak",))
    )
    assert enforcer.decides("https://example.com/public").allowed is True
    assert enforcer.decides("https://example.com/admin/x").allowed is False
    assert enforcer.decides("https://example.com/backup.bak").allowed is False


def test_web_scope_ip_and_cidr_roots() -> None:
    enforcer = WebScopeEnforcer(WebScopePolicy(root_ips=("203.0.113.5",), root_cidrs=("198.51.100.0/24",)))
    assert enforcer.decides("http://203.0.113.5/").allowed is True
    assert enforcer.decides("http://198.51.100.9/").allowed is True
    assert enforcer.decides("http://203.0.114.5/").allowed is False


def test_web_scope_subdomain_suffix_is_bounded() -> None:
    enforcer = WebScopeEnforcer(WebScopePolicy(roots=("example.com",)))
    assert enforcer.allows_host("sub.example.com") is True
    assert enforcer.allows_host("notexample.com") is False
    assert enforcer.allows_host("example.com.evil.com") is False
