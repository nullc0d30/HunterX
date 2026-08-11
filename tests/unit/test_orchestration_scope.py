# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Unit tests: mission scope guard."""

from __future__ import annotations

from hunterx.domain.orchestration.enums import ScopeClassification
from hunterx.domain.orchestration.models import MissionScope
from hunterx.engines.orchestration.scope import MissionScopeGuard


def test_exact_domain_in_scope() -> None:
    guard = MissionScopeGuard(MissionScope(roots=("example.com",)))
    decision = guard.decides("example.com")
    assert decision.allowed
    assert decision.classification is ScopeClassification.IN_SCOPE


def test_subdomain_follows_scope() -> None:
    guard = MissionScopeGuard(MissionScope(roots=("example.com",)))
    assert guard.allows("www.example.com")
    assert guard.allows("api.example.com")


def test_unrelated_domain_out_of_scope() -> None:
    guard = MissionScopeGuard(MissionScope(roots=("example.com",)))
    decision = guard.decides("other.org")
    assert not decision.allowed
    assert decision.classification is ScopeClassification.OUT_OF_SCOPE


def test_exclusion_wins() -> None:
    guard = MissionScopeGuard(
        MissionScope(roots=("example.com",), excludes=("internal.example.com",))
    )
    assert guard.allows("example.com")
    assert not guard.allows("internal.example.com")


def test_wildcard_pattern() -> None:
    guard = MissionScopeGuard(MissionScope(roots=("*.corp.example",)))
    assert guard.allows("a.corp.example")
    assert guard.allows("corp.example")
    assert not guard.allows("evil.example")


def test_cidr_containment() -> None:
    guard = MissionScopeGuard(MissionScope(roots=("10.0.0.0/24",)))
    assert guard.allows("10.0.0.5")
    assert not guard.allows("10.0.1.5")
    assert guard.allows("10.0.0.0/24")


def test_ip_exact() -> None:
    guard = MissionScopeGuard(MissionScope(roots=("192.168.1.10",)))
    assert guard.allows("192.168.1.10")
    assert not guard.allows("192.168.1.11")


def test_url_host_extraction() -> None:
    guard = MissionScopeGuard(MissionScope(roots=("example.com",)))
    assert guard.allows("https://example.com/")
    assert guard.allows("https://sub.example.com/path?q=1")
    assert not guard.allows("https://evil.com/steal")


def test_requires_authorization_when_no_rules() -> None:
    guard = MissionScopeGuard(MissionScope())
    decision = guard.decides("example.com")
    assert not decision.allowed
    assert decision.classification is ScopeClassification.REQUIRES_AUTHORIZATION


def test_decisions_recorded() -> None:
    guard = MissionScopeGuard(MissionScope(roots=("example.com",)))
    guard.decides("example.com")
    guard.decides("other.org")
    assert len(guard.decisions) == 2
    assert guard.decisions[0].allowed
    assert not guard.decisions[1].allowed
