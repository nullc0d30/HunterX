# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Unit tests: mission safety enforcer."""

from __future__ import annotations

from hunterx.domain.orchestration.enums import ExecutionPolicyLevel
from hunterx.domain.orchestration.models import SafetyPolicy
from hunterx.engines.orchestration.safety import MissionSafetyEnforcer


def test_allows_passive_action() -> None:
    enforcer = MissionSafetyEnforcer()
    decision = enforcer.decides(action="recon.enumerate", safety_class="passive")
    assert decision.allowed


def test_allows_controlled_within_default_classes() -> None:
    enforcer = MissionSafetyEnforcer()
    decision = enforcer.decides(action="validation.probe", safety_class="controlled")
    assert decision.allowed


def test_refuses_unknown_safety_class() -> None:
    enforcer = MissionSafetyEnforcer()
    decision = enforcer.decides(action="x", safety_class="destructive")
    assert not decision.allowed


def test_refuses_forbidden_action() -> None:
    enforcer = MissionSafetyEnforcer()
    decision = enforcer.decides(action="credential-dumping", safety_class="controlled")
    assert not decision.allowed


def test_refuses_forbidden_parameter_marker() -> None:
    enforcer = MissionSafetyEnforcer()
    decision = enforcer.decides(
        action="run",
        safety_class="controlled",
        parameters={"command": "echo $(id)"},
    )
    assert not decision.allowed


def test_destructive_never_permitted() -> None:
    policy = SafetyPolicy(destructive_allowed=True)
    enforcer = MissionSafetyEnforcer(safety=policy)
    decision = enforcer.decides(action="erase", safety_class="controlled")
    assert not decision.allowed


def test_passive_only_execution_policy_is_reported() -> None:
    enforcer = MissionSafetyEnforcer(execution_policy=ExecutionPolicyLevel.PASSIVE_ONLY)
    assert not enforcer._execution_policy.allows_active
