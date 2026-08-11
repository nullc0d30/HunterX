# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for the validation rules, scope and safety gates."""

from __future__ import annotations

import pytest

from hunterx.domain.vulnerability_validation.enums import (
    MissionProfile,
    SafetyClass,
    ValidationClass,
)
from hunterx.domain.vulnerability_validation.rules import (
    ValidationRuleSet,
    default_validation_rules,
)
from hunterx.domain.vulnerability_validation.safety import SafetyEnforcer, SafetyPolicy
from hunterx.domain.vulnerability_validation.scope import (
    ValidationScopeEnforcer,
    ValidationScopePolicy,
)


class TestValidationRuleSet:
    def test_default_rules_cover_core_classes(self) -> None:
        rules = ValidationRuleSet()
        for cls in (
            ValidationClass.KNOWN_VULNERABLE_SOFTWARE,
            ValidationClass.SQL_INJECTION,
            ValidationClass.XSS,
            ValidationClass.BROKEN_ACCESS_CONTROL,
            ValidationClass.SECURITY_MISCONFIGURATION,
        ):
            assert rules.supports(cls), cls

    def test_known_vulnerable_software_permits_confirmation(self) -> None:
        rule = ValidationRuleSet().require(ValidationClass.KNOWN_VULNERABLE_SOFTWARE)
        assert rule.permits_confirmation is True
        assert "version" in rule.confirmation_evidence

    def test_weaponized_classes_never_permit_confirmation(self) -> None:
        rules = ValidationRuleSet()
        for cls in (
            ValidationClass.COMMAND_INJECTION,
            ValidationClass.DESERIALIZATION,
            ValidationClass.SSRF,
        ):
            assert rules.require(cls).permits_confirmation is False

    def test_forbidden_actions_are_universal(self) -> None:
        rules = ValidationRuleSet()
        for rule in rules.rules:
            for action in ("rce", "shell-payload-execution", "data-deletion", "persistence"):
                assert rules.forbid(rule, action)

    def test_no_rule_permits_destructive_safety(self) -> None:
        for rule in default_validation_rules():
            assert "destructive" not in rule.safe_checks


class TestScopeEnforcer:
    def test_in_scope_allowed(self) -> None:
        policy = ValidationScopePolicy(targets=("example.com",))
        enforcer = ValidationScopeEnforcer(policy)
        decision = enforcer.decides(target="app.example.com", asset="app.example.com")
        assert decision.allowed is True
        assert decision.reason == "allowed"

    def test_out_of_scope_blocked(self) -> None:
        policy = ValidationScopePolicy(targets=("example.com",))
        enforcer = ValidationScopeEnforcer(policy)
        decision = enforcer.decides(target="attacker.com")
        assert decision.allowed is False
        assert decision.reason == "scope_blocked"

    def test_empty_scope_is_fail_closed(self) -> None:
        enforcer = ValidationScopeEnforcer(ValidationScopePolicy())
        assert enforcer.decides(target="example.com").allowed is False

    def test_exclusion_wins(self) -> None:
        policy = ValidationScopePolicy(targets=("example.com",), excludes=("admin.example.com",))
        enforcer = ValidationScopeEnforcer(policy)
        assert enforcer.decides(target="admin.example.com").allowed is False

    def test_expired_scope_refuses_everything(self) -> None:
        policy = ValidationScopePolicy(targets=("example.com",), expired=True)
        enforcer = ValidationScopeEnforcer(policy)
        assert enforcer.decides(target="app.example.com").allowed is False
        assert enforcer.decides(target="app.example.com").reason == "scope-expired"

    def test_wildcard_subdomain_not_allowed(self) -> None:
        # Dot-suffix matching must not treat "*.example.com" as a literal host.
        policy = ValidationScopePolicy(targets=("*.example.com",))
        enforcer = ValidationScopeEnforcer(policy)
        assert enforcer.decides(target="app.example.com").allowed is False


class TestSafetyEnforcer:
    def test_destructive_class_always_blocked(self) -> None:
        enforcer = SafetyEnforcer(SafetyPolicy())
        decision = enforcer.decides(action="rce", safety_class=SafetyClass.DESTRUCTIVE)
        assert decision.allowed is False
        assert decision.reason == "safety_blocked"

    def test_passive_allowed(self) -> None:
        enforcer = SafetyEnforcer(SafetyPolicy())
        decision = enforcer.decides(action="version-verify", safety_class=SafetyClass.PASSIVE)
        assert decision.allowed is True

    def test_forbidden_action_blocked(self) -> None:
        enforcer = SafetyEnforcer(SafetyPolicy())
        decision = enforcer.decides(action="shell-payload-execution", safety_class=SafetyClass.CONTROLLED)
        assert decision.allowed is False
        assert decision.blocked_action == "shell-payload-execution"

    def test_forbidden_parameter_marker_blocked(self) -> None:
        enforcer = SafetyEnforcer(SafetyPolicy())
        decision = enforcer.decides(
            action="run-command",
            safety_class=SafetyClass.CONTROLLED,
            parameters={"command": "echo hi; rm -rf /"},
        )
        assert decision.allowed is False

    def test_profile_restricts_class(self) -> None:
        policy = SafetyPolicy(profile=MissionProfile.BUG_BOUNTY, allowed_classes=(ValidationClass.CORS,))
        enforcer = SafetyEnforcer(policy)
        decision = enforcer.decides(
            action="version-verify",
            safety_class=SafetyClass.PASSIVE,
            vulnerability_class=ValidationClass.KNOWN_VULNERABLE_SOFTWARE,
        )
        assert decision.allowed is False

    def test_destructive_never_configurable(self) -> None:
        with pytest.raises(ValueError):
            SafetyPolicy(destructive_allowed=True)
