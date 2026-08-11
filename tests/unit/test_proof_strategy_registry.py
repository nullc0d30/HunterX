# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for the proof strategy registry (immutability, versioning)."""

from __future__ import annotations

import pytest

from hunterx.domain.vulnerability_proof.library import default_strategy_library
from hunterx.domain.vulnerability_proof.registry import (
    ProofStrategyRegistry,
    StrategyConflictError,
    UnknownStrategyError,
)
from hunterx.domain.vulnerability_proof.strategy import ProofStrategy
from hunterx.domain.vulnerability_validation.enums import SafetyClass, ValidationClass


def _simple_strategy(strategy_id: str = "strategy.test", version: str = "1.0.0") -> ProofStrategy:
    return ProofStrategy(
        strategy_id=strategy_id,
        strategy_version=version,
        vulnerability_class=ValidationClass.SQL_INJECTION,
        security_property="query semantics attacker-influenced",
        required_evidence=("behavioral_differential",),
        expected_observations=("differential behavior",),
        safety_class=SafetyClass.BENIGN_MARKER,
    )


class TestRegistry:
    def test_registration_and_lookup(self) -> None:
        registry = ProofStrategyRegistry(default_strategy_library())
        assert registry.count() == len(default_strategy_library())
        strategy = registry.get("strategy.sql_injection")
        assert strategy is not None
        assert strategy.strategy_id == "strategy.sql_injection"

    def test_supports_and_find_best(self) -> None:
        registry = ProofStrategyRegistry(default_strategy_library())
        assert registry.supports(ValidationClass.SQL_INJECTION)
        assert registry.supports(ValidationClass.UNKNOWN_BEHAVIOR)
        assert not registry.supports(ValidationClass.INJECTION)

    def test_resolve_returns_only_active(self) -> None:
        registry = ProofStrategyRegistry(default_strategy_library())
        strategies = registry.resolve(ValidationClass.UNKNOWN_BEHAVIOR)
        assert all(item.status.value == "active" for item in strategies)

    def test_immutable_after_registration(self) -> None:
        registry = ProofStrategyRegistry()
        registry.register(_simple_strategy())
        with pytest.raises(StrategyConflictError):
            registry.register(_simple_strategy())

    def test_update_creates_new_version(self) -> None:
        registry = ProofStrategyRegistry()
        v1 = _simple_strategy(version="1.0.0")
        v2 = _simple_strategy(version="2.0.0")
        registry.register(v1)
        registry.register(v2)
        current = registry.get("strategy.test")
        assert current.strategy_version == "2.0.0"
        assert registry.get("strategy.test", version="1.0.0") is not None

    def test_get_or_raise(self) -> None:
        registry = ProofStrategyRegistry(default_strategy_library())
        assert registry.get_or_raise("strategy.xss") is not None
        with pytest.raises(UnknownStrategyError):
            registry.get_or_raise("strategy.does-not-exist")

    def test_deprecate_excludes_from_resolution(self) -> None:
        registry = ProofStrategyRegistry(default_strategy_library())
        registry.deprecate("strategy.sql_injection", reason="superseded")
        assert registry.is_deprecated("strategy.sql_injection")
        assert not registry.supports(ValidationClass.SQL_INJECTION)
        assert registry.get("strategy.sql_injection") is not None  # still retrievable

    def test_deprecate_unknown_raises(self) -> None:
        registry = ProofStrategyRegistry(default_strategy_library())
        with pytest.raises(UnknownStrategyError):
            registry.deprecate("strategy.nope")

    def test_fallback_for(self) -> None:
        registry = ProofStrategyRegistry(default_strategy_library())
        fallbacks = registry.fallback_for("strategy.path_traversal")
        assert any(item.strategy_id == "strategy.file_inclusion" for item in fallbacks)

    def test_list_active_dedupes_by_version(self) -> None:
        registry = ProofStrategyRegistry()
        registry.register(_simple_strategy(version="1.0.0"))
        registry.register(_simple_strategy(version="1.1.0"))
        active = registry.list_active()
        assert len(active) == 1
        assert active[0].strategy_version == "1.1.0"

    def test_versions_returns_all(self) -> None:
        registry = ProofStrategyRegistry()
        registry.register(_simple_strategy(version="1.0.0"))
        registry.register(_simple_strategy(version="1.1.0"))
        versions = registry.versions("strategy.test")
        assert {item.strategy_version for item in versions} == {"1.0.0", "1.1.0"}


class TestStrategyValidation:
    def test_valid_strategy(self) -> None:
        registry = ProofStrategyRegistry(default_strategy_library())
        result = registry.validate_strategy(registry.get_or_raise("strategy.sql_injection"))
        assert result.valid is True
        assert not result.errors

    def test_missing_security_property_invalid(self) -> None:
        registry = ProofStrategyRegistry()
        strategy = _simple_strategy()
        strategy = ProofStrategy(
            strategy_id=strategy.strategy_id,
            vulnerability_class=strategy.vulnerability_class,
            required_evidence=strategy.required_evidence,
        )
        result = registry.validate_strategy(strategy)
        assert result.valid is False
        assert any("security_property" in error for error in result.errors)

    def test_missing_evidence_invalid(self) -> None:
        registry = ProofStrategyRegistry()
        strategy = ProofStrategy(
            strategy_id="strategy.x",
            security_property="prop",
            vulnerability_class=ValidationClass.XSS,
        )
        result = registry.validate_strategy(strategy)
        assert result.valid is False
        assert any("required_evidence" in error for error in result.errors)

    def test_destructive_safety_invalid(self) -> None:
        registry = ProofStrategyRegistry()
        strategy = _simple_strategy()
        strategy = ProofStrategy(
            strategy_id=strategy.strategy_id,
            vulnerability_class=strategy.vulnerability_class,
            security_property=strategy.security_property,
            required_evidence=strategy.required_evidence,
            safety_class=SafetyClass.DESTRUCTIVE,
        )
        result = registry.validate_strategy(strategy)
        assert result.valid is False
        assert any("safety_class" in error for error in result.errors)

    def test_replay_min_over_max_invalid(self) -> None:
        registry = ProofStrategyRegistry()
        strategy = _simple_strategy()
        strategy = ProofStrategy(
            strategy_id=strategy.strategy_id,
            vulnerability_class=strategy.vulnerability_class,
            security_property=strategy.security_property,
            required_evidence=strategy.required_evidence,
            replay_requirements={"minimum": 5, "max": 2},
        )
        result = registry.validate_strategy(strategy)
        assert result.valid is False

    def test_all_library_strategies_validate(self) -> None:
        registry = ProofStrategyRegistry(default_strategy_library())
        invalid = [item for item in registry.validate_all() if not item.valid]
        assert invalid == []

    def test_registry_version(self) -> None:
        registry = ProofStrategyRegistry()
        assert registry.version() == "1.0.0"
