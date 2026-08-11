# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Performance benchmarks for the vulnerability proof strategy library."""

from __future__ import annotations

import threading

from hunterx.domain.vulnerability_proof.enums import ReplayResult
from hunterx.domain.vulnerability_proof.library import default_strategy_library
from hunterx.domain.vulnerability_proof.matrix import matrix_from_strategies
from hunterx.domain.vulnerability_proof.models import ProofReplay
from hunterx.domain.vulnerability_proof.registry import ProofStrategyRegistry
from hunterx.domain.vulnerability_proof.selector import ProofStrategySelector, ProofStrategySelectorInput
from hunterx.domain.vulnerability_proof.strategy import ProofStrategy
from hunterx.domain.vulnerability_proof.validator import ProofValidationContext, ProofValidator
from hunterx.domain.vulnerability_validation.enums import (
    EvidenceComparison,
    EvidenceKind,
    ValidationClass,
)
from hunterx.domain.vulnerability_validation.models import ValidationEvidence, ValidationObservation


def _resolver(sdk_capability: str) -> tuple[str, ...]:
    return ("proof-replay",) if sdk_capability in ("proof-replay", "safe-validation") else ()


def _registry(n: int = 1000) -> ProofStrategyRegistry:
    base = default_strategy_library()
    registry = ProofStrategyRegistry(list(base))
    for index in range(n):
        strategy = ProofStrategy(
            strategy_id=f"strategy.bench.{index}",
            vulnerability_class=ValidationClass.UNKNOWN_BEHAVIOR,
            security_property="benchmark strategy",
            required_evidence=("behavioral_differential",),
            expected_observations=("behavior",),
        )
        registry.register(strategy)
    return registry


class TestStrategyBenchmarks:
    def test_large_registry_selection(self, benchmark) -> None:
        registry = _registry(n=2000)
        selector = ProofStrategySelector(registry, capability_resolver=_resolver)

        def select() -> None:
            for cls in (
                ValidationClass.SQL_INJECTION,
                ValidationClass.XSS,
                ValidationClass.SSRF,
                ValidationClass.UNKNOWN_BEHAVIOR,
            ):
                selector.select(ProofStrategySelectorInput(vulnerability_class=cls))

        benchmark(select)

    def test_large_evidence_matrix(self, benchmark) -> None:
        strategies = list(default_strategy_library())
        for index in range(500):
            strategies.append(
                ProofStrategy(
                    strategy_id=f"strategy.matrix.{index}",
                    vulnerability_class=ValidationClass.UNKNOWN_BEHAVIOR,
                    security_property="matrix bench",
                    required_evidence=("behavioral_differential",),
                )
            )
        benchmark(lambda: matrix_from_strategies(strategies))

    def test_validation_throughput(self, benchmark) -> None:
        validator = ProofValidator()
        strategy = next(item for item in default_strategy_library() if item.strategy_id == "strategy.sql_injection")

        def evidence(index: int) -> ValidationEvidence:
            return ValidationEvidence(
                observation=ValidationObservation(
                    kind=EvidenceKind.BEHAVIORAL_DIFFERENTIAL, value=f"diff-{index}", source="bench"
                ),
                comparison=EvidenceComparison.MATCH,
            )

        def replay() -> ProofReplay:
            return ProofReplay(proof_id="p", result=ReplayResult.SUCCESS, target_state="s1")

        def validate_batch() -> None:
            for index in range(100):
                context = ProofValidationContext(
                    proof_id=f"p{index}",
                    vulnerability_class=ValidationClass.SQL_INJECTION,
                    evidence=(evidence(index),),
                    replays=(replay(), replay()),
                    target_state="s1",
                    generated_target_state="s1",
                    impact_evidence=("integrity",),
                    independent_verified=True,
                )
                validator.validate(strategy, context)

        benchmark(validate_batch)

    def test_large_finding_set_validation(self, benchmark) -> None:
        validator = ProofValidator()
        registry = _registry(n=3000)
        strategy = registry.find_best_strategy(ValidationClass.SQL_INJECTION)
        assert strategy is not None

        def run() -> None:
            for index in range(500):
                context = ProofValidationContext(
                    proof_id=f"finding-{index}",
                    vulnerability_class=ValidationClass.SQL_INJECTION,
                    evidence=(
                        ValidationEvidence(
                            observation=ValidationObservation(
                                kind=EvidenceKind.BEHAVIORAL_DIFFERENTIAL, value="diff", source="bench"
                            ),
                            comparison=EvidenceComparison.MATCH,
                        ),
                    ),
                    replays=(
                        ProofReplay(proof_id=f"finding-{index}", result=ReplayResult.SUCCESS, target_state="s1"),
                        ProofReplay(proof_id=f"finding-{index}", result=ReplayResult.SUCCESS, target_state="s1"),
                    ),
                    target_state="s1",
                    generated_target_state="s1",
                    impact_evidence=("integrity",),
                    independent_verified=True,
                )
                validator.validate(strategy, context)

        benchmark(run)

    def test_concurrent_strategy_selection(self) -> None:
        registry = _registry(n=500)
        selector = ProofStrategySelector(registry, capability_resolver=_resolver)
        errors: list[Exception] = []

        def worker() -> None:
            try:
                for _ in range(50):
                    selector.select(ProofStrategySelectorInput(vulnerability_class=ValidationClass.XSS))
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        assert errors == []
