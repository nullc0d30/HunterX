# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for proof-strategy TIDB entity persistence and mapping."""

from __future__ import annotations

from hunterx.application.vulnerability_proof_strategy import (
    _candidate_entity,
    _manual_instruction_entity,
    _strategy_entity,
    _validation_result_entity,
)
from hunterx.domain.entities.tidb.proof_strategy import (
    ProofManualInstruction as TidbProofManualInstruction,
)
from hunterx.domain.entities.tidb.proof_strategy import (
    ProofStrategy as TidbProofStrategy,
)
from hunterx.domain.entities.tidb.proof_strategy import (
    ProofStrategyCandidate as TidbProofStrategyCandidate,
)
from hunterx.domain.entities.tidb.proof_strategy import (
    ProofValidationResult as TidbProofValidationResult,
)
from hunterx.domain.vulnerability_proof.library import default_strategy_library
from hunterx.domain.vulnerability_proof.strategy import (
    ManualProofInstruction,
    ProofQualityLevel,
    ProofStrategy,
    ProofValidationResult,
    ProofVerdict,
    StrategyCandidate,
)
from hunterx.infrastructure.db.sql.memory import InMemoryTidbRepositoryFactory
from hunterx.infrastructure.db.sql.registry import all_entities


def _strategy() -> ProofStrategy:
    return next(item for item in default_strategy_library() if item.strategy_id == "strategy.sql_injection")


class TestEntityMapping:
    def test_strategy_entity_mapping(self) -> None:
        strategy = _strategy()
        entity = _strategy_entity(strategy)
        assert isinstance(entity, TidbProofStrategy)
        assert entity.strategy_id == strategy.strategy_id
        assert entity.strategy_version == strategy.strategy_version
        assert entity.vulnerability_class == "sql_injection"
        assert entity.required_evidence == list(strategy.required_evidence)
        assert entity.safety_class == strategy.safety_class.value
        assert entity.permits_confirmation is True

    def test_validation_result_entity_mapping(self) -> None:
        result = ProofValidationResult(
            proof_id="p1",
            strategy_id="strategy.sql_injection",
            verdict=ProofVerdict.VALID,
            score=0.9,
            proof_quality_level=ProofQualityLevel.P4_CONFIRMED,
            required_evidence=("behavioral_differential",),
            present_evidence=("behavioral_differential",),
            reasoning=("gates passed",),
        )
        entity = _validation_result_entity(result)
        assert isinstance(entity, TidbProofValidationResult)
        assert entity.verdict == "valid"
        assert entity.score == 0.9
        assert entity.reasoning == ["gates passed"]

    def test_manual_instruction_entity_mapping(self) -> None:
        instruction = ManualProofInstruction(
            proof_id="p1",
            strategy_id="strategy.unknown_behavior",
            objective="observe behavior",
            steps=("observe",),
        )
        entity = _manual_instruction_entity(instruction)
        assert isinstance(entity, TidbProofManualInstruction)
        assert entity.objective == "observe behavior"
        assert entity.steps == ["observe"]

    def test_candidate_entity_mapping(self) -> None:
        candidate = StrategyCandidate(observed_behavior="marker echoed", reasoning="novel")
        entity = _candidate_entity(candidate)
        assert isinstance(entity, TidbProofStrategyCandidate)
        assert entity.candidate_id == candidate.candidate_id
        assert entity.status == "proposed"


class TestInMemoryPersistence:
    def test_strategy_persists_and_lists(self) -> None:
        factory = InMemoryTidbRepositoryFactory()
        repo = factory.repository_for(TidbProofStrategy)
        entity = _strategy_entity(_strategy())
        repo.save(entity)
        records = repo.list(limit=10)
        assert len(records) == 1
        assert records[0].strategy_id == "strategy.sql_injection"

    def test_validation_result_persists(self) -> None:
        factory = InMemoryTidbRepositoryFactory()
        repo = factory.repository_for(TidbProofValidationResult)
        result = ProofValidationResult(proof_id="p1", strategy_id="strategy.xss", verdict=ProofVerdict.VALID)
        repo.save(_validation_result_entity(result))
        records = repo.list_by("proof_id", "p1", limit=10)
        assert len(records) == 1
        assert records[0].verdict == "valid"

    def test_new_entities_registered(self) -> None:
        names = {cls.__name__ for cls in all_entities()}
        assert {"ProofStrategy", "ProofStrategyVersion", "ProofValidationResult", "ProofManualInstruction", "ProofStrategyCandidate"} <= names
