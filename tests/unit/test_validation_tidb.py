# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for TIDB registration and mapping of validation entities."""

from __future__ import annotations

from hunterx.domain.entities.tidb.validation import (
    ValidationDifferential,
    ValidationEvidence,
    ValidationExecution,
    ValidationHistory,
    ValidationPlan,
    ValidationPolicyDecision,
    ValidationRule,
    ValidationStep,
    ValidationToolUsage,
    ValidationVerdict,
    VulnerabilityHypothesis,
)
from hunterx.infrastructure.db.sql.mapping import RowMapper
from hunterx.infrastructure.db.sql.memory import InMemoryTidbRepositoryFactory
from hunterx.infrastructure.db.sql.registry import ENTITY_TO_MODEL

_ENTITIES = (
    VulnerabilityHypothesis,
    ValidationRule,
    ValidationPlan,
    ValidationStep,
    ValidationExecution,
    ValidationEvidence,
    ValidationVerdict,
    ValidationHistory,
    ValidationDifferential,
    ValidationToolUsage,
    ValidationPolicyDecision,
)


class TestValidationEntityRegistry:
    def test_all_entities_registered_with_orm_models(self) -> None:
        for entity in _ENTITIES:
            assert entity in ENTITY_TO_MODEL, entity.__name__
            assert ENTITY_TO_MODEL[entity].__tablename__.startswith("tidb_")

    def test_row_mapper_round_trip_hypothesis(self) -> None:
        entity = VulnerabilityHypothesis(
            hypothesis_id="h1",
            mission_id="m1",
            target_id="app.example.com",
            asset_id="app.example.com",
            vulnerability_id="CVE-2024-1234",
            class_name="sqlinjection",
            state="hypothesis",
        )
        mapper = RowMapper(VulnerabilityHypothesis)
        row = mapper.new_row(entity)
        restored = mapper.to_entity(row)
        assert restored.hypothesis_id == "h1"
        assert restored.class_name == "sqlinjection"
        assert restored.state == "hypothesis"
        assert restored.mission_id == "m1"

    def test_row_mapper_round_trip_evidence(self) -> None:
        entity = ValidationEvidence(
            evidence_id="e1",
            validation_id="v1",
            hypothesis_id="h1",
            comparison="match",
            observation={"kind": "version", "value": "1.24.0"},
        )
        mapper = RowMapper(ValidationEvidence)
        row = mapper.new_row(entity)
        restored = mapper.to_entity(row)
        assert restored.evidence_id == "e1"
        assert restored.comparison == "match"
        assert restored.observation == {"kind": "version", "value": "1.24.0"}

    def test_row_mapper_round_trip_verdict(self) -> None:
        entity = ValidationVerdict(
            verdict_id="vd1",
            validation_id="v1",
            hypothesis_id="h1",
            result="confirmed",
            evidence_ids=["e1"],
        )
        mapper = RowMapper(ValidationVerdict)
        row = mapper.new_row(entity)
        restored = mapper.to_entity(row)
        assert restored.result == "confirmed"
        assert restored.evidence_ids == ["e1"]

    def test_in_memory_factory_persists_validation_entities(self) -> None:
        factory = InMemoryTidbRepositoryFactory()
        hypothesis = VulnerabilityHypothesis(hypothesis_id="h1", asset_id="app.example.com")
        factory.repository_for(VulnerabilityHypothesis).save(hypothesis)
        verdict = ValidationVerdict(verdict_id="v1", hypothesis_id="h1", result="validated")
        factory.repository_for(ValidationVerdict).save(verdict)
        assert factory.repository_for(VulnerabilityHypothesis).count() == 1
        assert factory.repository_for(ValidationVerdict).count() == 1
        restored = factory.repository_for(ValidationVerdict).get(verdict.id)
        assert restored.result == "validated"
