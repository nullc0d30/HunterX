# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for vulnerability proof TIDB persistence."""

from __future__ import annotations

from hunterx.domain.entities.tidb.proof import (
    ConfidenceAssessment,
    FindingStateTransition,
    ImpactAssessment,
    ProofContract,
    ProofEvidence,
    ProofExecution,
    ProofHistory,
    ProofOfConcept,
    ProofPlan,
    ProofPolicyDecision,
    ProofQuality,
    ProofReplay,
    ProofStep,
    VulnerabilityProof,
)
from hunterx.infrastructure.db.sql.mapping import RowMapper
from hunterx.infrastructure.db.sql.memory import InMemoryTidbRepositoryFactory
from hunterx.infrastructure.db.sql.registry import ENTITY_TO_MODEL
from hunterx.shared.ids import generate_id


class TestProofTidbEntities:
    def test_entities_are_registered(self) -> None:
        entities = (
            VulnerabilityProof,
            ProofContract,
            ProofPlan,
            ProofStep,
            ProofExecution,
            ProofOfConcept,
            ProofReplay,
            ProofEvidence,
            ProofPolicyDecision,
            ImpactAssessment,
            ConfidenceAssessment,
            ProofQuality,
            FindingStateTransition,
            ProofHistory,
        )
        for entity in entities:
            assert entity in ENTITY_TO_MODEL, entity.__name__

    def test_models_use_tidb_prefix_tables(self) -> None:
        for entity, model in ENTITY_TO_MODEL.items():
            if entity in (
                VulnerabilityProof,
                ProofContract,
                ProofPlan,
                ProofStep,
                ProofExecution,
                ProofOfConcept,
                ProofReplay,
                ProofEvidence,
                ProofPolicyDecision,
                ImpactAssessment,
                ConfidenceAssessment,
                ProofQuality,
                FindingStateTransition,
                ProofHistory,
            ):
                assert model.__tablename__.startswith("tidb_"), model.__tablename__

    def test_rowmapper_round_trip(self) -> None:
        proof = VulnerabilityProof(
            proof_id=generate_id(),
            hypothesis_id=generate_id(),
            mission_id="m1",
            target_id="app.example.com",
            asset_id="app.example.com",
            proof_status="validated",
            evidence_ids=["e1"],
        )
        mapper = RowMapper(VulnerabilityProof)
        row = mapper.new_row(proof)
        restored = mapper.to_entity(row)
        assert restored.proof_id == proof.proof_id
        assert restored.proof_status == "validated"

    def test_in_memory_repository(self) -> None:
        factory = InMemoryTidbRepositoryFactory()
        proof = VulnerabilityProof(
            proof_id=generate_id(),
            hypothesis_id=generate_id(),
            mission_id="m1",
            target_id="app.example.com",
            asset_id="app.example.com",
        )
        repo = factory.repository_for(VulnerabilityProof)
        repo.save(proof)
        assert repo.count() == 1
        assert repo.get(proof.id) is not None
