# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Proof / PoC persistence tests (Sprint 034.3 §8).

PoC metadata and evidence must round-trip with target, finding, execution
context, tool, operation, reproduction information, validation result,
evidence, timestamp and provenance intact, and stay linked to the correct
finding.
"""

from __future__ import annotations

import pytest

from hunterx.domain.entities.tidb import (
    FindingRecord,
    ProofOfConcept,
    VulnerabilityProof,
)

pytest.importorskip("sqlalchemy")


def _complete_proof() -> VulnerabilityProof:
    return VulnerabilityProof(
        proof_id="P-rt",
        finding_id="F-rt",
        hypothesis_id="H-1",
        validation_id="V-1",
        mission_id="mis-rt",
        target_id="tgt-rt",
        asset_id="tgt-rt",
        vulnerability_id="CVE-2024-1234",
        proof_type="poc",
        proof_strategy="safe_validation",
        proof_status="proven",
        reproducibility_status="reproducible",
        safety_class="active",
        scope={"authorized": True, "target": "example.com"},
        preconditions=["outbound DNS allowed", "attacker-controlled server running"],
        steps=["submit url parameter", "observe callback"],
        inputs={"url": "https://attacker.example.com/cb"},
        expected_behavior="server performs a request to the supplied URL",
        observed_behavior="server issued a DNS lookup to attacker.example.com",
        evidence_ids=["ev-1", "ev-2"],
        impact_evidence_ids=["i-1"],
        replay_count=3,
        successful_replays=3,
        failed_replays=0,
        confidence=0.94,
        validated_at="2026-08-10T11:00:00+00:00",
        analysis_version="1.0.0",
        proof_version="1.0.0",
        provenance={"tool": "httpx", "engine": "proof-orchestration"},
        created_by="certification",
        meta={"proof_contract": "safe-validation/1.0.0"},
    )


def _assert_proof_fields(loaded: VulnerabilityProof) -> None:
    assert loaded.proof_id == "P-rt"
    assert loaded.finding_id == "F-rt"
    assert loaded.hypothesis_id == "H-1"
    assert loaded.validation_id == "V-1"
    assert loaded.mission_id == "mis-rt"
    assert loaded.target_id == "tgt-rt"
    assert loaded.asset_id == "tgt-rt"
    assert loaded.vulnerability_id == "CVE-2024-1234"
    assert loaded.proof_type == "poc"
    assert loaded.proof_strategy == "safe_validation"
    assert loaded.proof_status == "proven"
    assert loaded.reproducibility_status == "reproducible"
    assert loaded.safety_class == "active"
    assert loaded.scope == {"authorized": True, "target": "example.com"}
    assert loaded.preconditions == ["outbound DNS allowed", "attacker-controlled server running"]
    assert loaded.steps == ["submit url parameter", "observe callback"]
    assert loaded.inputs == {"url": "https://attacker.example.com/cb"}
    assert loaded.expected_behavior == "server performs a request to the supplied URL"
    assert loaded.observed_behavior == "server issued a DNS lookup to attacker.example.com"
    assert loaded.evidence_ids == ["ev-1", "ev-2"]
    assert loaded.impact_evidence_ids == ["i-1"]
    assert loaded.replay_count == 3
    assert loaded.successful_replays == 3
    assert loaded.failed_replays == 0
    assert loaded.confidence == 0.94
    assert loaded.validated_at == "2026-08-10T11:00:00+00:00"
    assert loaded.proof_version == "1.0.0"
    assert loaded.provenance == {"tool": "httpx", "engine": "proof-orchestration"}
    assert loaded.created_by == "certification"


def test_proof_roundtrips_through_sql(sql_factory) -> None:
    repo = sql_factory.repository_for(VulnerabilityProof)
    proof = _complete_proof()
    repo.save(proof)
    loaded = repo.get(proof.id)
    assert loaded is not None
    _assert_proof_fields(loaded)


def test_proof_roundtrips_through_memory(memory_factory) -> None:
    repo = memory_factory.repository_for(VulnerabilityProof)
    proof = _complete_proof()
    repo.save(proof)
    loaded = repo.get(proof.id)
    assert loaded is not None
    _assert_proof_fields(loaded)


def test_poc_roundtrip_and_finding_link(sql_factory) -> None:
    proof_repo = sql_factory.repository_for(VulnerabilityProof)
    poc_repo = sql_factory.repository_for(ProofOfConcept)
    finding_repo = sql_factory.repository_for(FindingRecord)

    proof = _complete_proof()
    proof_repo.save(proof)
    finding = FindingRecord(
        finding_id="F-rt",
        mission_id="mis-rt",
        target_id="tgt-rt",
        title="SSRF",
        proof_refs=["P-rt"],
        status="validated",
    )
    finding_repo.save(finding)
    poc = ProofOfConcept(
        poc_id="PoC-1",
        proof_id="P-rt",
        finding_id="F-rt",
        format="request/response",
        description="sanitized minimal request/response demonstrating the SSRF",
        preconditions=["attacker server available"],
        scope={"authorized": True},
        steps=["GET /fetch?url=https://attacker.example.com/cb"],
        inputs={"url": "https://attacker.example.com/cb"},
        expected_result="outbound request",
        observed_result="DNS callback observed",
        evidence=["ev-1"],
        replay_policy={"max_replays": 3, "safe": True},
        safety_policy="safe_validation",
        poc_version="1.0.0",
        status="validated",
        validated_at="2026-08-10T11:05:00+00:00",
    )
    poc_repo.save(poc)

    loaded_poc = poc_repo.get(poc.id)
    assert loaded_poc is not None
    assert loaded_poc.proof_id == "P-rt"
    assert loaded_poc.finding_id == "F-rt"
    assert loaded_poc.format == "request/response"
    assert loaded_poc.evidence == ["ev-1"]
    assert loaded_poc.safety_policy == "safe_validation"
    assert loaded_poc.status == "validated"

    # The PoC stays linked to the correct finding via the proof.
    loaded_finding = finding_repo.get(finding.id)
    assert loaded_finding is not None and loaded_finding.proof_refs == ["P-rt"]
    loaded_proof = proof_repo.get(proof.id)
    assert loaded_proof is not None and loaded_proof.finding_id == "F-rt"
