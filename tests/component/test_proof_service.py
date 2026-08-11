# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Component tests for the vulnerability proof service pipeline."""

from __future__ import annotations

from hunterx.application.vulnerability_proof import VulnerabilityProofService
from hunterx.domain.entities.tidb.proof import (
    ConfidenceAssessment as TidbConfidenceAssessment,
)
from hunterx.domain.entities.tidb.proof import (
    FindingStateTransition as TidbFindingStateTransition,
)
from hunterx.domain.entities.tidb.proof import (
    ImpactAssessment as TidbImpactAssessment,
)
from hunterx.domain.entities.tidb.proof import (
    ProofOfConcept as TidbProofOfConcept,
)
from hunterx.domain.entities.tidb.proof import (
    ProofPlan as TidbProofPlan,
)
from hunterx.domain.entities.tidb.proof import (
    ProofReplay as TidbProofReplay,
)
from hunterx.domain.entities.tidb.proof import (
    VulnerabilityProof as TidbVulnerabilityProof,
)
from hunterx.domain.vulnerability_proof.enums import ProofState
from hunterx.domain.vulnerability_validation.enums import ValidationClass
from hunterx.domain.vulnerability_validation.models import VulnerabilityHypothesis
from hunterx.domain.vulnerability_validation.safety import SafetyPolicy
from hunterx.domain.vulnerability_validation.scope import ValidationScopePolicy
from hunterx.infrastructure.db.graph import InMemoryKnowledgeGraph
from hunterx.infrastructure.db.sql.memory import InMemoryTidbRepositoryFactory
from hunterx.infrastructure.event_bus import InMemoryEventBus
from hunterx.tools.proof_replay import register_proof_replay_adapters
from hunterx.tools.sdk.engine import ExecutionEngine

SCOPE = ValidationScopePolicy(targets=("app.example.com",))
SAFETY = SafetyPolicy()


def _build_service() -> VulnerabilityProofService:
    engine = ExecutionEngine()
    register_proof_replay_adapters(engine)
    engine.install_hook("proof-replay", lambda tool_id, version: "1.0.0")
    engine.install("proof-replay", version="1.0.0")
    return VulnerabilityProofService(
        engine=engine,
        stores=InMemoryTidbRepositoryFactory(),
        event_bus=InMemoryEventBus(),
        knowledge_graph=InMemoryKnowledgeGraph(),
    )


def _hypothesis(**kwargs) -> VulnerabilityHypothesis:
    defaults = dict(
        hypothesis_id="h1",
        mission_id="m1",
        target_id="app.example.com",
        asset_id="app.example.com",
        vulnerability_id="CVE-2024-0001",
        type=ValidationClass.SQL_INJECTION,
        expected_behavior="marker reflected differently",
    )
    defaults.update(kwargs)
    return VulnerabilityHypothesis(**defaults)


def _output(value: str, kind: str = "behavioral_differential") -> dict:
    return {
        "observations": [
            {"kind": kind, "value": value, "confidence": 0.9, "metadata": {"expected": value}}
        ]
    }


class TestProofServiceLifecycle:
    def test_full_validated_flow(self) -> None:
        service = _build_service()
        result = service.run_proof(
            _hypothesis(),
            scope_policy=SCOPE,
            safety_policy=SAFETY,
            proof_inputs={"target": "https://app.example.com/x?id=1", "marker": "hx_abc", "expected": "marker reflected differently"},
            tool_output=_output("marker reflected differently"),
            replay_outputs=[_output("marker reflected differently"), _output("marker reflected differently")],
            replay_count=2,
        )
        assert result.proof.proof_status == ProofState.VALIDATED
        assert result.proof.reproducibility_status.value == "reproducible"
        assert result.proof.successful_replays == 2
        assert result.impact is not None
        assert result.confidence is not None
        assert result.confidence.confidence > 0.0
        assert result.package is not None
        assert any(t.to_state.value == "proven" for t in result.transitions)
        assert any(t.to_state.value == "report_ready" for t in result.transitions)
        assert result.report is not None
        assert result.report["summary"]["report_ready"] is True

    def test_scope_blocked_never_executes(self) -> None:
        service = _build_service()
        hypothesis = _hypothesis(
            target_id="evil.example.com",
            asset_id="evil.example.com",
            hypothesis_id="h2",
        )
        result = service.run_proof(
            hypothesis,
            scope_policy=SCOPE,
            safety_policy=SAFETY,
            tool_output=_output("marker reflected differently"),
        )
        assert result.blocked is True
        assert result.block_reason == "scope_blocked"
        assert result.proof.proof_status == ProofState.BLOCKED

    def test_out_of_scope_replay_blocked(self) -> None:
        service = _build_service()
        result = service.run_proof(
            _hypothesis(target_id="attacker.example.com", asset_id="attacker.example.com", hypothesis_id="h3"),
            scope_policy=SCOPE,
            safety_policy=SAFETY,
            tool_output=_output("marker reflected differently"),
        )
        assert result.blocked is True

    def test_inconclusive_when_evidence_insufficient(self) -> None:
        service = _build_service()
        result = service.run_proof(
            _hypothesis(hypothesis_id="h4"),
            scope_policy=SCOPE,
            safety_policy=SAFETY,
            tool_output={"observations": []},
            replay_outputs=[],
            replay_count=1,
        )
        assert result.proof.proof_status == ProofState.INCONCLUSIVE

    def test_inconclusive_on_replay_failure(self) -> None:
        service = _build_service()
        result = service.run_proof(
            _hypothesis(hypothesis_id="h5"),
            scope_policy=SCOPE,
            safety_policy=SAFETY,
            proof_inputs={"marker": "hx", "expected": "marker reflected differently"},
            tool_output=_output("marker reflected differently"),
            replay_outputs=[_output("no reflection"), _output("no reflection")],
            replay_count=2,
        )
        assert result.proof.proof_status == ProofState.INCONCLUSIVE
        assert result.proof.reproducibility_status.value == "not_reproducible"

    def test_persists_to_tidb(self) -> None:
        service = _build_service()
        stores = service._stores  # type: ignore[attr-defined]
        result = service.run_proof(
            _hypothesis(hypothesis_id="h6"),
            scope_policy=SCOPE,
            safety_policy=SAFETY,
            proof_inputs={"marker": "hx", "expected": "marker reflected differently"},
            tool_output=_output("marker reflected differently"),
            replay_outputs=[_output("marker reflected differently"), _output("marker reflected differently")],
            replay_count=2,
        )
        assert result.proof.proof_status == ProofState.VALIDATED
        assert stores.repository_for(TidbVulnerabilityProof).count() >= 1
        assert stores.repository_for(TidbProofPlan).count() >= 1
        assert stores.repository_for(TidbProofOfConcept).count() >= 1
        assert stores.repository_for(TidbProofReplay).count() >= 2
        assert stores.repository_for(TidbImpactAssessment).count() >= 1
        assert stores.repository_for(TidbConfidenceAssessment).count() >= 1
        assert stores.repository_for(TidbFindingStateTransition).count() >= 1

    def test_poc_versioning(self) -> None:
        service = _build_service()
        hypothesis = _hypothesis(hypothesis_id="h7")
        plan = service.plan_proof(service.create_proof(hypothesis), hypothesis)
        proof = service.proofs(mission_id="m1")[0]
        poc = service.generate_poc(proof, plan, hypothesis)
        v2 = service.version_poc(poc, reason="changed marker", changes=("marker",), inputs={"marker": "b"})
        assert v2.poc_id == poc.poc_id
        assert v2.version != poc.version

    def test_queries_return_persisted_records(self) -> None:
        service = _build_service()
        hypothesis = _hypothesis(hypothesis_id="h8")
        result = service.run_proof(
            hypothesis,
            scope_policy=SCOPE,
            safety_policy=SAFETY,
            proof_inputs={"marker": "hx", "expected": "marker reflected differently"},
            tool_output=_output("marker reflected differently"),
            replay_outputs=[_output("marker reflected differently"), _output("marker reflected differently")],
            replay_count=2,
        )
        assert service.proofs(mission_id="m1")
        assert service.pocs(proof_id=result.proof.proof_id)
        assert service.replays(proof_id=result.proof.proof_id)
        assert service.transitions(hypothesis_id="h8")
