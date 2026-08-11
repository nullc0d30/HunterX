# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Performance benchmarks for the vulnerability proof & PoC engine."""

from __future__ import annotations

from hunterx.application.vulnerability_proof import VulnerabilityProofService
from hunterx.domain.vulnerability_proof.confidence import ConfidenceEngine
from hunterx.domain.vulnerability_proof.models import ProofOfConcept, VulnerabilityProof
from hunterx.domain.vulnerability_proof.replay import ReplayEngine
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


def _service() -> VulnerabilityProofService:
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


def _hypothesis(hypothesis_id: str) -> VulnerabilityHypothesis:
    return VulnerabilityHypothesis(
        hypothesis_id=hypothesis_id,
        mission_id="m-bench",
        target_id="app.example.com",
        asset_id="app.example.com",
        vulnerability_id="CVE-2024-BENCH",
        type=ValidationClass.SQL_INJECTION,
        expected_behavior="marker reflected differently",
    )


def _output(value: str = "marker reflected differently") -> dict:
    return {"observations": [{"kind": "behavioral_differential", "value": value, "confidence": 0.9, "metadata": {"expected": value}}]}


class TestProofBenchmarks:
    def test_proof_creation_benchmark(self, benchmark) -> None:
        service = _service()

        def create() -> int:
            for index in range(50):
                service.create_proof(_hypothesis(f"h-{index}"))
            return 50

        count = benchmark(create)
        assert count == 50

    def test_proof_run_benchmark(self, benchmark) -> None:
        service = _service()

        def run_all() -> int:
            for index in range(20):
                service.run_proof(
                    _hypothesis(f"h-run-{index}"),
                    scope_policy=SCOPE,
                    safety_policy=SAFETY,
                    proof_inputs={"marker": "hx", "expected": "marker reflected differently"},
                    tool_output=_output(),
                    replay_outputs=[_output(), _output()],
                    replay_count=2,
                )
            return 20

        count = benchmark(run_all)
        assert count == 20

    def test_replay_evaluation_benchmark(self, benchmark) -> None:
        engine = ReplayEngine()
        poc = ProofOfConcept(proof_id="p", expected_result="marker reflected differently")
        proof = VulnerabilityProof(proof_id="p")

        def replay_all() -> int:
            for _ in range(200):
                engine.replay(poc, proof, observed_behavior="marker reflected differently", expected_behavior="marker reflected differently")
            return 200

        assert benchmark(replay_all) == 200

    def test_confidence_calculation_benchmark(self, benchmark) -> None:
        engine = ConfidenceEngine()

        def calculate_all() -> int:
            for _ in range(200):
                engine.calculate(proof_id="p", finding_id="f")
            return 200

        assert benchmark(calculate_all) == 200

    def test_large_evidence_set(self) -> None:
        service = _service()
        result = service.run_proof(
            _hypothesis("h-large"),
            scope_policy=SCOPE,
            safety_policy=SAFETY,
            proof_inputs={"marker": "hx", "expected": "marker reflected differently"},
            tool_output={"observations": [{"kind": "behavioral_differential", "value": "marker reflected differently", "confidence": 0.9} for _ in range(200)]},
            replay_outputs=[_output(), _output()],
            replay_count=2,
        )
        assert len(result.evidence) == 200

    def test_large_proof_set_query(self) -> None:
        service = _service()
        for index in range(50):
            service.run_proof(
                _hypothesis(f"h-q-{index}"),
                scope_policy=SCOPE,
                safety_policy=SAFETY,
                proof_inputs={"marker": "hx", "expected": "marker reflected differently"},
                tool_output=_output(),
                replay_outputs=[_output(), _output()],
                replay_count=2,
            )
        assert len(service.proofs(mission_id="m-bench", limit=500)) >= 50

    def test_temporal_differential_large(self) -> None:
        from hunterx.domain.vulnerability_proof.enums import ProofState
        from hunterx.domain.vulnerability_proof.temporal import ProofSnapshot, ProofTemporalDifferencer

        differencer = ProofTemporalDifferencer()
        current = [
            ProofSnapshot(key=f"k{i}", proof_id=f"p{i}", hypothesis_id=f"h{i}", mission_id="m", asset_id="app", vulnerability_id="CVE", state=ProofState.VALIDATED)
            for i in range(200)
        ]
        previous = [
            ProofSnapshot(key=f"k{i}", proof_id=f"p{i}", hypothesis_id=f"h{i}", mission_id="m", asset_id="app", vulnerability_id="CVE", state=ProofState.CANDIDATE)
            for i in range(200)
        ]
        diff = differencer.diff(current, previous)
        assert len(diff) == 200
