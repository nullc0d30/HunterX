# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Integration tests for the vulnerability proof platform wiring."""

from __future__ import annotations

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
    ProofPolicyDecision as TidbProofPolicyDecision,
)
from hunterx.domain.entities.tidb.proof import (
    ProofReplay as TidbProofReplay,
)
from hunterx.domain.entities.tidb.proof import (
    VulnerabilityProof as TidbVulnerabilityProof,
)
from hunterx.domain.vulnerability_validation.enums import ValidationClass
from hunterx.domain.vulnerability_validation.models import VulnerabilityHypothesis
from hunterx.domain.vulnerability_validation.safety import SafetyPolicy
from hunterx.domain.vulnerability_validation.scope import ValidationScopePolicy
from hunterx.platform.assembler import build_platform

SCOPE = ValidationScopePolicy(targets=("app.example.com",))
SAFETY = SafetyPolicy()

_PROOF_EVENTS = (
    "proof.created",
    "proof.planned",
    "proof.started",
    "proof.step.started",
    "proof.step.completed",
    "proof.generated",
    "proof.executed",
    "proof.replay.started",
    "proof.replay.completed",
    "proof.validated",
    "proof.failed",
    "proof.blocked",
    "proof.inconclusive",
    "proof.invalidated",
    "poc.created",
    "poc.validated",
    "impact.assessed",
    "confidence.calculated",
    "finding.proven",
    "finding.confirmed",
    "finding.report_ready",
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


class TestProofPlatform:
    def test_platform_wires_proof_service(self) -> None:
        platform = build_platform()
        assert platform.vulnerability_proof_service is not None
        assert platform.execution_engine.adapter_for("proof-replay") is not None
        assert platform.execution_engine.health_check("proof-replay")

    def test_full_proof_flow_persists_to_tidb(self) -> None:
        platform = build_platform()
        service = platform.vulnerability_proof_service
        result = service.run_proof(
            _hypothesis(),
            scope_policy=SCOPE,
            safety_policy=SAFETY,
            proof_inputs={"target": "https://app.example.com/x?id=1", "marker": "hx_abc", "expected": "marker reflected differently"},
            tool_output=_output("marker reflected differently"),
            replay_outputs=[_output("marker reflected differently"), _output("marker reflected differently")],
            replay_count=2,
        )
        assert result.proof.proof_status.value == "validated"
        stores = platform.tidb
        assert stores.repository_for(TidbVulnerabilityProof).count() >= 1
        assert stores.repository_for(TidbProofPlan).count() >= 1
        assert stores.repository_for(TidbProofOfConcept).count() >= 1
        assert stores.repository_for(TidbProofReplay).count() >= 2
        assert stores.repository_for(TidbImpactAssessment).count() >= 1
        assert stores.repository_for(TidbConfidenceAssessment).count() >= 1
        assert stores.repository_for(TidbFindingStateTransition).count() >= 1
        assert stores.repository_for(TidbProofPolicyDecision).count() >= 1

    def test_event_catalog_covers_proof_events(self) -> None:
        platform = build_platform()
        for event_type in _PROOF_EVENTS:
            assert platform.event_registry.has(event_type), event_type

    def test_knowledge_graph_updated(self) -> None:
        platform = build_platform()
        service = platform.vulnerability_proof_service
        result = service.run_proof(
            _hypothesis(),
            scope_policy=SCOPE,
            safety_policy=SAFETY,
            proof_inputs={"marker": "hx", "expected": "marker reflected differently"},
            tool_output=_output("marker reflected differently"),
            replay_outputs=[_output("marker reflected differently"), _output("marker reflected differently")],
            replay_count=2,
        )
        graph = platform.knowledge_graph
        neighbors = graph.query_neighbors(result.proof.proof_id)
        types = {item["type"] for item in neighbors}
        assert "has_proof_evidence" in types
        assert "has_impact" in types
        assert "has_confidence" in types

    def test_report_view_from_persisted_records(self) -> None:
        platform = build_platform()
        service = platform.vulnerability_proof_service
        result = service.run_proof(
            _hypothesis(),
            scope_policy=SCOPE,
            safety_policy=SAFETY,
            proof_inputs={"marker": "hx", "expected": "marker reflected differently"},
            tool_output=_output("marker reflected differently"),
            replay_outputs=[_output("marker reflected differently"), _output("marker reflected differently")],
            replay_count=2,
        )
        report = service.build_report(mission_id="m1", target_id="app.example.com")
        assert report["summary"]["reproducible"] is True
        assert result.proof.proof_status.value == "validated"
        from hunterx.reporting.proof import ProofReportView

        view = ProofReportView.from_data(report)
        assert view.summary.get("report_ready", 0) >= 1

    def test_scope_blocked_through_platform(self) -> None:
        platform = build_platform()
        service = platform.vulnerability_proof_service
        result = service.run_proof(
            _hypothesis(hypothesis_id="h2", target_id="evil.example.com", asset_id="evil.example.com"),
            scope_policy=SCOPE,
            safety_policy=SAFETY,
            tool_output=_output("x"),
        )
        assert result.blocked is True
        assert platform.tidb.repository_for(TidbProofPolicyDecision).count() >= 1
