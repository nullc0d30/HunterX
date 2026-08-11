# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Security tests for the vulnerability proof & PoC engine."""

from __future__ import annotations

import pytest

from hunterx.application.vulnerability_proof import VulnerabilityProofService
from hunterx.domain.vulnerability_proof.enums import ProofState
from hunterx.domain.vulnerability_validation.enums import SafetyClass, ValidationClass
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


def _hypothesis(*, target: str = "app.example.com", cls: ValidationClass = ValidationClass.SQL_INJECTION, hypothesis_id: str = "h-sec") -> VulnerabilityHypothesis:
    return VulnerabilityHypothesis(
        hypothesis_id=hypothesis_id,
        mission_id="m-sec",
        target_id=target,
        asset_id=target,
        vulnerability_id="CVE-2024-SEC",
        type=cls,
        expected_behavior="marker reflected differently",
    )


def _output(value: str, kind: str = "behavioral_differential") -> dict:
    return {"observations": [{"kind": kind, "value": value, "confidence": 0.9, "metadata": {"expected": value}}]}


class TestScopeSecurity:
    def test_dot_suffix_cannot_escape_scope(self) -> None:
        service = _service()
        result = service.run_proof(
            _hypothesis(target="app.example.com.evil.com", hypothesis_id="h-scope1"),
            scope_policy=SCOPE,
            safety_policy=SAFETY,
            tool_output=_output("x"),
        )
        assert result.blocked is True

    def test_wildcard_is_not_wildcard(self) -> None:
        service = _service()
        result = service.run_proof(
            _hypothesis(target="*.example.com", hypothesis_id="h-scope2"),
            scope_policy=SCOPE,
            safety_policy=SAFETY,
            tool_output=_output("x"),
        )
        assert result.blocked is True

    def test_redirect_like_target_change_blocked(self) -> None:
        service = _service()
        hypothesis = VulnerabilityHypothesis(
            hypothesis_id="h-scope3",
            mission_id="m-sec",
            target_id="app.example.com",
            asset_id="attacker.example.com",
            vulnerability_id="CVE-1",
            type=ValidationClass.SQL_INJECTION,
        )
        result = service.run_proof(hypothesis, scope_policy=SCOPE, safety_policy=SAFETY, tool_output=_output("x"))
        assert result.blocked is True

    def test_dns_rebinding_stop_condition(self) -> None:
        service = _service()
        result = service.run_proof(
            _hypothesis(hypothesis_id="h-scope4"),
            scope_policy=SCOPE,
            safety_policy=SAFETY,
            tool_output=_output("x"),
            stop_check=lambda: "target-instability",
        )
        assert result.blocked is True
        assert "stop condition" in result.block_reason


class TestSafetySecurity:
    def test_shell_marker_inputs_blocked(self) -> None:
        service = _service()
        for marker in ("rm -rf /", "$(id)", "1; nc -e /bin/sh"):
            result = service.run_proof(
                _hypothesis(hypothesis_id=f"h-safety-{abs(hash(marker))}"),
                scope_policy=SCOPE,
                safety_policy=SAFETY,
                proof_inputs={"param": marker},
                tool_output=_output("x"),
            )
            assert result.blocked is True, marker
            assert "safety" in result.block_reason, marker

    def test_destructive_safety_class_rejected(self) -> None:
        service = _service()
        hypothesis = VulnerabilityHypothesis(
            hypothesis_id="h-safety-destructive",
            mission_id="m-sec",
            target_id="app.example.com",
            asset_id="app.example.com",
            vulnerability_id="CVE-1",
            type=ValidationClass.SQL_INJECTION,
            safety_class=SafetyClass.DESTRUCTIVE,
        )
        with pytest.raises(ValueError):
            service.create_proof(hypothesis)

    def test_data_extraction_action_refused(self) -> None:
        from hunterx.domain.vulnerability_proof.contracts import FORBIDDEN_PROOF_ACTIONS

        assert "mass-data-extraction" in FORBIDDEN_PROOF_ACTIONS
        assert "table-dumping" in FORBIDDEN_PROOF_ACTIONS
        assert "credential-dumping" in FORBIDDEN_PROOF_ACTIONS
        assert "persistence" in FORBIDDEN_PROOF_ACTIONS
        assert "reverse-shell" in FORBIDDEN_PROOF_ACTIONS


class TestReplaySecurity:
    def test_replay_budget_is_bounded(self) -> None:
        service = _service()
        hypothesis = _hypothesis(hypothesis_id="h-replay-bound")
        # Force an absurd replay_count; the policy caps it.
        result = service.run_proof(
            hypothesis,
            scope_policy=SCOPE,
            safety_policy=SAFETY,
            proof_inputs={"marker": "hx", "expected": "marker reflected differently"},
            tool_output=_output("marker reflected differently"),
            replay_outputs=[_output("marker reflected differently")] * 100,
            replay_count=100,
        )
        assert result.proof.replay_count <= 3

    def test_replay_against_wrong_target_blocked(self) -> None:
        service = _service()
        result = service.run_proof(
            _hypothesis(target="other.example.com", hypothesis_id="h-replay-target"),
            scope_policy=SCOPE,
            safety_policy=SAFETY,
            tool_output=_output("x"),
        )
        assert result.blocked is True

    def test_failed_replay_never_false_positive(self) -> None:
        service = _service()
        result = service.run_proof(
            _hypothesis(hypothesis_id="h-replay-fail"),
            scope_policy=SCOPE,
            safety_policy=SAFETY,
            proof_inputs={"marker": "hx", "expected": "marker reflected differently"},
            tool_output=_output("marker reflected differently"),
            replay_outputs=[_output("no reflection"), _output("no reflection")],
            replay_count=2,
        )
        assert result.proof.proof_status in (ProofState.INCONCLUSIVE, ProofState.FAILED)
        assert result.proof.proof_status != ProofState.INVALIDATED
        assert not any(t.to_state.value == "false_positive" for t in result.transitions)


class TestEvidenceSecurity:
    def test_secret_redacted_in_poc(self) -> None:
        service = _service()
        hypothesis = _hypothesis(hypothesis_id="h-secret")
        result = service.run_proof(
            hypothesis,
            scope_policy=SCOPE,
            safety_policy=SAFETY,
            proof_inputs={"marker": "hx", "expected": "sk-live-SECRET123 value revealed", "secret": "sk-live-SECRET123"},
            tool_output={"observations": [{"kind": "secret", "value": "sk-live-SECRET123 value revealed", "confidence": 0.9}]},
            replay_outputs=[{"observations": [{"kind": "secret", "value": "sk-live-SECRET123 value revealed", "confidence": 0.9}]}] * 2,
            replay_count=2,
        )
        assert result.poc is not None
        rendered = str(result.poc.to_dict())
        assert "sk-live-SECRET123" not in rendered

    def test_cross_target_leakage_prevented(self) -> None:
        service = _service()
        a = service.run_proof(
            _hypothesis(hypothesis_id="h-leak-a"),
            scope_policy=SCOPE,
            safety_policy=SAFETY,
            proof_inputs={"marker": "hx", "expected": "marker reflected differently"},
            tool_output=_output("marker reflected differently"),
            replay_outputs=[_output("marker reflected differently"), _output("marker reflected differently")],
            replay_count=2,
        )
        b = service.run_proof(
            _hypothesis(target="app2.example.com", hypothesis_id="h-leak-b"),
            scope_policy=ValidationScopePolicy(targets=("app2.example.com",)),
            safety_policy=SAFETY,
            proof_inputs={"marker": "hx", "expected": "marker reflected differently"},
            tool_output=_output("marker reflected differently"),
            replay_outputs=[_output("marker reflected differently"), _output("marker reflected differently")],
            replay_count=2,
        )
        assert a.proof.asset_id != b.proof.asset_id
        assert set(a.proof.evidence_ids).isdisjoint(set(b.proof.evidence_ids))

    def test_raw_tool_output_never_confirms(self) -> None:
        service = _service()
        result = service.run_proof(
            _hypothesis(hypothesis_id="h-raw"),
            scope_policy=SCOPE,
            safety_policy=SAFETY,
            tool_output={"observations": [{"kind": "behavioral_differential", "value": "raw claim", "confidence": 0.99}]},
            replay_outputs=[{"observations": [{"kind": "behavioral_differential", "value": "no marker", "confidence": 0.99}]}] * 2,
            replay_count=2,
        )
        # A raw claim with failing replays must not confirm.
        assert result.proof.proof_status != ProofState.VALIDATED


class TestResourceSecurity:
    def test_bounded_inputs(self) -> None:
        service = _service()
        result = service.run_proof(
            _hypothesis(hypothesis_id="h-bound"),
            scope_policy=SCOPE,
            safety_policy=SAFETY,
            proof_inputs={"marker": "x" * 10_000, "expected": "x" * 10_000},
            tool_output=_output("marker reflected differently"),
            replay_outputs=[_output("marker reflected differently"), _output("marker reflected differently")],
            replay_count=2,
        )
        assert result.poc is not None
        rendered = str(result.poc.to_dict())
        assert len(rendered) < 20_000

    def test_no_unbounded_proof_loop(self) -> None:
        from hunterx.domain.vulnerability_proof.policy import ABSOLUTE_MAX_REPLAYS

        assert ABSOLUTE_MAX_REPLAYS == 10
