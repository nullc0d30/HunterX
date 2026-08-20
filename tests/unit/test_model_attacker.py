# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for the Phase 7 autonomous model-driven attack loop domain."""

from __future__ import annotations

import json

from hunterx.domain.model_attacker.dedup import hypothesis_fingerprint
from hunterx.domain.model_attacker.enums import AttackerCompletion, ModelFailureReason, ModelHypothesisStatus
from hunterx.domain.model_attacker.exhaustion import classify_completion, genuine_exhaustion
from hunterx.domain.model_attacker.learning import LearningContext, adjacent_paths_for
from hunterx.domain.model_attacker.models import ModelHypothesis
from hunterx.domain.model_attacker.reasoner import ModelReasoner, build_prompt
from hunterx.domain.model_attacker.telemetry import AttackerTelemetry


def _ai(response: str | None = None, *, fail: bool = False):
    """A minimal deterministic :class:`AIPort` double."""

    class _AI:
        def __init__(self) -> None:
            self.prompts: list[str] = []

        def complete(self, prompt: str, *, model: str | None = None, temperature: float = 0.0) -> str:
            self.prompts.append(prompt)
            if fail:
                raise RuntimeError("provider unavailable")
            return response or '{"hypotheses": []}'

        def embed(self, text: str) -> list[float]:  # noqa: ARG002
            return []

    return _AI()


def _context(surfaces: list[dict[str, object]] | None = None) -> dict[str, object]:
    return {
        "target": "http://localhost:8000/",
        "session_state": "anonymous",
        "surfaces": surfaces
        or [
            {"surface": "http://localhost:8000/vuln/search", "parameters": ["q"], "layer": "surface"},
            {"surface": "http://localhost:8000/vuln/echo", "parameters": ["msg"], "layer": "surface"},
        ],
        "catalog": ["sql-injection", "xss", "ssti"],
        "observations": [],
        "findings": [],
        "adjacent_paths": [],
        "disproven": [],
    }


class TestReasonerParsing:
    """The model reasoner validates every hypothesis against the real catalog."""

    def test_valid_hypotheses_are_accepted(self) -> None:
        response = json.dumps(
            {
                "hypotheses": [
                    {
                        "capability": "sql-injection",
                        "surface": "http://localhost:8000/vuln/search",
                        "attack_vector": "q",
                        "attack_strategy": "error-based",
                        "expected_signal": "error_based",
                        "priority": 0.9,
                        "confidence": 0.8,
                        "reasoning_context": "search reflects SQL errors",
                    }
                ]
            }
        )
        result = ModelReasoner(_ai(response)).reason(_context())
        assert result.usable
        hypothesis = result.hypotheses[0]
        assert hypothesis.capability == "sql-injection"
        assert hypothesis.surface == "http://localhost:8000/vuln/search"
        assert hypothesis.attack_vector == "q"
        assert hypothesis.status is ModelHypothesisStatus.PROPOSED

    def test_malformed_output_is_rejected_without_fabrication(self) -> None:
        result = ModelReasoner(_ai("totally not json")).reason(_context())
        assert not result.usable
        assert result.error
        assert result.failure_reason is not ModelFailureReason.NONE

    def test_code_fenced_json_is_accepted(self) -> None:
        payload = json.dumps(
            {
                "hypotheses": [
                    {
                        "capability": "xss",
                        "surface": "http://localhost:8000/vuln/echo",
                        "attack_vector": "msg",
                        "expected_signal": "reflected",
                    }
                ]
            }
        )
        result = ModelReasoner(_ai(f"```json\n{payload}\n```")).reason(_context())
        assert result.usable and result.hypotheses[0].capability == "xss"

    def test_out_of_catalog_capability_is_rejected(self) -> None:
        response = json.dumps(
            {"hypotheses": [{"capability": "made-up-class", "surface": "http://localhost:8000/vuln/search", "attack_vector": "q"}]}
        )
        result = ModelReasoner(_ai(response)).reason(_context())
        assert not result.usable
        assert any(item.get("capability") == "made-up-class" for item in result.rejected)

    def test_unknown_surface_is_rejected_as_out_of_scope(self) -> None:
        response = json.dumps(
            {"hypotheses": [{"capability": "sql-injection", "surface": "http://evil.example/x", "attack_vector": "q"}]}
        )
        result = ModelReasoner(_ai(response)).reason(_context())
        assert not result.usable
        assert any(item.get("surface") == "http://evil.example/x" for item in result.rejected)

    def test_empty_vector_is_rejected(self) -> None:
        response = json.dumps(
            {"hypotheses": [{"capability": "sql-injection", "surface": "http://localhost:8000/vuln/search", "attack_vector": ""}]}
        )
        result = ModelReasoner(_ai(response)).reason(_context())
        assert not result.usable

    def test_provider_failure_is_reported_not_fabricated(self) -> None:
        result = ModelReasoner(_ai(fail=True)).reason(_context())
        assert not result.usable
        assert result.error
        assert result.failure_reason in (
            ModelFailureReason.UNAVAILABLE,
            ModelFailureReason.TIMEOUT,
            ModelFailureReason.PROVIDER_LIMIT,
        )

    def test_no_model_means_no_hypotheses(self) -> None:
        result = ModelReasoner(ai=None).reason(_context())
        assert not result.usable
        assert result.failure_reason is ModelFailureReason.UNAVAILABLE

    def test_prompt_carries_target_catalog_and_surfaces(self) -> None:
        prompt = build_prompt(_context())
        assert "http://localhost:8000/" in prompt
        assert "sql-injection" in prompt
        assert "/vuln/search" in prompt
        assert "VALIDATED FINDINGS" in prompt


class TestHypothesisFingerprint:
    """Duplicates are recognised on the actionable tuple; escalation stays open."""

    def test_same_actionable_tuple_is_duplicate(self) -> None:
        first = hypothesis_fingerprint(capability="sql-injection", surface="http://x/", attack_vector="q", attack_strategy="error-based", authentication_context="anonymous")
        second = hypothesis_fingerprint(capability="sql-injection", surface="http://x/", attack_vector="q", attack_strategy="error-based", authentication_context="anonymous")
        assert first == second

    def test_different_vector_is_not_duplicate(self) -> None:
        first = hypothesis_fingerprint(capability="sql-injection", surface="http://x/", attack_vector="q", attack_strategy="error-based", authentication_context="anonymous")
        second = hypothesis_fingerprint(capability="sql-injection", surface="http://x/", attack_vector="id", attack_strategy="error-based", authentication_context="anonymous")
        assert first != second

    def test_different_auth_context_is_not_duplicate(self) -> None:
        first = hypothesis_fingerprint(capability="sql-injection", surface="http://x/", attack_vector="q", attack_strategy="error-based", authentication_context="anonymous")
        second = hypothesis_fingerprint(capability="sql-injection", surface="http://x/", attack_vector="q", attack_strategy="error-based", authentication_context="authenticated")
        assert first != second


class TestLearningContext:
    """Contradictions and findings expand, not stop, the search."""

    def test_adjacent_parameter_on_affected_surface(self) -> None:
        finding = {"capability": "sql-injection", "surface": "http://x/vuln/search", "vector": "q"}
        surfaces = [{"surface": "http://x/vuln/search", "parameters": ["q", "id"], "layer": "surface"}]
        paths = adjacent_paths_for(finding, surfaces)
        assert any(path["attack_vector"] == "id" for path in paths)

    def test_sibling_endpoint_path(self) -> None:
        finding = {"capability": "sql-injection", "surface": "http://x/vuln/search", "vector": "q"}
        surfaces = [
            {"surface": "http://x/vuln/search", "parameters": ["q"], "layer": "surface"},
            {"surface": "http://x/vuln/echo", "parameters": ["msg"], "layer": "surface"},
        ]
        paths = adjacent_paths_for(finding, surfaces)
        assert any(path["surface"] == "http://x/vuln/echo" and path["attack_vector"] == "msg" for path in paths)

    def test_disproven_hypothesis_is_remembered(self) -> None:
        learning = LearningContext()
        learning.remember_disproven("fp-1")
        assert "fp-1" in learning.summary()["disproven_hypotheses"]

    def test_finding_and_paths_recorded(self) -> None:
        learning = LearningContext()
        finding = {"capability": "sql-injection", "surface": "http://x/vuln/search", "vector": "q"}
        learning.record_finding(finding, related=[{"capability": "sql-injection", "surface": "http://x/vuln/echo", "attack_vector": "msg", "reason": "sibling"}])
        summary = learning.summary()
        assert len(summary["validated_findings"]) == 1
        assert len(summary["adjacent_paths"]) == 1


class TestExhaustionSemantics:
    """Genuine exhaustion is strict; resource ceilings are never completion."""

    def test_genuine_exhaustion_requires_every_source_empty(self) -> None:
        assert genuine_exhaustion(queue_exhausted=True, pending_hypotheses=0, pending_model_tasks=0, discovery_exhausted=True, surfaces_pending=False)
        assert not genuine_exhaustion(queue_exhausted=False, pending_hypotheses=0, pending_model_tasks=0, discovery_exhausted=True, surfaces_pending=False)
        assert not genuine_exhaustion(queue_exhausted=True, pending_hypotheses=1, pending_model_tasks=0, discovery_exhausted=True, surfaces_pending=False)
        assert not genuine_exhaustion(queue_exhausted=True, pending_hypotheses=0, pending_model_tasks=1, discovery_exhausted=True, surfaces_pending=False)

    def test_classify_completion_is_truthful(self) -> None:
        assert classify_completion(exhausted=True, resource_ceiling_hit=False, model_unavailable=False) == "exhausted"
        assert classify_completion(exhausted=False, resource_ceiling_hit=True, model_unavailable=False) == "resource_limit"
        assert classify_completion(exhausted=False, resource_ceiling_hit=False, model_unavailable=True) == "model_unavailable"
        assert classify_completion(exhausted=False, resource_ceiling_hit=False, model_unavailable=False) == "stopped"


class TestTelemetry:
    """Telemetry exposes the machine-readable autonomous-loop counters."""

    def test_telemetry_round_trips_json_safe(self) -> None:
        telemetry = AttackerTelemetry(
            model_calls=5,
            hypotheses_generated=4,
            hypotheses_accepted=3,
            post_finding_model_calls=2,
            validated_findings=1,
            completion_reason=AttackerCompletion.EXHAUSTED.value,
        )
        payload = json.loads(json.dumps(telemetry.to_dict()))
        assert payload["model_calls"] == 5
        assert payload["validated_findings"] == 1
        assert payload["post_finding_model_calls"] == 2
        assert payload["completion_reason"] == "exhausted"

    def test_telemetry_has_all_spec_fields(self) -> None:
        payload = AttackerTelemetry().to_dict()
        for field in (
            "model_calls",
            "hypotheses_generated",
            "hypotheses_accepted",
            "hypotheses_rejected",
            "hypotheses_exhausted",
            "model_generated_tasks",
            "model_task_execution_count",
            "model_feedback_events",
            "new_attack_paths",
            "finding_events",
            "post_finding_model_calls",
            "remaining_hypotheses",
            "remaining_attack_tasks",
            "completion_reason",
        ):
            assert field in payload


class TestHypothesisModel:
    """The structured hypothesis carries the actionable fields."""

    def test_hypothesis_to_dict_is_machine_readable(self) -> None:
        hypothesis = ModelHypothesis(capability="sql-injection", surface="http://x/", attack_vector="q")
        payload = hypothesis.to_dict()
        assert payload["capability"] == "sql-injection"
        assert payload["attack_vector"] == "q"
        assert payload["status"] == "proposed"
        assert "reasoning_context" in payload

    def test_with_status_returns_copy(self) -> None:
        hypothesis = ModelHypothesis(capability="sql-injection")
        updated = hypothesis.with_status(ModelHypothesisStatus.QUEUED)
        assert updated is not hypothesis
        assert updated.status is ModelHypothesisStatus.QUEUED
        assert hypothesis.status is ModelHypothesisStatus.PROPOSED


__all__: list[str] = []
