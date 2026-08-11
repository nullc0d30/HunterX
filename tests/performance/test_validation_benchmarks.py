# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Performance benchmarks for the safe vulnerability validation engine."""

from __future__ import annotations

from hunterx.application.vulnerability_validation import VulnerabilityValidationService
from hunterx.domain.vulnerability_validation.enums import ValidationClass
from hunterx.domain.vulnerability_validation.history import HypothesisSnapshot
from hunterx.domain.vulnerability_validation.safety import SafetyPolicy
from hunterx.domain.vulnerability_validation.scope import ValidationScopePolicy
from hunterx.infrastructure.db.graph import InMemoryKnowledgeGraph
from hunterx.infrastructure.db.sql.memory import InMemoryTidbRepositoryFactory
from hunterx.infrastructure.event_bus import InMemoryEventBus
from hunterx.tools.safe_validation import register_validation_adapters
from hunterx.tools.sdk.engine import ExecutionEngine

SCOPE = ValidationScopePolicy(targets=("app.example.com",))
SAFETY = SafetyPolicy()


def _service() -> VulnerabilityValidationService:
    engine = ExecutionEngine()
    register_validation_adapters(engine)
    for tool_id in ("passive-probe", "version-probe", "error-behavior-probe"):
        engine.install_hook(tool_id, lambda tool_id, version: "1.0.0")
        engine.install(tool_id, version="1.0.0")
    return VulnerabilityValidationService(
        engine=engine,
        stores=InMemoryTidbRepositoryFactory(),
        event_bus=InMemoryEventBus(),
        knowledge_graph=InMemoryKnowledgeGraph(),
    )


def _confirmed_output() -> dict:
    return {
        "observations": [
            {"kind": "version", "value": "1.24.0", "confidence": 1.0, "metadata": {"expected": "1.24.0"}}
        ]
    }


class TestValidationBenchmarks:
    def test_hypothesis_creation_benchmark(self, benchmark) -> None:
        service = _service()

        def create() -> None:
            for index in range(50):
                service.create_hypothesis(
                    mission_id=f"m-{index}", target_id="app.example.com", asset_id="app.example.com",
                    vulnerability_id=f"CVE-{index}", class_name=ValidationClass.KNOWN_VULNERABLE_SOFTWARE,
                )

        benchmark(create)

    def test_validation_run_benchmark(self, benchmark) -> None:
        service = _service()

        def run_all() -> None:
            for index in range(30):
                hypothesis = service.create_hypothesis(
                    mission_id=f"run-{index}", target_id="app.example.com", asset_id="app.example.com",
                    vulnerability_id=f"CVE-{index}", class_name=ValidationClass.KNOWN_VULNERABLE_SOFTWARE,
                )
                plan = service.plan_validation(hypothesis)
                service.run_validation(
                    hypothesis, plan=plan, scope_policy=SCOPE, safety_policy=SAFETY,
                    probe_parameters=_confirmed_output(),
                )

        benchmark(run_all)

    def test_verdict_evaluation_benchmark(self, benchmark) -> None:
        from hunterx.domain.vulnerability_validation.enums import EvidenceKind
        from hunterx.domain.vulnerability_validation.evidence import EvidenceBuilder, EvidenceContext
        from hunterx.domain.vulnerability_validation.models import ValidationObservation
        from hunterx.domain.vulnerability_validation.rules import ValidationRuleSet
        from hunterx.domain.vulnerability_validation.verdict import VerdictEngine

        rules = ValidationRuleSet()
        engine = VerdictEngine(rules)
        rule = rules.require(ValidationClass.KNOWN_VULNERABLE_SOFTWARE)
        context = EvidenceContext(validation_id="v", hypothesis_id="h")
        builder = EvidenceBuilder(context)
        evidence = [
            builder.build(
                ValidationObservation(kind=EvidenceKind.VERSION, value="1.24.0", confidence=1.0, metadata={"expected": "1.24.0"})
            )
        ]

        def evaluate() -> None:
            for _ in range(100):
                engine.evaluate(hypothesis_id="h", validation_id="v", rule=rule, evidence=evidence)

        benchmark(evaluate)

    def test_large_evidence_set(self) -> None:
        service = _service()
        hypothesis = service.create_hypothesis(
            mission_id="large", target_id="app.example.com", asset_id="app.example.com",
            vulnerability_id="CVE-2024-1234", class_name=ValidationClass.KNOWN_VULNERABLE_SOFTWARE,
        )
        plan = service.plan_validation(hypothesis)
        observations = [
            {"kind": "version", "value": f"1.24.{index % 10}", "confidence": 1.0, "metadata": {"expected": "1.24.0"}}
            for index in range(200)
        ]
        result = service.run_validation(
            hypothesis, plan=plan, scope_policy=SCOPE, safety_policy=SAFETY,
            probe_parameters={"observations": observations},
        )
        assert len(result.evidence) == 200
        assert result.verdict is not None

    def test_large_hypothesis_set_query(self) -> None:
        service = _service()
        for index in range(200):
            service.create_hypothesis(
                mission_id="big-mission", target_id="app.example.com", asset_id="app.example.com",
                vulnerability_id=f"CVE-{index}", class_name=ValidationClass.KNOWN_VULNERABLE_SOFTWARE,
            )
        hypotheses = service.hypotheses(mission_id="big-mission", limit=500)
        assert len(hypotheses) == 200

    def test_historical_differential_analysis(self, benchmark) -> None:
        service = _service()
        previous = [
            HypothesisSnapshot(
                key=f"hypothesis:app.example.com|CVE-{index}|",
                hypothesis_id=f"h-{index}",
                mission_id="m0",
                asset_id="app.example.com",
                vulnerability_id=f"CVE-{index}",
                technology_id="",
                state=__import__("hunterx.domain.vulnerability_validation.enums", fromlist=["VulnerabilityState"]).VulnerabilityState.CONFIRMED,
                confidence=0.9,
            )
            for index in range(200)
        ]

        def diff() -> None:
            differencer = service._differencer
            for _ in range(10):
                differencer.diff(previous, previous)

        benchmark(diff)
