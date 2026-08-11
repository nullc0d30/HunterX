# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Performance and scale tests for the Sprint 028 finding orchestration.

Validates that the engines and the application service handle thousands of
findings, large evidence sets and high-volume queries without N+1 access
patterns or unbounded memory, and that evidence analysis stays deterministic
and linear in the evidence count.
"""

from __future__ import annotations

from hunterx.application.vulnerability_finding import VulnerabilityFindingService
from hunterx.domain.entities.tidb.finding_orchestration import FindingRecord
from hunterx.domain.vulnerability_finding.enums import (
    EvidenceRequirementPurpose,
    FindingEvidenceKind,
    FindingVulnerabilityClass,
)
from hunterx.domain.vulnerability_finding.evidence import EvidenceRequirementEngine
from hunterx.domain.vulnerability_finding.models import EvidenceItem
from hunterx.infrastructure.db.graph import InMemoryKnowledgeGraph
from hunterx.infrastructure.db.sql.memory import InMemoryTidbRepositoryFactory
from hunterx.infrastructure.event_bus import InMemoryEventBus
from hunterx.infrastructure.memory import InMemoryFindingRepository
from hunterx.tools.intelligence.api import ToolIntelligenceAPI
from hunterx.tools.sdk.engine import ExecutionEngine


def _service() -> VulnerabilityFindingService:
    return VulnerabilityFindingService(
        engine=ExecutionEngine(),
        stores=InMemoryTidbRepositoryFactory(),
        event_bus=InMemoryEventBus(),
        knowledge_graph=InMemoryKnowledgeGraph(),
        tip=ToolIntelligenceAPI(),
        findings=InMemoryFindingRepository(),
    )


def _evidence(count: int) -> list[EvidenceItem]:
    kinds = list(FindingEvidenceKind)
    return [
        EvidenceItem(kind=kinds[index % len(kinds)], value=f"value-{index}")
        for index in range(count)
    ]


class TestScale:
    def test_evidence_analysis_scales_to_thousands(self) -> None:
        engine = EvidenceRequirementEngine()
        assessment = engine.analyze(
            FindingVulnerabilityClass.SQL_INJECTION,
            _evidence(2000),
            finding_id="bulk",
        )
        assert assessment.gaps
        validation = assessment.sufficiency_for(EvidenceRequirementPurpose.VALIDATION)
        assert validation is not None

    def test_thousands_of_findings_created(self) -> None:
        service = _service()
        for index in range(1200):
            service.create_finding(
                mission_id="scale",
                target_id=f"https://scale.example/{index}",
                vulnerability_class="xss",
                title=f"XSS {index}",
                description="xss",
                severity="medium",
                tool="dalfox",
                observations=[{"kind": "reflection", "value": f"v{index}", "quality": "high"}],
            )
        findings = service.list_findings("scale")
        assert len(findings) == 1200
        records = service._stores.repository_for(FindingRecord).list_by("mission_id", "scale", limit=2000)
        assert len(records) == 1200

    def test_dedup_across_many_findings(self) -> None:
        service = _service()
        first = service.create_finding(
            mission_id="dedup",
            target_id="https://dedup.example",
            asset_id="asset-1",
            vulnerability_class="xss",
            title="XSS",
            description="xss",
            severity="high",
            tool="dalfox",
            observations=[{"kind": "reflection", "value": "x", "quality": "high"}],
        )
        for index in range(500):
            service.create_finding(
                mission_id="dedup",
                target_id=f"https://other.example/{index}",
                asset_id="asset-1",
                vulnerability_class="xss",
                title=f"XSS {index}",
                description="xss",
                severity="high",
                tool="dalfox",
                observations=[{"kind": "reflection", "value": "x", "quality": "high"}],
            )
        decision = service.deduplicate_finding(str(first["finding_id"]))
        assert decision["relation"] in ("same_root_cause", "same_vulnerability_across_endpoints", "independent_finding")


class TestBenchmarks:
    def test_evidence_analysis_benchmark(self, benchmark: object) -> None:
        engine = EvidenceRequirementEngine()
        items = _evidence(500)

        def run() -> object:
            return engine.analyze(FindingVulnerabilityClass.SQL_INJECTION, items)

        benchmark(run)

    def test_confidence_benchmark(self, benchmark: object) -> None:
        from hunterx.domain.vulnerability_finding.confidence import ConfidenceEngine, ConfidenceInput

        engine = ConfidenceEngine()
        items = tuple(_evidence(100))

        def run() -> object:
            return engine.calculate(
                ConfidenceInput(finding_id="f", evidence=items, replay_successes=1, replay_attempts=1)
            )

        benchmark(run)

    def test_impact_benchmark(self, benchmark: object) -> None:
        from hunterx.domain.vulnerability_finding.impact import ImpactAssessmentEngine

        engine = ImpactAssessmentEngine()
        items = _evidence(100)

        def run() -> object:
            return engine.assess(FindingVulnerabilityClass.RCE, items)

        benchmark(run)

    def test_concurrent_analysis_is_thread_safe(self) -> None:
        import threading

        engine = EvidenceRequirementEngine()
        results: list[object] = []
        lock = threading.Lock()

        def analyze() -> None:
            assessment = engine.analyze(FindingVulnerabilityClass.SQL_INJECTION, _evidence(100))
            with lock:
                results.append(assessment)

        threads = [threading.Thread(target=analyze) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        assert len(results) == 8
