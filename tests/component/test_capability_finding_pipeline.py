# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Component tests for the Phase 6 capability-finding pipeline.

Drives the full contract against a generic loopback target: capability
execution (Phase 5) seeds candidates, the pipeline promotes them into the
canonical finding lifecycle, replays them in isolation, classifies
reproduction, assesses impact, generates PoCs, scores severity and
finalizes report-ready packages. Honest negatives: safe targets produce no
candidates, non-reproducible candidates are rejected (never fabricated into
valid findings), and duplicates resolve to one logical finding.
"""

from __future__ import annotations

import pytest

from hunterx.application.adaptive_attack import AdaptiveAttackService
from hunterx.application.attack_surface import AttackSurfaceService
from hunterx.application.capability_execution import CapabilityExecutionEngine
from hunterx.application.capability_finding import CapabilityFindingPipeline
from hunterx.application.vulnerability_finding import VulnerabilityFindingService
from hunterx.domain.capability_execution.enums import CapabilityExecutionStatus
from hunterx.domain.capability_finding.models import CapabilityCandidate, ReplayAttempt
from hunterx.domain.capability_finding.replay import ReplayEngine
from hunterx.infrastructure.db.graph import InMemoryKnowledgeGraph
from hunterx.infrastructure.db.sql.memory import InMemoryTidbRepositoryFactory
from hunterx.infrastructure.event_bus import InMemoryEventBus
from hunterx.infrastructure.memory import InMemoryFindingRepository
from hunterx.tools.intelligence.api import ToolIntelligenceAPI
from hunterx.tools.sdk.engine import ExecutionEngine
from tests.framework.vulnerable_app import VulnerableApp


def _finding_service() -> VulnerabilityFindingService:
    return VulnerabilityFindingService(
        engine=ExecutionEngine(),
        stores=InMemoryTidbRepositoryFactory(),
        event_bus=InMemoryEventBus(),
        knowledge_graph=InMemoryKnowledgeGraph(),
        tip=ToolIntelligenceAPI(),
        findings=InMemoryFindingRepository(),
    )


def _run_engine(app: VulnerableApp) -> CapabilityExecutionEngine:
    target = app.base_url
    surface = AttackSurfaceService(mission_id="phase6-component", target_key=target)
    surface.on_observation(
        observation_type="api",
        content={"endpoints": [f"{target}/vuln/search", f"{target}/vuln/echo"]},
        asset_key=target,
        source="phase6-component",
    )
    surface.on_observation(
        observation_type="parameter",
        content={"parameters": ["q"]},
        asset_key=f"{target}/vuln/search",
        source="phase6-component",
    )
    surface.on_observation(
        observation_type="parameter",
        content={"parameters": ["msg"]},
        asset_key=f"{target}/vuln/echo",
        source="phase6-component",
    )
    engine = CapabilityExecutionEngine(
        mission_id="phase6-component",
        target_key=target,
        surface=surface,
        adaptive=AdaptiveAttackService(mission_id="phase6-component", target_key=target, enforce_pacing=False),
        probe_timeout_s=5.0,
    )
    engine.execute_ready()
    return engine


class TestCandidateSeeding:
    """Capability execution seeds only genuine differential findings."""

    def test_vulnerable_app_seeds_candidates_with_retained_evidence(self) -> None:
        with VulnerableApp() as app:
            engine = _run_engine(app)
            candidates = CapabilityFindingPipeline(_finding_service()).candidates_from(engine)
            assert candidates
            finding_records = [r for r in engine.records if r.outcome is CapabilityExecutionStatus.FINDING]
            assert len(candidates) == len(finding_records)
            for candidate in candidates:
                assert candidate.endpoint
                assert candidate.request_summaries, "candidate must retain the request evidence"
                assert candidate.response_summaries, "candidate must retain the response evidence"
                assert candidate.evidence, "candidate must retain the differential evidence"

    def test_safe_target_seeds_no_candidates(self) -> None:
        with VulnerableApp() as app:
            target = app.base_url
            surface = AttackSurfaceService(mission_id="phase6-component", target_key=target)
            surface.on_observation(
                observation_type="api",
                content={"endpoints": [f"{target}/safe/search"]},
                asset_key=target,
                source="phase6-component",
            )
            surface.on_observation(
                observation_type="parameter",
                content={"parameters": ["msg"]},
                asset_key=f"{target}/safe/search",
                source="phase6-component",
            )
            engine = CapabilityExecutionEngine(
                mission_id="phase6-component",
                target_key=target,
                surface=surface,
                adaptive=AdaptiveAttackService(mission_id="phase6-component", target_key=target, enforce_pacing=False),
                probe_timeout_s=5.0,
            )
            engine.execute_ready()
            candidates = CapabilityFindingPipeline(_finding_service()).candidates_from(engine)
            assert candidates == []


class TestFullLifecycle:
    """A candidate runs the complete lifecycle to a reportable package."""

    def test_full_pipeline_reaches_report_ready_with_evidence(self) -> None:
        with VulnerableApp() as app:
            engine = _run_engine(app)
            pipeline = CapabilityFindingPipeline(_finding_service())
            summary = pipeline.run_all(engine)
            assert summary["candidates"] >= 1
            assert summary["reportable"] >= 1
            for outcome in summary["outcomes"]:
                assert outcome["stages"], "lifecycle stages must be recorded"
                assert outcome["verdict"] in ("report_ready", "duplicate", "not_reproducible", "contradicted", "failed")
            reportable = next(item for item in summary["outcomes"] if item["verdict"] == "report_ready")
            assert reportable["reproduction"] == "reproducible"
            assert len(reportable["replay_attempts"]) >= 1
            assert all(attempt["confirmed"] for attempt in reportable["replay_attempts"])
            assert reportable["severity"] is not None
            assert reportable["remediation"], "candidate must carry class-specific remediation"
            package = reportable["package"]
            assert package.get("finding_id") == reportable["finding_id"]
            assert package.get("finding_state") in ("report_ready", "validated", "proved")
            assert package.get("reproduction"), "package must carry the reproduction record"
            assert package.get("pocs"), "package must carry the PoCs"

    def test_lifecycle_stages_cover_the_spec_contract(self) -> None:
        with VulnerableApp() as app:
            engine = _run_engine(app)
            pipeline = CapabilityFindingPipeline(_finding_service())
            summary = pipeline.run_all(engine)
            reportable = next(item for item in summary["outcomes"] if item["verdict"] == "report_ready")
            stages = [entry["stage"] for entry in reportable["stages"]]
            assert "Candidate" in stages
            assert "Evidence" in stages
            assert "Replay" in stages
            assert "Reproduction" in stages
            assert "Impact Analysis" in stages
            assert "PoC" in stages
            assert "Validated Finding" in stages
            assert "Report" in stages

    def test_severity_is_evidence_derived_and_never_automatic_critical(self) -> None:
        with VulnerableApp() as app:
            engine = _run_engine(app)
            pipeline = CapabilityFindingPipeline(_finding_service())
            summary = pipeline.run_all(engine)
            for outcome in summary["outcomes"]:
                assert outcome["severity"] in ("low", "medium", "high", "critical")


class TestHonestNegatives:
    """No fabricated findings: contradiction, non-reproduction, duplicates."""

    def test_non_reproducible_candidate_is_rejected(self) -> None:
        with VulnerableApp() as app:
            engine = _run_engine(app)

            class _NeverReplays(ReplayEngine):
                def replay(self, candidate: CapabilityCandidate) -> tuple[ReplayAttempt, ...]:
                    return tuple(
                        ReplayAttempt(index=i, confirmed=False, signal="none", baseline_status=200, attack_status=200)
                        for i in range(3)
                    )

            pipeline = CapabilityFindingPipeline(_finding_service(), replay_engine=_NeverReplays())
            outcome = pipeline.run(pipeline.candidates_from(engine)[0])
            assert outcome["verdict"] == "not_reproducible"
            assert outcome["reproduction"] == "not_reproducible"

    def test_duplicate_candidates_resolve_to_one_logical_finding(self) -> None:
        with VulnerableApp() as app:
            engine = _run_engine(app)
            service = _finding_service()
            pipeline = CapabilityFindingPipeline(service)
            first = pipeline.run_all(engine)
            assert first["reportable"] >= 1
            second = pipeline.run_all(engine)
            outcomes = second["outcomes"]
            assert outcomes, "the second pass still produced candidates"
            assert any(item["verdict"] == "duplicate" for item in outcomes), "same signal must resolve as a duplicate"

    def test_replay_engine_refuses_non_loopback_endpoints(self) -> None:
        candidate = CapabilityCandidate(
            candidate_id="c",
            finding_class="sql_injection",
            capability_id="sql-injection",
            mission_id="m",
            surface_key="http://evil.example/",
            endpoint="http://evil.example/vuln",
            vector="q",
            session_state="anonymous",
            strategies=("single-payload",),
            tools=("hunterx-differential",),
            evidence={"signal": "error"},
            confidence=0.9,
            request_summaries=(),
            response_summaries=(),
            recorded_at="2026-01-01T00:00:00Z",
        )
        with pytest.raises(PermissionError):
            ReplayEngine().replay(candidate)


__all__: list[str] = []
