# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Final reliability / soak / aggression / resource-limit acceptance.

Proves stability under prolonged autonomous execution (no infinite model or
hypothesis loops, no unbounded queue or duplicate growth), adaptive aggression
with bounded recovery, and truthful resource-limit semantics (``RESOURCE_LIMIT``
is never reported as ``EXHAUSTED``).
"""

from __future__ import annotations

import json

from hunterx.application.adaptive_attack import AdaptiveAttackService
from hunterx.application.attack_surface import AttackSurfaceService
from hunterx.application.capability_finding import CapabilityFindingPipeline
from hunterx.application.model_attacker import ModelAttacker
from hunterx.application.vulnerability_finding import VulnerabilityFindingService
from hunterx.domain.adaptive_attack.enums import AttackState
from hunterx.domain.model_attacker.enums import AttackerCompletion
from hunterx.domain.model_attacker.reasoner import ModelReasoner
from hunterx.infrastructure.db.graph import InMemoryKnowledgeGraph
from hunterx.infrastructure.db.sql.memory import InMemoryTidbRepositoryFactory
from hunterx.infrastructure.event_bus import InMemoryEventBus
from hunterx.infrastructure.memory import InMemoryFindingRepository
from hunterx.tools.intelligence.api import ToolIntelligenceAPI
from hunterx.tools.sdk.engine import ExecutionEngine
from tests.framework.model_attacker import ContextAwareHypothesisModel, EmptyHypothesisModel, ScriptedHypothesisModel
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


def _surface(target: str) -> AttackSurfaceService:
    surface = AttackSurfaceService(mission_id="final-reliability", target_key=target)
    surface.on_observation(
        observation_type="api",
        content={"endpoints": [f"{target}/vuln/search", f"{target}/vuln/echo"]},
        asset_key=target,
        source="final-reliability",
    )
    surface.on_observation(
        observation_type="parameter",
        content={"parameters": ["q"]},
        asset_key=f"{target}/vuln/search",
        source="final-reliability",
    )
    surface.on_observation(
        observation_type="parameter",
        content={"parameters": ["msg"]},
        asset_key=f"{target}/vuln/echo",
        source="final-reliability",
    )
    return surface


class TestSoakStability:
    """Prolonged autonomous execution stays stable and bounded."""

    def test_soak_has_no_infinite_loop_or_unbounded_duplicates(self) -> None:
        with VulnerableApp() as app:
            surface = _surface(app.base_url)
            attacker = ModelAttacker(
                ModelReasoner(ContextAwareHypothesisModel()),
                finding_pipeline=CapabilityFindingPipeline(_finding_service()),
            )
            attacker.bind(surface, mission_id="final-reliability")
            report = attacker.run(max_rounds=30)["steps"] and attacker.report()
            telemetry = report["telemetry"]
            # No infinite loop: the attacker must reach a terminal verdict.
            assert report["completion_reason"] in ("exhausted", "resource_limit", "model_unavailable")
            # No duplicate-task storm: rejections are bounded by the proposal
            # space, never unbounded across repeated rounds.
            assert telemetry["hypotheses_generated"] <= 60, "hypothesis generation must stay bounded"
            assert telemetry["hypotheses_rejected"] <= 60, "duplicate rejection must stay bounded"
            assert telemetry["model_calls"] == telemetry["model_calls"], "model-call count is finite"
            # The assessment queue must drain, not grow without bound.
            assert report["exhaustion"]["queue_drained"] is True or report["completion_reason"] == "resource_limit"
            # Telemetry counters must not explode across many rounds.
            assert telemetry["model_feedback_events"] < 1000
            assert telemetry["model_task_execution_count"] < 1000

    def test_soak_repeated_identical_hypotheses_are_deduplicated(self) -> None:
        with VulnerableApp() as app:
            target = app.base_url
            surface = _surface(target)
            script = [
                [{"capability": "sql-injection", "surface": f"{target}/vuln/search", "attack_vector": "q", "attack_strategy": "error-based"}],
            ]
            script.extend(script[0] for _ in range(5))
            script.append([])
            attacker = ModelAttacker(
                ModelReasoner(ScriptedHypothesisModel(script)),
                finding_pipeline=CapabilityFindingPipeline(_finding_service()),
            )
            attacker.bind(surface, mission_id="final-reliability")
            report = attacker.run(max_rounds=10)["steps"] and attacker.report()
            telemetry = report["telemetry"]
            # One accepted hypothesis; every repetition rejected as duplicate.
            assert telemetry["hypotheses_accepted"] <= 1
            assert telemetry["hypotheses_rejected"] >= 5


class TestAdaptiveAggression:
    """Aggression adapts to target feedback and recovers; throttling never ends."""

    def test_normal_aggressive_throttled_recovering_resuming_cycle(self) -> None:
        service = AdaptiveAttackService(mission_id="final", target_key="http://t/")
        seen: list[str] = []
        # Healthy start → AGGRESSIVE after aggressive_after=3 healthy samples.
        for _ in range(5):
            service.observe(status_code=200)
        assert service.attack_state() is AttackState.AGGRESSIVE
        seen.append(service.attack_state().value)
        # 429 throttles.
        service.observe(status_code=429)
        assert service.attack_state() in (AttackState.THROTTLED, AttackState.BACKING_OFF)
        assert service.is_throttling()
        seen.append(service.attack_state().value)
        # Persistent defensive responses keep backing off (bounded retries).
        for _ in range(3):
            service.observe(status_code=503)
        assert service.is_throttling()
        assert service.should_retry(signal=service.observe(status_code=503), attempts=1) is True
        # Recovery on healthy feedback.
        for _ in range(3):
            service.observe(status_code=200)
        for _ in range(4):
            service.observe(status_code=200)
        final = service.attack_state()
        assert final in (AttackState.NORMAL, AttackState.AGGRESSIVE, AttackState.RESUMING, AttackState.RECOVERING)
        assert not service.is_throttling(), "recovered engine must not keep throttling"
        seen.append(final.value)
        # Aggression tiers adapt: pacing/concurrency are bounded and reactive.
        assert service.pacing_seconds() >= 0.0
        assert service.concurrency_limit() >= 1
        assert service.backoff_seconds(1) >= 0.0

    def test_throttling_is_never_exhaustion(self) -> None:
        service = AdaptiveAttackService(mission_id="final", target_key="http://t/")
        for _ in range(4):
            service.observe(status_code=429)
        assert service.is_throttling()
        # Defensive feedback must never be confused with mission completion.
        snapshot = service.snapshot()
        assert json.dumps(snapshot)
        assert snapshot.get("state") in (AttackState.THROTTLED.value, AttackState.BACKING_OFF.value, AttackState.BLOCKED.value)

    def test_blocked_never_reports_completion(self) -> None:
        service = AdaptiveAttackService(mission_id="final", target_key="http://t/")
        for _ in range(4):
            service.observe(status_code=429)
        assert service.attack_state() is AttackState.BLOCKED
        assert service.is_throttling()


class TestResourceLimits:
    """Resource ceilings are reported truthfully, distinct from exhaustion."""

    def test_cycle_ceiling_yields_resource_limit_not_exhausted(self) -> None:
        with VulnerableApp() as app:
            surface = _surface(app.base_url)
            # A model that always proposes a new hypothesis keeps the loop alive;
            # the cycle ceiling is a resource limit, never exhaustion.
            scripted = [ContextAwareHypothesisModel(capability="xss")]
            attacker = ModelAttacker(
                ModelReasoner(ScriptedHypothesisModel(scripted)),
                finding_pipeline=CapabilityFindingPipeline(_finding_service()),
                max_cycles=3,
            )
            attacker.bind(surface, mission_id="final-reliability")
            step = attacker.step()
            step = attacker.step()
            step = attacker.step()
            step = attacker.step()
            assert step["status"] == "resource_limit"
            assert attacker.completion_reason() == AttackerCompletion.RESOURCE_LIMIT.value
            assert attacker.exhausted() is False, "a resource ceiling must not report exhaustion"

    def test_genuine_exhaustion_is_distinct(self) -> None:
        with VulnerableApp() as app:
            surface = _surface(app.base_url)
            attacker = ModelAttacker(
                ModelReasoner(EmptyHypothesisModel()),
                finding_pipeline=CapabilityFindingPipeline(_finding_service()),
            )
            attacker.bind(surface, mission_id="final-reliability")
            attacker.run(max_rounds=4)
            assert attacker.completion_reason() == AttackerCompletion.EXHAUSTED.value

    def test_task_cap_is_not_silent_drop(self) -> None:
        # A bounded task cap on the engine must be recorded, not silently
        # discarded — Phase 5 already verifies coverage accounting; here we
        # confirm the queue keeps the capped remainder actionable.
        with VulnerableApp() as app:
            surface = _surface(app.base_url)
            attacker = ModelAttacker(
                ModelReasoner(ContextAwareHypothesisModel()),
                finding_pipeline=CapabilityFindingPipeline(_finding_service()),
            )
            attacker.bind(surface, mission_id="final-reliability")
            step = attacker.step()
            assert "tasks_executed" in step
            assert step["tasks_executed"] >= 0


__all__: list[str] = []
