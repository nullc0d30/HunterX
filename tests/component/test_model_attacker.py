# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Component tests for the Phase 7 autonomous model-driven attack loop.

The connected model participates in the *real* execution loop: its hypotheses
become real assessment tasks on the attack-surface queue, the ordinary
capability execution engine executes them, results and findings feed back into
the model's reasoning, and a finding never terminates the mission. Honest
negatives: duplicates are rejected, contradicted hypotheses are never re-run,
and a failed model is reported as unavailable — never as exhaustion.
"""

from __future__ import annotations

from typing import Any

from hunterx.application.attack_surface import AttackSurfaceService
from hunterx.application.capability_finding import CapabilityFindingPipeline
from hunterx.application.model_attacker import ModelAttacker
from hunterx.application.vulnerability_finding import VulnerabilityFindingService
from hunterx.domain.model_attacker.reasoner import ModelReasoner
from hunterx.infrastructure.db.graph import InMemoryKnowledgeGraph
from hunterx.infrastructure.db.sql.memory import InMemoryTidbRepositoryFactory
from hunterx.infrastructure.event_bus import InMemoryEventBus
from hunterx.infrastructure.memory import InMemoryFindingRepository
from hunterx.tools.intelligence.api import ToolIntelligenceAPI
from hunterx.tools.sdk.engine import ExecutionEngine
from tests.framework.model_attacker import ScriptedHypothesisModel
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
    surface = AttackSurfaceService(mission_id="phase7-component", target_key=target)
    surface.on_observation(
        observation_type="api",
        content={"endpoints": [f"{target}/vuln/search", f"{target}/vuln/echo"]},
        asset_key=target,
        source="phase7-component",
    )
    return surface


def _script(target: str) -> list[list[dict[str, Any]]]:
    """One hypothesis per round targeting distinct vulnerabilities, then empty."""
    return [
        [
            {
                "capability": "sql-injection",
                "surface": f"{target}/vuln/search",
                "attack_vector": "q",
                "attack_strategy": "error-based",
                "expected_signal": "error_based",
                "priority": 0.9,
                "confidence": 0.8,
                "reasoning_context": "search reflects SQL errors",
            }
        ],
        [
            {
                "capability": "xss",
                "surface": f"{target}/vuln/echo",
                "attack_vector": "msg",
                "attack_strategy": "reflection",
                "expected_signal": "reflected",
                "priority": 0.8,
                "confidence": 0.7,
                "reasoning_context": "echo reflects input unescaped",
            }
        ],
        [
            {
                "capability": "ssti",
                "surface": f"{target}/vuln/search",
                "attack_vector": "q",
                "attack_strategy": "reflection",
                "expected_signal": "reflected",
                "priority": 0.7,
                "confidence": 0.6,
                "reasoning_context": "search may render templates",
            }
        ],
        [],
    ]


class TestClosedLoop:
    """The model drives the real loop to multiple findings and exhaustion."""

    def test_model_loop_reaches_multiple_findings_then_exhaustion(self) -> None:
        with VulnerableApp() as app:
            surface = _surface(app.base_url)
            model = ScriptedHypothesisModel(_script(app.base_url))
            attacker = ModelAttacker(ModelReasoner(model), finding_pipeline=CapabilityFindingPipeline(_finding_service()))
            attacker.bind(surface, mission_id="phase7-component")
            result = attacker.run(max_rounds=10)
            telemetry = result["telemetry"]
            assert telemetry["model_calls"] >= 3
            assert telemetry["hypotheses_accepted"] >= 2
            assert telemetry["validated_findings"] >= 3, "multiple findings must be validated"
            assert telemetry["post_finding_model_calls"] > 0, "the model must keep reasoning after a finding"
            assert telemetry["finding_events"] > 0
            assert telemetry["model_generated_tasks"] >= 1
            assert telemetry["model_task_execution_count"] >= 1
            assert telemetry["model_feedback_events"] >= 1
            assert result["completion_reason"] == "exhausted"
            assert result["exhaustion"]["exhausted"] is True

    def test_telemetry_invariant_validated_findings_and_post_finding_calls(self) -> None:
        with VulnerableApp() as app:
            surface = _surface(app.base_url)
            model = ScriptedHypothesisModel(_script(app.base_url))
            attacker = ModelAttacker(ModelReasoner(model), finding_pipeline=CapabilityFindingPipeline(_finding_service()))
            attacker.bind(surface, mission_id="phase7-component")
            attacker.run(max_rounds=10)
            telemetry = attacker.telemetry()
            assert telemetry["validated_findings"] > 0
            assert telemetry["post_finding_model_calls"] > 0

    def test_hypotheses_become_real_queued_tasks(self) -> None:
        with VulnerableApp() as app:
            surface = _surface(app.base_url)
            model = ScriptedHypothesisModel(_script(app.base_url))
            attacker = ModelAttacker(ModelReasoner(model), finding_pipeline=CapabilityFindingPipeline(_finding_service()))
            attacker.bind(surface, mission_id="phase7-component")
            attacker.run(max_rounds=10)
            assert attacker.report()["plans"], "every accepted hypothesis must produce an attack plan"
            assert any(plan["task_id"] for plan in attacker.report()["plans"]), "plans must reference real queue tasks"

    def test_observations_feed_back_to_the_model(self) -> None:
        with VulnerableApp() as app:
            surface = _surface(app.base_url)
            model = ScriptedHypothesisModel(_script(app.base_url))
            attacker = ModelAttacker(ModelReasoner(model), finding_pipeline=CapabilityFindingPipeline(_finding_service()))
            attacker.bind(surface, mission_id="phase7-component")
            attacker.run(max_rounds=10)
            observations = attacker.report()["learning"]["observations"]
            assert observations, "attack results must return to the model context"
            assert any(item.get("supported") for item in observations), "supported observations must be recorded"
            assert model.prompts, "the model must be invoked with the loop context"

    def test_attack_chaining_from_findings(self) -> None:
        with VulnerableApp() as app:
            surface = _surface(app.base_url)
            model = ScriptedHypothesisModel(_script(app.base_url))
            attacker = ModelAttacker(ModelReasoner(model), finding_pipeline=CapabilityFindingPipeline(_finding_service()))
            attacker.bind(surface, mission_id="phase7-component")
            attacker.run(max_rounds=10)
            learning = attacker.report()["learning"]
            assert learning["validated_findings"], "validated findings must feed the learning context"
            assert learning["adjacent_paths"], "findings must expand into adjacent attack paths"
            discovered = [f"{app.base_url}/vuln/search", f"{app.base_url}/vuln/echo"]
            assert all(
                item["surface"] in discovered for item in learning["adjacent_paths"]
            ), "adjacent paths must reference discovered surfaces"
            assert all(item["attack_vector"] for item in learning["adjacent_paths"]), "adjacent paths must carry vectors"


class TestHonestNegatives:
    """Duplicates, contradictions and model failure are handled explicitly."""

    def test_duplicate_hypothesis_is_rejected_not_rerun(self) -> None:
        with VulnerableApp() as app:
            surface = _surface(app.base_url)
            target = app.base_url
            script = [
                [{"capability": "sql-injection", "surface": f"{target}/vuln/search", "attack_vector": "q", "attack_strategy": "error-based"}],
                [{"capability": "sql-injection", "surface": f"{target}/vuln/search", "attack_vector": "q", "attack_strategy": "error-based"}],
                [],
            ]
            model = ScriptedHypothesisModel(script)
            attacker = ModelAttacker(ModelReasoner(model), finding_pipeline=CapabilityFindingPipeline(_finding_service()))
            attacker.bind(surface, mission_id="phase7-component")
            result = attacker.run(max_rounds=6)
            telemetry = result["telemetry"]
            assert telemetry["hypotheses_generated"] == 2
            assert telemetry["hypotheses_rejected"] >= 1, "the repeated hypothesis must be rejected as a duplicate"

    def test_contradicted_hypothesis_is_never_rerun(self) -> None:
        with VulnerableApp() as app:
            target = app.base_url
            surface = AttackSurfaceService(mission_id="phase7-component", target_key=target)
            surface.on_observation(
                observation_type="api",
                content={"endpoints": [f"{target}/safe/search"]},
                asset_key=target,
                source="phase7-component",
            )
            script = [
                [{"capability": "sql-injection", "surface": f"{target}/safe/search", "attack_vector": "msg", "attack_strategy": "error-based"}],
                [{"capability": "sql-injection", "surface": f"{target}/safe/search", "attack_vector": "msg", "attack_strategy": "error-based"}],
                [],
            ]
            model = ScriptedHypothesisModel(script)
            attacker = ModelAttacker(ModelReasoner(model), finding_pipeline=CapabilityFindingPipeline(_finding_service()))
            attacker.bind(surface, mission_id="phase7-component")
            result = attacker.run(max_rounds=6)
            telemetry = result["telemetry"]
            assert telemetry["validated_findings"] == 0, "a safe surface must never validate a finding"
            assert telemetry["hypotheses_rejected"] >= 1, "the contradicted hypothesis must be rejected, never re-run"
            disproven = attacker.report()["learning"]["disproven_hypotheses"]
            assert disproven, "the contradiction must feed back into the learning context"

    def test_model_failure_is_reported_not_exhaustion(self) -> None:
        with VulnerableApp() as app:
            surface = _surface(app.base_url)
            model = ScriptedHypothesisModel([[]], fail_after=1)
            attacker = ModelAttacker(ModelReasoner(model), finding_pipeline=CapabilityFindingPipeline(_finding_service()))
            attacker.bind(surface, mission_id="phase7-component")
            step = attacker.step()
            assert step["status"] == "model_unavailable"
            assert attacker.exhausted() is False, "a failed model must never be treated as exhaustion"
            assert attacker.completion_reason() == "model_unavailable"

    def test_empty_model_concludes_genuine_exhaustion(self) -> None:
        with VulnerableApp() as app:
            surface = _surface(app.base_url)
            model = ScriptedHypothesisModel([[]])
            attacker = ModelAttacker(ModelReasoner(model), finding_pipeline=CapabilityFindingPipeline(_finding_service()))
            attacker.bind(surface, mission_id="phase7-component")
            result = attacker.run(max_rounds=4)
            assert result["completion_reason"] == "exhausted"
            assert result["telemetry"]["model_calls"] == 1


class TestMissionIntegration:
    """The attacker is wired into the real mission loop; findings do not stop it."""

    def _runner(self, surface: AttackSurfaceService, model: Any, mission_id: str):
        from hunterx.application.mission_execution import MissionExecutionService
        from hunterx.application.mission_orchestration import MissionOrchestrationService
        from hunterx.domain.adaptive_mission_planning.toolchain import ToolSelectionEngine
        from hunterx.domain.mission_orchestration.orchestrator import MissionOrchestrator
        from hunterx.engines.adaptive_mission_planning.engine import AdaptiveMissionPlanningEngine
        from hunterx.engines.mission_orchestration import MissionOrchestrationEngine
        from tests.framework.fakes import FakeExecutionEngine

        planning = AdaptiveMissionPlanningEngine(
            tool_selection_engine=ToolSelectionEngine(
                mission_type="bug-bounty",
                default_candidates={
                    "subdomain_enumeration": ("subfinder",),
                    "dns_enumeration": ("dnsx",),
                    "port_discovery": ("nmap",),
                    "service_detection": ("nmap",),
                    "technology_fingerprint": ("whatweb",),
                },
            ),
        )
        orchestrator = MissionOrchestrator(planning=planning)
        orchestration = MissionOrchestrationService(
            engine=MissionOrchestrationEngine(orchestrator=orchestrator),
            stores=InMemoryTidbRepositoryFactory(),
        )
        finding_service = _finding_service()
        attacker = ModelAttacker(ModelReasoner(model), finding_pipeline=CapabilityFindingPipeline(finding_service))
        runner = MissionExecutionService(
            orchestration=orchestration,
            planning=planning,
            execution_engine=FakeExecutionEngine(
                outputs={
                    "subfinder": {"discoveries": [{"kind": "subdomain", "name": "api.target"}]},
                    "dnsx": {"records": ["api.target -> 1.2.3.4"]},
                    "nmap": {"ports": [80, 443]},
                    "whatweb": {"name": "express", "technologies": ["node.js", "express"]},
                }
            ),
            finding_service=finding_service,
            attack_surface=surface,
            model_attacker=attacker,
        )
        mission = orchestration.create_mission(objective="full_security_assessment", target=surface.target_key)
        orchestration.start(mission.mission_id)
        return runner, mission.mission_id

    def test_mission_loop_continues_after_finding_and_reaches_attacker_exhaustion(self) -> None:
        with VulnerableApp() as app:
            surface = _surface(app.base_url)
            model = ScriptedHypothesisModel(_script(app.base_url))
            runner, mission_id = self._runner(surface, model, "phase7-mission")
            result = runner.run(mission_id, max_cycles=14)
            assert "model_attacker" in result, "the run must expose the model attacker report"
            attacker_report = result["model_attacker"]
            telemetry = attacker_report["telemetry"]
            assert telemetry["validated_findings"] >= 3, "the mission must validate multiple findings"
            assert telemetry["post_finding_model_calls"] > 0, "the mission must continue reasoning after a finding"
            assert telemetry["model_task_execution_count"] >= 1, "model hypotheses must become real executed tasks"
            # The mission never terminates on the first finding: multiple model
            # rounds ran after findings were validated.
            model_calls_after_first = telemetry["model_calls"] - 1
            assert telemetry["finding_events"] >= 1 and model_calls_after_first >= 1


__all__: list[str] = []
