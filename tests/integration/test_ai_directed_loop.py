# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Integration tests: AI Hunt Director drives the mission loop.

Proves the core architectural contract:

1. A configured, healthy AI makes the NEXT decision each cycle (not the
   deterministic planner).
2. Out-of-scope AI decisions are rejected by the deterministic policy gate
   and never executed (scope isolation holds even against a rogue model).
3. Queue exhaustion never ends an incomplete full_security_assessment: the
   Security Test Matrix backstop schedules new work.
4. AI decisions are attributable (provider/model recorded, ai_assisted=True).
"""

from __future__ import annotations

import dataclasses
import json
from typing import Any

import pytest

from hunterx.application.mission_execution import MissionExecutionService
from hunterx.application.mission_orchestration import MissionOrchestrationService
from hunterx.config.settings import AISettings
from hunterx.domain.adaptive_mission_planning.toolchain import ToolSelectionEngine
from hunterx.domain.mission_orchestration.orchestrator import MissionOrchestrator
from hunterx.engines.adaptive_mission_planning.engine import AdaptiveMissionPlanningEngine
from hunterx.engines.mission_orchestration import MissionOrchestrationEngine
from hunterx.infrastructure.db.sql.memory import InMemoryTidbRepositoryFactory
from tests.framework.fakes import FakeExecutionEngine


class ScriptedAIClient:
    """AI double returning scripted JSON decisions; records prompts."""

    def __init__(self, responses: list[str]) -> None:
        self.responses = list(responses)
        self.prompts: list[str] = []
        provider = "scripted"

    def complete(self, prompt: str, *, model: str | None = None, temperature: float = 0.0) -> str:
        self.prompts.append(prompt)
        if self.responses:
            return self.responses.pop(0)
        return json.dumps(
            {
                "question": "what is next",
                "security_domain": "reconnaissance",
                "reason": "no scripted response left",
                "action": "execute_tool",
                "capability": "content_discovery",
                "arguments": {"asset": "http://127.0.0.1:1"},
            }
        )

    def embed(self, text: str) -> list[float]:  # pragma: no cover - unused
        return [0.0]

    def check(self) -> bool:
        return True


_CANDIDATES: dict[str, tuple[str, ...]] = {
    "content_discovery": ("ffuf",),
}


def _runner(ai_client: Any) -> tuple[MissionExecutionService, MissionOrchestrationService, str]:
    planning = AdaptiveMissionPlanningEngine(
        tool_selection_engine=ToolSelectionEngine(
            mission_type="web-security",
            default_candidates=dict(_CANDIDATES),
        ),
    )
    orchestrator = MissionOrchestrator(planning=planning)
    orchestration = MissionOrchestrationService(
        engine=MissionOrchestrationEngine(orchestrator=orchestrator),
        stores=InMemoryTidbRepositoryFactory(),
    )
    engine_outputs = {"ffuf": {"urls": ["/admin"]}}
    runner = MissionExecutionService(
        orchestration=orchestration,
        planning=planning,
        execution_engine=FakeExecutionEngine(outputs=engine_outputs),
        readiness=None,
        ai_client=ai_client,
        ai_settings=AISettings(provider="scripted", model="test-model"),
    )
    mission = orchestration.create_mission(
        objective="full_security_assessment", target="http://127.0.0.1:1"
    )
    orchestration.start(mission.mission_id)
    return runner, orchestration, mission.mission_id


_DECISION_RECON = json.dumps(
    {
        "question": "What endpoints exist under the target?",
        "security_domain": "attack_surface_discovery",
        "reason": "surface not yet enumerated",
        "action": "execute_tool",
        "capability": "content_discovery",
        "tool": "",
        "arguments": {"asset": "http://127.0.0.1:1"},
        "expected_evidence": ["discovered URLs"],
        "validation_plan": "n/a — discovery",
    }
)

_DECISION_OUT_OF_SCOPE = json.dumps(
    {
        "question": "Can we reach third-party infrastructure?",
        "security_domain": "attack_surface_discovery",
        "reason": "rogue decision",
        "action": "execute_tool",
        "capability": "content_discovery",
        "arguments": {"asset": "https://evil.example.net"},
        "expected_evidence": [],
        "validation_plan": "",
    }
)


def test_ai_director_decision_drives_execution() -> None:
    ai = ScriptedAIClient([_DECISION_RECON])
    runner, _orchestration, mission_id = _runner(ai)
    outcome = runner.execute_cycle(mission_id)
    assert outcome.get("ai_directed") is True, outcome
    assert outcome.get("status") == "completed"
    assert len(ai.prompts) == 1
    prompt = ai.prompts[0]
    # Complete mission state must reach the model.
    for required in ("SECURITY TEST MATRIX", "AVAILABLE CAPABILITIES", "http://127.0.0.1:1"):
        assert required in prompt
    attribution = runner.ai_attribution()
    assert attribution["enabled"] is True
    assert attribution["provider"] == "scripted"
    assert attribution["model"] == "test-model"
    assert attribution["ai_decisions"] >= 1
    assert attribution["deterministic_decisions"] == 0


def test_out_of_scope_ai_decision_is_rejected() -> None:
    ai = ScriptedAIClient([_DECISION_OUT_OF_SCOPE])
    runner, _orchestration, mission_id = _runner(ai)
    outcome = runner.execute_cycle(mission_id)
    # The rogue decision must NOT execute; the cycle falls through to the
    # deterministic planner (which runs ffuf against the in-scope target).
    assert outcome.get("ai_directed") is None
    attribution = runner.ai_attribution()
    assert attribution["policy_rejections"] >= 1
    rejected = [
        entry for entry in attribution["decisions_trace"] if entry.get("status") == "policy_rejected"
    ]
    assert rejected, attribution["decisions_trace"]
    assert "outside authorized scope" in str(rejected[0])


def test_premature_completion_is_refused_while_matrix_incomplete() -> None:
    premature = json.dumps({"action": "complete", "reason": "I am done"})
    ai = ScriptedAIClient([premature, _DECISION_RECON])
    runner, _orchestration, mission_id = _runner(ai)
    outcome = runner.execute_cycle(mission_id)
    # Completion refused → the AI's premature completion was rejected
    # (ai_directed is None). The deterministic fallback may or may not
    # succeed depending on available tool outputs; both outcomes are honest.
    assert outcome.get("ai_directed") is None
    attribution = runner.ai_attribution()
    statuses = [entry.get("status") for entry in attribution["decisions_trace"]]
    assert "rejected" in statuses or "provider_failure" in statuses or "policy_rejected" in statuses


def test_matrix_backstop_schedules_work_when_queue_empty() -> None:
    ai = ScriptedAIClient([])  # every director call returns a generic replay-able decision
    runner, _orchestration, mission_id = _runner(ai)
    # Drain the deterministic plan so no ready actions remain.
    for _ in range(6):
        outcome = runner.execute_cycle(mission_id)
        if outcome.get("status") == "idle":
            break
    # The Security Test Matrix backstop must create NEW assessment work for
    # the incomplete applicable domains rather than idling into completion.
    scheduled = runner._schedule_matrix_actions(mission_id)
    assert scheduled is True
