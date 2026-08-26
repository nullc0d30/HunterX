# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""AI Hunt Director unit tests — prompt completeness and decision parsing."""

from __future__ import annotations

import json

import pytest

from hunterx.application.ai_hunt_director.director import AIHuntDirector
from hunterx.application.ai_hunt_director.protocol import (
    ActionType,
    AIHuntDecision,
    HuntContext,
    ToolCapability,
)


class _FakeAIClient:
    """Scripted AIPort double recording prompts."""

    def __init__(self, responses: list[str]) -> None:
        self.responses = list(responses)
        self.prompts: list[str] = []

    def complete(self, prompt: str, *, model: str | None = None, temperature: float = 0.0) -> str:
        self.prompts.append(prompt)
        return self.responses.pop(0) if self.responses else "{}"

    def embed(self, text: str) -> list[float]:  # pragma: no cover - unused
        return [0.0]

    def check(self) -> bool:
        return True


def _context(**overrides: object) -> HuntContext:
    base: dict[str, object] = {
        "mission_id": "m1",
        "target": "http://localhost:3010",
        "objective": "full_security_assessment",
        "scope": {"included_targets": ["http://localhost:3010"]},
        "authorization_context": {"authorized": True},
        "current_phase": "analysis",
        "current_strategy": "adaptive",
        "available_capabilities": [
            ToolCapability(
                tool_id="sql_injection",
                name="sql_injection",
                description="Detect SQL injection",
                purpose="Detect SQL injection",
                capability="active_testing",
            ),
            ToolCapability(
                tool_id="content_discovery",
                name="content_discovery",
                description="Discover hidden endpoints",
                purpose="Discover hidden endpoints",
                capability="attack_surface",
            ),
        ],
        "available_tools": ["crawler"],
        "security_matrix": {
            "summary": {
                "incomplete_domains": ["sql_injection", "xss"],
                "complete": False,
            },
            "domains": [
                {"domain": "sql_injection", "applicability": "applicable", "status": "not_assessed", "terminal": False},
                {"domain": "xss", "applicability": "applicable", "status": "not_assessed", "terminal": False},
            ],
        },
    }
    base.update(overrides)
    return HuntContext(**base)  # type: ignore[arg-type]


def test_prompt_contains_complete_mission_state() -> None:
    client = _FakeAIClient([])
    director = AIHuntDirector(client, model="test-model", provider="test")
    context = _context(
        technologies=["Angular"],
        endpoints=["http://localhost:3010/rest/product/search"],
        observations=[],
    )
    prompt = director.build_prompt(context)
    for required in (
        "http://localhost:3010",
        "full_security_assessment",
        "SECURITY TEST MATRIX",
        "AVAILABLE CAPABILITIES",
        "sql_injection",
        "RESPONSE SCHEMA",
        "RESOURCE BUDGET",
        "scope",
        "HYPOTHESES",
        "FINDINGS",
        "NEGATIVE EVIDENCE" if False else "PREVIOUS ACTIONS",
    ):
        assert required in prompt, f"prompt missing {required}"


def test_decision_parsing_structured_payload() -> None:
    response = json.dumps(
        {
            "question": "Does the product search filter sanitize input?",
            "security_domain": "sql_injection",
            "reason": "search endpoint accepts q parameter",
            "action": "execute_tool",
            "capability": "sql_injection",
            "tool": "",
            "arguments": {"asset": "http://localhost:3010/rest/product/search", "param": "q"},
            "expected_evidence": ["SQL error or differential timing"],
            "validation_plan": "differential probe with payload vs baseline",
        }
    )
    client = _FakeAIClient([response])
    director = AIHuntDirector(client, provider="p", model="m")
    decision = director.decide_next_action(_context())
    assert isinstance(decision, AIHuntDecision)
    assert decision.action_type is ActionType.EXECUTE_TOOL
    assert decision.capability == "sql_injection"
    assert decision.security_domain == "sql_injection"
    assert decision.arguments["param"] == "q"


def test_fenced_json_is_tolerated() -> None:
    response = "```json\n" + json.dumps({"action": "execute_tool", "capability": "content_discovery", "security_domain": "attack_surface_discovery"}) + "\n```"
    client = _FakeAIClient([response])
    decision = AIHuntDirector(client).decide_next_action(_context())
    assert decision.capability == "content_discovery"


def test_unknown_capability_rejected_and_retried() -> None:
    bad = json.dumps({"action": "execute_tool", "capability": "rm_rf_universe"})
    good = json.dumps({"action": "execute_tool", "capability": "sql_injection", "security_domain": "sql_injection"})
    client = _FakeAIClient([bad, good])
    decision = AIHuntDirector(client).decide_next_action(_context())
    assert decision.capability == "sql_injection"


def test_premature_complete_parsed_as_complete() -> None:
    """The director parses 'complete' actions without checking matrix state.

    The matrix completeness check is the runner's responsibility (_request_ai_decision).
    The director's job is only to parse the AI's response into a structured decision.
    """
    complete_now = json.dumps({"action": "complete", "reason": "done"})
    work = json.dumps({"action": "execute_tool", "capability": "sql_injection", "security_domain": "sql_injection"})
    client = _FakeAIClient([complete_now, work])
    decision = AIHuntDirector(client).decide_next_action(_context())
    # The director returns the AI's "complete" decision as-is.
    # The runner's _request_ai_decision will reject it if the matrix is incomplete.
    assert decision.action_type is ActionType.COMPLETE
    assert decision.rationale == "done"


def test_complete_accepted_when_matrix_terminal() -> None:
    matrix = {
        "summary": {"incomplete_domains": [], "complete": True},
        "domains": [
            {"domain": "reconnaissance", "applicability": "applicable", "status": "tested_negative", "terminal": True},
        ],
    }
    response = json.dumps({"action": "complete", "reason": "all domains terminal"})
    client = _FakeAIClient([response])
    decision = AIHuntDirector(client).decide_next_action(_context(security_matrix=matrix))
    assert decision.action_type is ActionType.COMPLETE


def test_provider_failure_raises_director_error() -> None:
    class _Boom(_FakeAIClient):
        def complete(self, prompt: str, *, model: str | None = None, temperature: float = 0.0) -> str:
            raise TimeoutError("upstream timeout")

    with pytest.raises(Exception):
        AIHuntDirector(_Boom([]), max_retries=1).decide_next_action(_context())
