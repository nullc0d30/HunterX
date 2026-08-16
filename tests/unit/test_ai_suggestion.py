# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for the advisory AI action-suggestion producer.

Covers the AI suggestion contract:

- a valid AI response is parsed and validated against the candidate set;
- a suggestion not in the candidate set is rejected;
- malformed / non-JSON / empty AI responses fall back to "no suggestion";
- AI client unavailability never raises and yields a deterministic fallback;
- the prompt is constrained (no secrets, candidate ids only).
"""

from __future__ import annotations

import json

from hunterx.application.ai_suggestion import AIActionSuggester
from tests.framework.fakes import FakeAIClient


class _Candidate:
    def __init__(self, action_id: str, capability: str = "recon", description: str = "d", tool_ids=("nmap",)) -> None:
        self.action_id = action_id
        self.capability = capability
        self.description = description
        self.tool_ids = tool_ids


class _Mission:
    """Minimal mission double exposing the context the prompt builder reads."""

    def __init__(self) -> None:
        self.mission_id = "M1"
        self.mission = _Obj(objective="full_security_assessment", mode="balanced")
        self.policy = _Obj(strategy="adaptive")
        self.context = _Obj(
            target_id="http://localhost:3010",
            current_phase="target_modeling",
            assets={"a": 1},
            technologies={},
            services={},
            endpoints={},
            observations=[],
            decisions=[],
            tool_executions=[],
        )


class _Obj:
    def __init__(self, **kw: object) -> None:
        for key, value in kw.items():
            setattr(self, key, value)


def _candidates() -> list[_Candidate]:
    return [
        _Candidate("act-port", capability="port_discovery"),
        _Candidate("act-tech", capability="technology_fingerprint"),
    ]


class TestValidSuggestion:
    def test_valid_suggestion_is_parsed_and_validated(self) -> None:
        payload = json.dumps({"suggested_action_id": "act-port", "reason": "open ports first"})
        ai = FakeAIClient(response=payload)
        suggester = AIActionSuggester(ai)
        suggestion = suggester.suggest(_Mission(), _candidates())
        assert suggestion.usable
        assert suggestion.action_id == "act-port"
        assert suggestion.reason == "open ports first"
        assert suggestion.invoked
        assert ai.prompts, "the AI client must be invoked"
        assert "act-port" in ai.prompts[0] and "act-tech" in ai.prompts[0], "candidates must be in the prompt"
        assert "http://localhost:3010" in ai.prompts[0]

    def test_fenced_json_is_parsed(self) -> None:
        ai = FakeAIClient(response='```json\n{"suggested_action_id": "act-tech", "reason": "tech first"}\n```')
        suggestion = AIActionSuggester(ai).suggest(_Mission(), _candidates())
        assert suggestion.action_id == "act-tech"

    def test_trailing_prose_after_json_is_ignored(self) -> None:
        ai = FakeAIClient(response='{"suggested_action_id": "act-port", "reason": "ok"}\nSome prose.')
        suggestion = AIActionSuggester(ai).suggest(_Mission(), _candidates())
        assert suggestion.action_id == "act-port"


class TestInvalidSuggestion:
    def test_out_of_candidate_suggestion_is_rejected(self) -> None:
        ai = FakeAIClient(response='{"suggested_action_id": "act-evil", "reason": "do this"}')
        suggestion = AIActionSuggester(ai).suggest(_Mission(), _candidates())
        assert not suggestion.usable
        assert suggestion.action_id == ""
        assert "not an available candidate" in suggestion.error
        assert suggestion.invoked

    def test_malformed_json_falls_back(self) -> None:
        ai = FakeAIClient(response="not json at all")
        suggestion = AIActionSuggester(ai).suggest(_Mission(), _candidates())
        assert not suggestion.usable
        assert suggestion.error

    def test_empty_response_falls_back(self) -> None:
        ai = FakeAIClient(response="")
        suggestion = AIActionSuggester(ai).suggest(_Mission(), _candidates())
        assert not suggestion.usable
        assert "empty" in suggestion.error

    def test_missing_action_id_falls_back(self) -> None:
        ai = FakeAIClient(response='{"reason": "no id"}')
        suggestion = AIActionSuggester(ai).suggest(_Mission(), _candidates())
        assert not suggestion.usable
        assert "suggested_action_id" in suggestion.error


class TestUnavailableAI:
    def test_no_client_returns_no_suggestion(self) -> None:
        suggestion = AIActionSuggester(None).suggest(_Mission(), _candidates())
        assert not suggestion.usable
        assert not suggestion.invoked
        assert "unavailable" in suggestion.error

    def test_client_failure_never_raises(self) -> None:
        class BrokenAI:
            def complete(self, prompt, *, model=None, temperature=0.0):  # noqa: ANN001
                raise RuntimeError("provider down")

            def embed(self, text):  # noqa: ANN001
                return []

        suggestion = AIActionSuggester(BrokenAI()).suggest(_Mission(), _candidates())
        assert not suggestion.usable
        assert suggestion.invoked
        assert "failed" in suggestion.error


class TestNoCandidates:
    def test_no_candidates_returns_no_suggestion(self) -> None:
        ai = FakeAIClient(response='{"suggested_action_id": "act-port", "reason": "ok"}')
        suggestion = AIActionSuggester(ai).suggest(_Mission(), [])
        assert not suggestion.usable
        assert not suggestion.invoked
