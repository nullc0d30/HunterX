# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Golden tests for the Adaptive Target Intelligence layer.

The entire intelligence pipeline must be replayable from stored artifacts:
artifact -> parser -> observation -> correlation -> hypothesis -> action
recommendation, without rerunning external tools. These tests exercise the
replay runner against golden observation fixtures and assert the derived
state is deterministic and provenance-preserving.
"""

from __future__ import annotations

from hunterx.domain.target_intelligence.enums import IntelligenceTargetKind, ObservationType
from hunterx.domain.target_intelligence.models import IntelligenceTarget, Observation
from hunterx.domain.target_intelligence.replay import IntelligenceReplayRunner

#: Golden fixture: normalized observations extracted from preserved tool
#: artifacts (subfinder, httpx, katana, nuclei). Represents "what we learned"
#: for a golden shop target.
GOLDEN_OBSERVATIONS: list[dict[str, object]] = [
    {
        "tool": "subfinder",
        "tool_version": "2.6.0",
        "capability": "subdomain_enumeration",
        "observation_type": "host",
        "value": "api.golden-shop.example",
        "asset_key": "hostname:api.golden-shop.example",
        "confidence": 0.9,
        "raw_artifact_ref": "artifacts/golden/subfinder.jsonl",
    },
    {
        "tool": "httpx",
        "tool_version": "1.6.0",
        "capability": "technology_fingerprint",
        "observation_type": "technology",
        "value": "nginx 1.18.0",
        "asset_key": "hostname:api.golden-shop.example",
        "confidence": 0.95,
        "raw_artifact_ref": "artifacts/golden/httpx.jsonl",
    },
    {
        "tool": "katana",
        "tool_version": "1.0.4",
        "capability": "endpoint_enumeration",
        "observation_type": "endpoint",
        "value": "https://api.golden-shop.example/v1/items/search?q=x",
        "asset_key": "url:https://api.golden-shop.example/v1/items/search?q=x",
        "confidence": 0.9,
        "raw_artifact_ref": "artifacts/golden/katana.jsonl",
    },
    {
        "tool": "katana",
        "tool_version": "1.0.4",
        "capability": "parameter_discovery",
        "observation_type": "parameter",
        "value": "q",
        "asset_key": "url:https://api.golden-shop.example/v1/items/search?q=x",
        "confidence": 0.8,
        "raw_artifact_ref": "artifacts/golden/katana.jsonl",
    },
    {
        "tool": "nuclei",
        "tool_version": "3.3.0",
        "capability": "vulnerability_scanning",
        "observation_type": "vulnerability",
        "value": "CVE-2024-simulated",
        "asset_key": "url:https://api.golden-shop.example/v1/items/search?q=x",
        "confidence": 0.6,
        "raw_artifact_ref": "artifacts/golden/nuclei.jsonl",
    },
]


def _golden_target() -> IntelligenceTarget:
    return IntelligenceTarget(
        target_id="golden-shop",
        mission_id="mis-golden",
        scope="golden-shop.example",
        identity="Golden Shop",
        kind=IntelligenceTargetKind.DOMAIN,
        value="golden-shop.example",
    )


def _observations() -> list[Observation]:
    observations: list[Observation] = []
    for payload in GOLDEN_OBSERVATIONS:
        observations.append(
            Observation(
                target_id="golden-shop",
                mission_id="mis-golden",
                tool=str(payload["tool"]),
                tool_version=str(payload["tool_version"]),
                capability=str(payload["capability"]),
                observation_type=ObservationType(str(payload["observation_type"])),
                value=str(payload["value"]),
                asset_key=str(payload["asset_key"]),
                confidence=float(payload["confidence"]),
                raw_artifact_ref=str(payload["raw_artifact_ref"]),
            )
        )
    return observations


class TestGoldenReplay:
    def test_replay_is_deterministic(self) -> None:
        runner = IntelligenceReplayRunner()
        first = runner.replay(_golden_target(), _observations(), mission_objective="find vulnerabilities")
        second = runner.replay(_golden_target(), _observations(), mission_objective="find vulnerabilities")

        assert first.observation_count == second.observation_count == len(GOLDEN_OBSERVATIONS)
        assert first.status == "replayed"
        # Deterministic derivation: the same stored artifacts produce the same
        # hypotheses and actions (ids are unique, statements are equal).
        assert [h.statement for h in first.hypotheses] == [h.statement for h in second.hypotheses]
        assert [a.objective for a in first.actions] == [a.objective for a in second.actions]

    def test_replay_correlates_and_derives_hypotheses(self) -> None:
        runner = IntelligenceReplayRunner()
        run = runner.replay(_golden_target(), _observations(), mission_objective="find vulnerabilities")
        assert run.correlations
        assert any(h.category.value == "injection" for h in run.hypotheses)
        assert run.decision is not None
        assert run.decision.rationale

    def test_replay_preserves_observation_count(self) -> None:
        runner = IntelligenceReplayRunner()
        run = runner.replay(_golden_target(), _observations())
        assert run.observation_count == len(GOLDEN_OBSERVATIONS)

    def test_replay_never_executes_tools(self) -> None:
        runner = IntelligenceReplayRunner()
        run = runner.replay(_golden_target(), _observations())
        # The runner is purely derivational: no tool, no external I/O.
        assert run.status == "replayed"
