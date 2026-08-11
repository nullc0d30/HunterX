# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Golden tests for Autonomous Mission Orchestration.

Replays the scripted mission fixtures under ``tests/golden/missions/`` through
the orchestrator and verifies deterministic behavior: identical scripts produce
identical decisions, and the final outcome matches the fixture's expectations.
"""

from __future__ import annotations

import json
import pathlib

import pytest

from hunterx.domain.mission_orchestration.baseline import TestResponse
from hunterx.domain.mission_orchestration.enums import FindingStage
from hunterx.domain.mission_orchestration.orchestrator import MissionOrchestrator

_FIXTURES = pathlib.Path(__file__).parent / "missions"


def _fixtures() -> list[pathlib.Path]:
    return sorted(_FIXTURES.glob("*.json"))


def _load_fixture(path: pathlib.Path) -> dict[str, object]:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def _replay(fixture: dict[str, object]) -> MissionOrchestrator:
    """Replay a fixture script through a fresh orchestrator."""
    orchestrator = MissionOrchestrator()
    orchestrator.create_mission(
        objective=str(fixture["objective"]),
        target=str(fixture["target"]),
    )
    for step in fixture["script"]:  # type: ignore[union-attr]
        action = str(step["action"])
        if action == "ingest":
            orchestrator.ingest_result(
                orchestrator.missions()[0].mission_id,
                tool_id=str(step["tool"]),
                asset_key=str(step.get("asset", "")),
                raw=dict(step["raw"]),  # type: ignore[arg-type]
            )
        elif action == "hypothesis":
            orchestrator.add_hypothesis(
                orchestrator.missions()[0].mission_id,
                statement=str(step["statement"]),
                category=str(step.get("category", "unknown_behavior")),
                priority=float(step.get("priority", 0.5)),
                validation_strategy=str(step.get("validation_strategy", "")),
            )
        elif action == "hypothesis_update":
            mission = orchestrator.missions()[0]
            hypothesis = next(
                (h for h in mission.hypotheses if h.statement == str(step["statement"])),
                None,
            )
            assert hypothesis is not None, f"hypothesis not found: {step['statement']}"
            orchestrator.update_hypothesis(
                mission.mission_id,
                hypothesis.hypothesis_id,
                supporting=tuple(step.get("supporting", []) or []),
                contradicting=tuple(step.get("contradicting", []) or []),
            )
            if step.get("verify"):
                orchestrator.verify_hypothesis(
                    mission.mission_id,
                    hypothesis.hypothesis_id,
                    reproducible=bool(step.get("reproducible", True)),
                )
        elif action == "baseline":
            orchestrator.capture_baseline(
                orchestrator.missions()[0].mission_id,
                asset_key=str(step.get("asset", "")),
                request_fingerprint=str(step.get("request_fingerprint", "")),
                status_code=int(step.get("status_code", 200)),
                content_length=int(step.get("content_length", 0)),
                headers=dict(step.get("headers", {}) or {}),
            )
        elif action == "differential":
            orchestrator.differential_test(
                orchestrator.missions()[0].mission_id,
                asset_key=str(step.get("asset", "")),
                test=TestResponse(
                    status_code=int(step.get("test_status", 200)),
                    content_length=int(step.get("test_length", 0)),
                    body=str(step.get("test_body", "")),
                ),
                classification_hint=str(step.get("classification_hint", "")),
            )
        elif action == "negative":
            orchestrator.record_negative(
                orchestrator.missions()[0].mission_id,
                asset_key=str(step.get("asset", "")),
                capability=str(step["capability"]),
                tool_id=str(step.get("tool", "")),
                input=str(step.get("input", "")),
                outcome=str(step.get("outcome", "")),
            )
        elif action == "coverage":
            orchestrator.record_coverage(
                orchestrator.missions()[0].mission_id,
                asset_key=str(step.get("asset", "")),
                capability=str(step["capability"]),
                state=str(step["state"]),
                tool_id=str(step.get("tool", "")),
                confidence=float(step.get("confidence", 0.5)),
                evidence_refs=tuple(step.get("evidence_refs", []) or []),
            )
        elif action == "finding":
            orchestrator.register_finding(
                orchestrator.missions()[0].mission_id,
                finding_id=str(step["finding_id"]),
                vulnerability_class=str(step["vulnerability_class"]),
                asset_key=str(step.get("asset_key", "")),
                severity=str(step.get("severity", "info")),
                tool=str(step.get("tool", "")),
                stage=FindingStage(str(step.get("stage", "candidate"))),
                confidence=float(step.get("confidence", 0.0)),
                evidence_refs=tuple(step.get("evidence_refs", []) or []),
            )
        elif action == "impact":
            finding = {
                "finding_id": str(step["finding_id"]),
                "vulnerability_class": str(step["vulnerability_class"]),
                "asset_key": str(step.get("asset_key", "")),
                "severity": str(step.get("severity", "info")),
            }
            orchestrator.analyze_impact(
                orchestrator.missions()[0].mission_id,
                finding=finding,
                confidence=float(step.get("confidence", 0.0)),
            )
        elif action == "cascade":
            orchestrator.cascade_findings(orchestrator.missions()[0].mission_id)
        elif action == "finalize":
            orchestrator.finalize(orchestrator.missions()[0].mission_id)
        else:  # pragma: no cover - fixture authoring guard
            raise AssertionError(f"unknown script action {action!r}")
    return orchestrator


class TestGoldenMissions:
    @pytest.mark.parametrize("path", _fixtures(), ids=lambda p: p.stem)
    def test_fixture_replays_to_expected_outcome(self, path: pathlib.Path) -> None:
        fixture = _load_fixture(path)
        orchestrator = _replay(fixture)
        mission = orchestrator.missions()[0]
        assert mission.outcome is not None
        expected = fixture["expected_outcome"]  # type: ignore[index]

        if "phase" in expected:
            assert mission.outcome.phase == expected["phase"]
        if "findings_validated" in expected:
            assert mission.outcome.findings_validated == expected["findings_validated"]
        if "hypotheses_resolved" in expected:
            assert mission.outcome.hypotheses_resolved == expected["hypotheses_resolved"]
        if "coverage_ratio_gt" in expected:
            assert mission.coverage_ratio() > float(expected["coverage_ratio_gt"])
        if "follow_on_hypotheses_gt" in expected:
            follow_ons = [
                h for h in mission.hypotheses if h.provenance.get("source") == "finding-cascade"
            ]
            assert len(follow_ons) > int(expected["follow_on_hypotheses_gt"])

    def test_replay_is_deterministic(self) -> None:
        fixture = _load_fixture(_fixtures()[0])
        first = _replay(fixture)
        second = _replay(fixture)
        first_decisions = [
            (d.next_action, d.information_gain, d.priority) for d in first.missions()[0].decisions
        ]
        second_decisions = [
            (d.next_action, d.information_gain, d.priority) for d in second.missions()[0].decisions
        ]
        assert first_decisions == second_decisions
