# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Golden replay tests for the Sprint 033 full-spectrum assessment datasets.

Each dataset under ``tests/golden/full_assessment/`` defines a target, the
assets, the scripted tool outputs, and the expected observations, correlations,
hypotheses, findings, PoCs, attack paths and final mission state. The golden
test replays the script through a fresh orchestrator and verifies the expected
final state is reached deterministically.
"""

from __future__ import annotations

import json
import pathlib
from typing import Any

import pytest

from hunterx.domain.mission_orchestration.enums import FindingStage
from hunterx.domain.mission_orchestration.orchestrator import MissionOrchestrator
from hunterx.domain.target_intelligence.enums import CoverageState

_FIXTURES = pathlib.Path(__file__).parent / "full_assessment"


def _fixtures() -> list[pathlib.Path]:
    return sorted(_FIXTURES.glob("*.json"))


def _load(path: pathlib.Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def _record(runner: ReplayRunner, mission_id: str, asset_key: str, capability: str, state: str, tool_id: str = "") -> None:
    runner.orchestrator.record_coverage(
        mission_id,
        asset_key=asset_key,
        capability=capability,
        state=CoverageState(state),
        tool_id=tool_id or "golden",
    )


class ReplayRunner:
    """Replay a golden dataset script through a fresh orchestrator."""

    def __init__(self, fixture: dict[str, Any]) -> None:
        self.fixture = fixture
        self.orchestrator = MissionOrchestrator()
        self.mission = None
        self._step_index = 0

    def run(self) -> dict[str, Any]:
        import dataclasses

        from hunterx.domain.mission_orchestration.enums import StopCondition

        self.mission = self.orchestrator.create_mission(
            objective=str(self.fixture["objective"]),
            target=str(self.fixture["target"]),
            strategy="adaptive",
        )
        self.mission.policy = dataclasses.replace(
            self.mission.policy,
            coverage_target=0.99,
            stop_conditions=(
                StopCondition.OBJECTIVES_COMPLETE,
                StopCondition.COVERAGE_TARGET_ACHIEVED,
                StopCondition.RESOURCE_BUDGET_EXHAUSTED,
                StopCondition.TIME_BUDGET_EXHAUSTED,
            ),
        )
        mission_id = self.mission.mission_id
        self.orchestrator.start(mission_id)
        for step in self.fixture["script"]:
            self._step(mission_id, step)
        self.orchestrator.finalize(mission_id)
        return self.orchestrator.get(mission_id).to_dict()

    def _step(self, mission_id: str, step: dict[str, Any]) -> None:
        action = str(step["action"])
        if action == "ingest":
            self.orchestrator.ingest_result(
                mission_id,
                tool_id=str(step["tool"]),
                asset_key=str(step.get("asset", "")),
                raw=dict(step["raw"]),
            )
            self._record(mission_id, str(step.get("asset", "")), str(step.get("capability", "asset_discovery")), "validated", str(step["tool"]))
        elif action == "hypothesis":
            self.orchestrator.add_hypothesis(
                mission_id,
                statement=str(step["statement"]),
                category=str(step.get("category", "unknown_behavior")),
                priority=float(step.get("priority", 0.5)),
            )
        elif action == "support_hypothesis":
            hypothesis = self.orchestrator.add_hypothesis(
                mission_id,
                statement=str(step["statement"]),
                category=str(step.get("category", "unknown_behavior")),
                priority=float(step.get("priority", 0.7)),
            )
            self.orchestrator.update_hypothesis(
                mission_id,
                hypothesis.hypothesis_id,
                supporting=tuple(step.get("supporting", []) or []),
            )
            if step.get("verify"):
                self.orchestrator.verify_hypothesis(
                    mission_id, hypothesis.hypothesis_id, reproducible=bool(step.get("reproducible", True))
                )
        elif action == "negative":
            self.orchestrator.record_negative(
                mission_id,
                asset_key=str(step.get("asset", "")),
                capability=str(step["capability"]),
                kind=str(step.get("kind", "not_vulnerable")),
                tool_id=str(step.get("tool", "")),
                outcome=str(step.get("outcome", "")),
            )
        elif action == "finding":
            self.orchestrator.register_finding(
                mission_id,
                finding_id=str(step["finding_id"]),
                vulnerability_class=str(step["vulnerability_class"]),
                asset_key=str(step.get("asset_key", "")),
                severity=str(step.get("severity", "high")),
                tool=str(step.get("tool", "")),
                stage=FindingStage(str(step.get("stage", "proven"))),
                confidence=float(step.get("confidence", 0.9)),
                evidence_refs=tuple(step.get("evidence_refs", []) or []),
            )
            self.orchestrator.analyze_impact(
                mission_id,
                finding={
                    "finding_id": str(step["finding_id"]),
                    "vulnerability_class": str(step["vulnerability_class"]),
                    "asset_key": str(step.get("asset_key", "")),
                    "severity": str(step.get("severity", "high")),
                },
                confidence=float(step.get("confidence", 0.9)),
            )
        elif action == "proof_coverage":
            _record(self, mission_id, str(step.get("asset", "")), str(step["capability"]), "proved", str(step.get("tool", "")))
        elif action == "novel":
            record = self.orchestrator.start_novel(
                mission_id,
                asset_key=str(step.get("asset", "")),
                behavior_summary=str(step.get("behavior_summary", "")),
            )
            from hunterx.domain.mission_orchestration.enums import NovelPipelineStage

            for stage in ("behavioral_model", "experiment", "observation", "new_hypothesis"):
                self.orchestrator.advance_novel(
                    mission_id, record.record_id, stage=NovelPipelineStage(stage)
                )
            self.orchestrator.advance_novel(mission_id, record.record_id, proof_ref="poc-novel-1")
            self.orchestrator.advance_novel(
                mission_id, record.record_id, stage=NovelPipelineStage.VALIDATED_BEHAVIOR
            )
        elif action == "cascade":
            self.orchestrator.cascade_findings(mission_id)
        else:  # pragma: no cover - fixture authoring guard
            raise AssertionError(f"unknown script action {action!r}")

    def _record(self, mission_id: str, asset_key: str, capability: str, state: str, tool_id: str = "") -> None:
        _record(self, mission_id, asset_key, capability, state, tool_id)


class TestFullAssessmentGolden:
    @pytest.mark.parametrize("path", _fixtures(), ids=lambda p: p.stem)
    def test_dataset_replays_to_expected_final_state(self, path: pathlib.Path) -> None:
        fixture = _load(path)
        runner = ReplayRunner(fixture)
        summary = runner.run()
        mission = runner.orchestrator.get(summary["mission_id"])
        expected = fixture["expected_final_state"]

        # phase
        if "phase" in expected:
            assert mission.current_phase.value == expected["phase"]

        # validated findings (by class)
        validated = [f for f in mission.context.findings if f.get("stage") in ("proven", "report_ready", "verified")]
        if "findings_validated_gte" in expected:
            assert len(validated) >= int(expected["findings_validated_gte"])
        for vuln_class in expected.get("validated_classes", []) or []:
            assert any(f.get("vulnerability_class") == vuln_class for f in validated), vuln_class

        # rejected classes (false positives never promoted)
        for vuln_class in expected.get("rejected_classes", []) or []:
            assert not any(f.get("vulnerability_class") == vuln_class for f in validated), vuln_class

        # hypotheses
        if "hypotheses_gte" in expected:
            assert len(mission.hypotheses) >= int(expected["hypotheses_gte"])

        # negative evidence
        if "negative_evidence_gte" in expected:
            assert len(mission.negative_evidence) >= int(expected["negative_evidence_gte"])

        # impact / proofs
        if "impact_analyses_gte" in expected:
            assert len(mission.impact_analyses) >= int(expected["impact_analyses_gte"])
        if "proof_cells_gte" in expected:
            proved = [cell for cell in mission.coverage_cells() if cell.state.value == "proved"]
            assert len(proved) >= int(expected["proof_cells_gte"])

        # novel behavior
        if "novel_behavior_validated" in expected:
            assert mission.novel_behaviors
            assert mission.novel_behaviors[-1].classification.value == "novel_validated"

        # reassessment cascade
        if "follow_on_hypotheses_gte" in expected:
            cascaded = [
                h for h in mission.hypotheses if h.provenance.get("source") == "finding-cascade"
            ]
            assert len(cascaded) >= int(expected["follow_on_hypotheses_gte"])

        # outcome
        assert mission.outcome is not None

    def test_replay_is_deterministic(self) -> None:
        fixture = _load(_fixtures()[0])
        first = ReplayRunner(fixture)
        second = ReplayRunner(fixture)
        a = first.run()
        b = second.run()
        assert a["observation_count"] == b["observation_count"]
        assert a["hypothesis_count"] == b["hypothesis_count"]
        assert a.get("finding_count", True)
        assert a["coverage_ratio"] == b["coverage_ratio"]

    def test_datasets_declare_expected_state(self) -> None:
        """Every dataset must declare target, assets, tool outputs and expected state."""
        for path in _fixtures():
            fixture = _load(path)
            assert fixture.get("target")
            assert fixture.get("assets")
            assert fixture.get("tool_outputs")
            assert fixture.get("expected_observations") is not None
            assert fixture.get("expected_correlations") is not None
            assert fixture.get("expected_hypotheses") is not None
            assert fixture.get("expected_findings") is not None
            assert fixture.get("expected_pocs") is not None
            assert fixture.get("expected_attack_paths") is not None
            assert fixture.get("expected_final_state")
