# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tests for the TargetIntelligenceEngine facade.

Covers the adaptive loop: target registration, observation ingestion,
asset materialization, coverage priming, conflict & change detection,
hypothesis generation, scoring and next-action ranking — all from pure
intelligence state (no tool execution).
"""

from __future__ import annotations

from hunterx.domain.target_intelligence.enums import (
    ActionStatus,
    ChangeKind,
    CoverageCapability,
    CoverageState,
    IntelligenceTargetKind,
    ObservationType,
)
from hunterx.domain.target_intelligence.models import (
    IntelligenceAsset,
    IntelligenceEvidence,
    IntelligenceTarget,
    NegativeResult,
    Observation,
)
from hunterx.domain.topology.enums import EntityKind
from hunterx.engines.target_intelligence import TargetIntelligenceEngine


def _target(**overrides: object) -> IntelligenceTarget:
    values: dict[str, object] = {
        "target_id": "tgt-1",
        "mission_id": "mis-1",
        "scope": "example.com",
        "identity": "Example",
        "kind": IntelligenceTargetKind.DOMAIN,
        "value": "example.com",
    }
    values.update(overrides)
    return IntelligenceTarget(**values)  # type: ignore[arg-type]


def _obs(**overrides: object) -> Observation:
    values: dict[str, object] = {
        "target_id": "tgt-1",
        "mission_id": "mis-1",
        "tool": "katana",
        "capability": "endpoint_enumeration",
        "observation_type": ObservationType.ENDPOINT,
        "value": "https://example.com/api/search?q=x",
        "asset_key": "url:https://example.com/api/search?q=x",
    }
    values.update(overrides)
    return Observation(**values)  # type: ignore[arg-type]


class TestTargetIntelligenceEngine:
    def test_register_and_get_target(self) -> None:
        engine = TargetIntelligenceEngine()
        target = _target()
        engine.register_target(target)
        assert engine.get_target("tgt-1") is target

    def test_ingest_observations_deduplicates(self) -> None:
        engine = TargetIntelligenceEngine()
        target = _target()
        engine.register_target(target)
        accepted = engine.ingest_observations(target, [_obs(), _obs()])
        assert len(accepted) == 1
        assert engine.observations.count(target_id="tgt-1") == 1

    def test_ingest_observations_materializes_assets(self) -> None:
        engine = TargetIntelligenceEngine()
        target = _target()
        engine.register_target(target)
        engine.ingest_observations(target, [_obs()])
        assets = engine.assets.list(target_id="tgt-1")
        assert assets
        assert assets[0].key == "url:https://example.com/api/search?q=x"

    def test_ingest_assets_and_graph(self) -> None:
        engine = TargetIntelligenceEngine()
        target = _target()
        engine.register_target(target)
        asset = IntelligenceAsset(
            target_id="tgt-1",
            mission_id="mis-1",
            kind=EntityKind.URL,
            name="https://example.com/",
        )
        engine.ingest_assets(target, [asset])
        assert len(engine.graph.assets()) == 1

    def test_ingest_evidence_and_record_negative(self) -> None:
        engine = TargetIntelligenceEngine()
        target = _target()
        engine.register_target(target)
        evidence = IntelligenceEvidence(
            target_id="tgt-1",
            mission_id="mis-1",
            what="server banner revealed version",
            where="https://example.com/",
            source="httpx",
        )
        engine.ingest_evidence(target, [evidence])
        assert engine.evidence.count(target_id="tgt-1") == 1

        negative = NegativeResult(
            target_id="tgt-1",
            asset_key="url:https://example.com/api/search?q=x",
            tested_capability=CoverageCapability.SQL_INJECTION,
            tool="sqlmap",
        )
        engine.record_negative(target, negative)
        state = engine.snapshot(target)
        assert state.negative_results
        assert state.coverage.state(negative.asset_key, CoverageCapability.SQL_INJECTION) is CoverageState.TESTED

    def test_detect_conflicts_from_observations(self) -> None:
        engine = TargetIntelligenceEngine()
        target = _target()
        engine.register_target(target)
        engine.ingest_observations(
            target,
            [
                _obs(tool="nuclei", capability="vulnerability_scanning", observation_type=ObservationType.VULNERABILITY, value="CVE-X", asset_key="url:https://example.com/"),
                _obs(tool="nikto", capability="vulnerability_scanning", observation_type=ObservationType.VULNERABILITY, value="none", asset_key="url:https://example.com/"),
            ],
        )
        conflicts = engine.detect_conflicts(target)
        assert len(conflicts) == 1

    def test_detect_changes_records_history(self) -> None:
        engine = TargetIntelligenceEngine()
        target = _target()
        engine.register_target(target)
        engine.ingest_assets(
            target,
            [IntelligenceAsset(target_id="tgt-1", mission_id="mis-1", kind=EntityKind.HOSTNAME, name="www.example.com")],
        )
        changes = engine.detect_changes(target)
        assert any(change.kind is ChangeKind.NEW for change in changes)
        assert engine.history.count("tgt-1") >= 1

    def test_run_cycle_returns_state_actions_decision(self) -> None:
        engine = TargetIntelligenceEngine()
        target = _target()
        engine.register_target(target)
        engine.ingest_assets(
            target,
            [
                IntelligenceAsset(
                    target_id="tgt-1",
                    mission_id="mis-1",
                    kind=EntityKind.URL,
                    name="https://example.com/api/search",
                    properties={"parameters": ["q"]},
                )
            ],
        )
        state, actions, decision = engine.run_cycle(target, mission_objective="find vulnerabilities")
        assert state.target.target_id == "tgt-1"
        assert state.coverage.entries
        assert actions
        assert decision.rationale
        # No action may be marked PROPOSED without a scope status.
        assert all(action.scope_status for action in actions)

    def test_actions_respect_safety_ceiling(self) -> None:
        engine = TargetIntelligenceEngine()
        target = _target()
        engine.register_target(target)
        engine.ingest_assets(
            target,
            [IntelligenceAsset(target_id="tgt-1", mission_id="mis-1", kind=EntityKind.URL, name="https://example.com/")],
        )
        _, actions, _ = engine.run_cycle(target, safety_ceiling="passive", authorization_granted=False)
        active_risk = [a for a in actions if a.risk in ("active", "high")]
        assert all(a.status is ActionStatus.BLOCKED for a in active_risk)

    def test_score_persists_on_engine(self) -> None:
        engine = TargetIntelligenceEngine()
        target = _target()
        engine.register_target(target)
        score = engine.score(target)
        assert score.target_id == "tgt-1"
        assert engine._scores["tgt-1"] is score

    def test_correlate_streams_observations(self) -> None:
        engine = TargetIntelligenceEngine()
        target = _target()
        engine.register_target(target)
        engine.ingest_observations(
            target,
            [_obs(tool="subfinder", observation_type=ObservationType.HOST, value="www.example.com", asset_key="hostname:www.example.com")],
        )
        result = engine.correlate(target)
        assert result.chains

    def test_isolated_targets(self) -> None:
        engine = TargetIntelligenceEngine()
        a = _target(target_id="a")
        b = _target(target_id="b")
        engine.register_target(a)
        engine.register_target(b)
        engine.ingest_observations(a, [_obs(target_id="a")])
        assert engine.observations.count(target_id="a") == 1
        assert engine.observations.count(target_id="b") == 0
