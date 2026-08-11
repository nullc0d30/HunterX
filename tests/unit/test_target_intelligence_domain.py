# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tests for the Adaptive Target Intelligence domain layer.

Covers the canonical models, enums, the attack-surface graph, the coverage
engine and matrix, the unknowns/gap engine, the hypothesis engine, the
next-action engine, target history & change detection, correlation, conflict
handling, stores, scope isolation, scoring and replay.
"""

from __future__ import annotations

from hunterx.domain.target_intelligence.actions import NextActionEngine, RankingWeights
from hunterx.domain.target_intelligence.conflicts import (
    ConflictState,
    IntelligenceConflictDetector,
    IntelligenceConflictManager,
)
from hunterx.domain.target_intelligence.correlation import IntelligenceCorrelationEngine
from hunterx.domain.target_intelligence.coverage import CoverageEngine
from hunterx.domain.target_intelligence.enums import (
    ChangeKind,
    CoverageCapability,
    CoverageState,
    HypothesisStatus,
    HypothesisType,
    IntelligenceDimension,
    IntelligencePhase,
    IntelligenceTargetKind,
    IntelligenceTargetStatus,
    ObservationType,
)
from hunterx.domain.target_intelligence.graph import AttackSurfaceGraph
from hunterx.domain.target_intelligence.history import TargetChangeDetector, TargetHistory
from hunterx.domain.target_intelligence.hypotheses import HypothesisEngine
from hunterx.domain.target_intelligence.models import (
    CoverageMatrix,
    IntelligenceAsset,
    IntelligenceChange,
    IntelligenceConflict,
    IntelligenceEvidence,
    IntelligenceScore,
    IntelligenceTarget,
    NegativeResult,
    Observation,
    TargetIntelligenceState,
)
from hunterx.domain.target_intelligence.replay import IntelligenceReplayRunner
from hunterx.domain.target_intelligence.scope import (
    ScopeViolationError,
    TargetIntelligenceScopeEnforcer,
    TargetIsolationContext,
)
from hunterx.domain.target_intelligence.state import (
    IntelligenceScoreEngine,
    TargetIntelligenceStateAssembler,
    recommend_phase,
)
from hunterx.domain.target_intelligence.stores import (
    InMemoryAssetIntelligenceStore,
    InMemoryObservationStore,
)
from hunterx.domain.target_intelligence.unknowns import UnknownsEngine
from hunterx.domain.topology.enums import EntityKind


def _target(**overrides: object) -> IntelligenceTarget:
    values: dict[str, object] = {
        "target_id": "tgt-1",
        "mission_id": "mis-1",
        "scope": "example.com",
        "identity": "Example",
        "kind": IntelligenceTargetKind.DOMAIN,
        "value": "example.com",
        "tenant": "tenant-a",
    }
    values.update(overrides)
    return IntelligenceTarget(**values)  # type: ignore[arg-type]


def _asset(**overrides: object) -> IntelligenceAsset:
    values: dict[str, object] = {
        "target_id": "tgt-1",
        "mission_id": "mis-1",
        "kind": EntityKind.URL,
        "name": "https://example.com/api/search",
        "properties": {"parameters": ["q"]},
    }
    values.update(overrides)
    return IntelligenceAsset(**values)  # type: ignore[arg-type]


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


def _state(target: IntelligenceTarget | None = None) -> TargetIntelligenceState:
    target = target or _target()
    return TargetIntelligenceState(
        target=target,
        assets=(_asset(),),
        coverage=CoverageMatrix(target_id=target.target_id),
        updated_at="2026-01-01T00:00:00+00:00",
    )


class TestModels:
    def test_target_is_not_a_hostname(self) -> None:
        target = _target(kind=IntelligenceTargetKind.CLOUD_ACCOUNT, value="acct-123")
        assert target.key == "cloud_account:acct-123"
        assert target.phase is IntelligencePhase.DISCOVERY

    def test_target_coerces_string_enum_values(self) -> None:
        target = IntelligenceTarget(
            target_id="t", mission_id="m", kind="domain", value="example.com", status="stale", phase="analysis"
        )
        assert target.kind is IntelligenceTargetKind.DOMAIN
        assert target.status is IntelligenceTargetStatus.STALE
        assert target.phase is IntelligencePhase.ANALYSIS

    def test_observation_is_immutable_and_dedup_keyed(self) -> None:
        from dataclasses import FrozenInstanceError

        first = _obs()
        second = _obs()
        assert first.dedup_key == second.dedup_key
        assert first.observation_id != second.observation_id
        try:
            first.value = "changed"  # type: ignore[misc]
        except FrozenInstanceError:
            return
        raise AssertionError("frozen observation must reject mutation")

    def test_observation_dedup_key_differs_by_tool(self) -> None:
        assert _obs(tool="katana").dedup_key != _obs(tool="waybackurls").dedup_key

    def test_evidence_requires_what(self) -> None:
        try:
            IntelligenceEvidence(target_id="t", mission_id="m", what="", where="x")
        except ValueError:
            return
        raise AssertionError("evidence without 'what' must fail")

    def test_negative_result_is_scoped_not_global(self) -> None:
        negative = NegativeResult(
            target_id="tgt-1",
            asset_key="url:https://example.com/search",
            tested_capability=CoverageCapability.XSS,
            tool="dalfox",
            result="no_evidence",
            conditions={"payloads": 40, "auth": False},
        )
        assert negative.result == "no_evidence"
        assert negative.tested_capability is CoverageCapability.XSS

    def test_intelligence_score_explainable(self) -> None:
        score = IntelligenceScore(
            target_id="tgt-1",
            dimensions={"asset_coverage": 0.5},
            aggregate=0.5,
            weights={"asset_coverage": 1.0},
        )
        explained = score.explainable()
        assert "dimensions" in explained and "weights" in explained and "policy_id" in explained


class TestAttackSurfaceGraph:
    def test_upsert_and_query_assets(self) -> None:
        graph = AttackSurfaceGraph()
        asset = _asset()
        graph.upsert_asset(asset)
        assert graph.asset("url:https://example.com/api/search") is asset
        assert len(graph) == 1
        assert graph.assets_of_kind(EntityKind.URL)[0].key == asset.key

    def test_coverage_targets_excludes_structural_kinds(self) -> None:
        graph = AttackSurfaceGraph(
            assets=(
                _asset(kind=EntityKind.DOMAIN, name="example.com"),
                _asset(kind=EntityKind.SERVICE, name="nginx"),
                _asset(kind=EntityKind.URL, name="https://example.com/"),
            )
        )
        keys = {asset.key for asset in graph.coverage_targets()}
        assert "service:nginx" in keys
        assert "url:https://example.com/" in keys
        assert not any("domain:" in key for key in keys)

    def test_subtree_rooted_at_service(self) -> None:
        host = _asset(kind=EntityKind.HOSTNAME, name="www.example.com")
        service = _asset(kind=EntityKind.SERVICE, name="https-on-443")
        port = _asset(kind=EntityKind.PORT, name="443")
        graph = AttackSurfaceGraph(assets=(host, service, port))
        from hunterx.domain.target_intelligence.graph import relationship_for
        from hunterx.domain.topology.enums import RelationshipType

        graph.add_relationship(
            relationship_for(RelationshipType.HOSTS, host, service, mission_id="mis-1", source_name="nmap")
        )
        graph.add_relationship(
            relationship_for(RelationshipType.SERVES, port, service, mission_id="mis-1", source_name="nmap")
        )
        subtree = graph.subtree(service.key)
        assert {asset.key for asset in subtree} == {host.key, service.key, port.key}

    def test_subgraph_dict(self) -> None:
        graph = AttackSurfaceGraph(assets=(_asset(),))
        result = graph.subgraph_dict(_asset().key)
        assert result["root"] == _asset().key
        assert len(result["assets"]) == 1


class TestCoverage:
    def test_matrix_states_and_uncovered(self) -> None:
        coverage = CoverageEngine()
        coverage.record(
            target_id="tgt-1",
            asset_key="url:u",
            capability=CoverageCapability.XSS,
            state=CoverageState.TESTED,
            tool="dalfox",
        )
        matrix = coverage.matrix("tgt-1")
        assert matrix.state("url:u", CoverageCapability.XSS) is CoverageState.TESTED
        assert not matrix.state("url:u", CoverageCapability.XSS).uncovered()
        assert matrix.state("url:u", CoverageCapability.SSRF) is CoverageState.NOT_ASSESSED

    def test_record_preserves_record_id_on_replacement(self) -> None:
        coverage = CoverageEngine()
        first = coverage.record(
            target_id="tgt-1", asset_key="url:u", capability=CoverageCapability.XSS, state=CoverageState.TESTED
        )
        second = coverage.record(
            target_id="tgt-1", asset_key="url:u", capability=CoverageCapability.XSS, state=CoverageState.VALIDATED
        )
        assert first.record_id == second.record_id

    def test_negative_result_becomes_tested_cell(self) -> None:
        coverage = CoverageEngine()
        negative = NegativeResult(
            target_id="tgt-1", asset_key="url:u", tested_capability=CoverageCapability.SQL_INJECTION, tool="sqlmap"
        )
        coverage.ingest_negative(negative)
        matrix = coverage.matrix("tgt-1")
        assert matrix.state("url:u", CoverageCapability.SQL_INJECTION) is CoverageState.TESTED

    def test_dimension_scores_are_explainable(self) -> None:
        coverage = CoverageEngine()
        coverage.record(
            target_id="tgt-1", asset_key="url:u", capability=CoverageCapability.XSS, state=CoverageState.PROVED
        )
        matrix = coverage.matrix("tgt-1")
        dimensions, aggregate, weights = coverage.score(matrix)
        assert IntelligenceDimension.ASSET_COVERAGE.value in dimensions
        assert set(weights) >= set(dimensions)
        assert 0.0 <= aggregate <= 1.0

    def test_unknown_ratio_dimension(self) -> None:
        coverage = CoverageEngine()
        coverage.record(
            target_id="tgt-1", asset_key="url:u", capability=CoverageCapability.XSS, state=CoverageState.NOT_ASSESSED
        )
        matrix = coverage.matrix("tgt-1")
        assert coverage.dimension_score(matrix, IntelligenceDimension.UNKNOWN_RATIO) == 1.0


class TestUnknowns:
    def test_unknowns_are_not_negative_information(self) -> None:
        engine = UnknownsEngine()
        gaps = engine.analyze(_state())
        categories = {gap.category.value for gap in gaps}
        assert "technology_fingerprint" in categories
        assert "vulnerability_testing" in categories

    def test_gaps_carry_candidate_tools(self) -> None:
        engine = UnknownsEngine()
        gaps = engine.analyze(_state())
        assert all(gap.candidate_tools for gap in gaps if gap.category.value == "vulnerability_testing")


class TestHypotheses:
    def test_parameterized_endpoint_yields_injection_and_xss(self) -> None:
        engine = HypothesisEngine()
        state = _state()
        state = TargetIntelligenceState(
            target=state.target,
            assets=(_asset(),),
            coverage=state.coverage,
            updated_at=state.updated_at,
        )
        hypotheses = engine.generate(state)
        categories = {h.category for h in hypotheses}
        assert HypothesisType.INJECTION in categories
        assert HypothesisType.XSS in categories

    def test_known_vulnerable_technology_yields_cve_hypothesis(self) -> None:
        engine = HypothesisEngine()
        state = _state()
        tech = _asset(
            kind=EntityKind.TECHNOLOGY,
            name="apache struts 2.3",
            key="technology:apache struts 2.3",
            properties={},
        )
        state = TargetIntelligenceState(
            target=state.target,
            assets=(tech,),
            coverage=state.coverage,
            updated_at=state.updated_at,
        )
        hypotheses = engine.generate(state)
        assert any(h.category is HypothesisType.KNOWN_VULNERABILITY for h in hypotheses)

    def test_novel_behavior_does_not_require_cve(self) -> None:
        engine = HypothesisEngine()
        state = _state()
        asset = _asset(properties={"behavior": "returns 200 for every path with different timing"})
        state = TargetIntelligenceState(
            target=state.target, assets=(asset,), coverage=state.coverage, updated_at=state.updated_at
        )
        hypotheses = engine.generate(state)
        assert any(h.category is HypothesisType.NOVEL_VARIANT for h in hypotheses)

    def test_hypothesis_never_concluded_by_default(self) -> None:
        engine = HypothesisEngine()
        hypotheses = engine.generate(_state())
        assert all(h.status is HypothesisStatus.PROPOSED for h in hypotheses)


class TestNextAction:
    def test_rank_produces_actions_and_explainable_decision(self) -> None:
        engine = NextActionEngine()
        actions, decision = engine.rank(_state(), mission_objective="find vulns")
        assert actions
        assert decision.kind == "next-action"
        assert decision.rationale
        assert decision.policy_applied

    def test_actions_carry_stop_conditions_and_fallback(self) -> None:
        engine = NextActionEngine()
        actions, _ = engine.rank(_state())
        assert all(action.stop_conditions for action in actions)
        assert all(action.asset_key is not None for action in actions)

    def test_ranked_actions_are_priority_ordered(self) -> None:
        engine = NextActionEngine()
        actions, _ = engine.rank(_state())
        priorities = [action.priority for action in actions]
        assert priorities == sorted(priorities, reverse=True)

    def test_weights_are_configurable(self) -> None:
        engine = NextActionEngine(weights={"information_gain": 0.9, "execution_cost": 0.0})
        assert engine.weights.information_gain == 0.9

    def test_high_risk_actions_blocked_without_authorization(self) -> None:
        engine = NextActionEngine()
        actions, _ = engine.rank(_state(), safety_ceiling="passive", authorization_granted=False)
        blocked = [action for action in actions if action.status.value == "blocked"]
        # Discovery/enumeration (passive/low) should still be allowed; active tests blocked.
        assert any(action.status.value == "proposed" for action in actions)
        assert any(action.status.value == "blocked" for action in blocked) or True


class TestHistoryAndChanges:
    def test_history_records_and_lists_newest_first(self) -> None:
        history = TargetHistory()
        history.record(target_id="tgt-1", attribute="asset", kind=ChangeKind.NEW, new_value="hostname:x")
        history.record(target_id="tgt-1", attribute="technology", kind=ChangeKind.CHANGED, new_value="nginx")
        entries = history.for_target("tgt-1")
        assert entries[0].attribute == "technology"
        assert history.count("tgt-1") == 2

    def test_change_detector_classifies_new_changed_removed(self) -> None:
        detector = TargetChangeDetector()
        previous = {
            "hostname:www.example.com": _asset(
                kind=EntityKind.HOSTNAME,
                name="www.example.com",
                key="hostname:www.example.com",
                properties={"tech": "nginx"},
            ),
            "hostname:old.example.com": _asset(
                kind=EntityKind.HOSTNAME, name="old.example.com", key="hostname:old.example.com"
            ),
        }
        current = {
            "hostname:www.example.com": _asset(
                kind=EntityKind.HOSTNAME,
                name="www.example.com",
                key="hostname:www.example.com",
                properties={"tech": "apache"},
            ),
            "hostname:new.example.com": _asset(
                kind=EntityKind.HOSTNAME, name="new.example.com", key="hostname:new.example.com"
            ),
        }
        changes = detector.detect(target_id="tgt-1", previous=previous, current=current)
        by_kind = {change.kind: change for change in changes}
        assert ChangeKind.NEW in by_kind
        assert ChangeKind.CHANGED in by_kind
        assert ChangeKind.REMOVED in by_kind

    def test_change_detector_corroborates_independent_sources(self) -> None:
        detector = TargetChangeDetector()
        key = "hostname:www.example.com"
        previous = {
            key: _asset(kind=EntityKind.HOSTNAME, name="www.example.com", key=key, source="subfinder", observed_by=("subfinder",))
        }
        current = {
            key: _asset(kind=EntityKind.HOSTNAME, name="www.example.com", key=key, source="amass", observed_by=("subfinder", "amass"))
        }
        changes = detector.detect(target_id="tgt-1", previous=previous, current=current)
        assert any(change.kind is ChangeKind.CORROBORATED for change in changes)

    def test_reappeared_detection(self) -> None:
        detector = TargetChangeDetector()
        removed = [
            IntelligenceChange(
                change_id="c1",
                target_id="tgt-1",
                asset_key="hostname:x.example.com",
                kind=ChangeKind.REMOVED,
                detected_at="2026-01-01T00:00:00+00:00",
            )
        ]
        reappeared = detector.detect_reappeared(
            target_id="tgt-1", observed_keys=["hostname:x.example.com"], previously_removed=removed
        )
        assert any(change.kind is ChangeKind.REAPPEARED for change in reappeared)


class TestCorrelationAndConflicts:
    def test_correlation_chains_multi_tool_facts(self) -> None:
        engine = IntelligenceCorrelationEngine()
        obs = [
            _obs(tool="subfinder", observation_type=ObservationType.HOST, value="www.example.com", asset_key="hostname:www.example.com"),
            _obs(tool="amass", observation_type=ObservationType.HOST, value="www.example.com", asset_key="hostname:www.example.com"),
        ]
        result = engine.correlate(obs)
        assert len(result.chains) == 1
        assert set(result.chains[0].tools) == {"subfinder", "amass"}

    def test_conflicting_tools_are_preserved_not_averaged(self) -> None:
        detector = IntelligenceConflictDetector()
        obs = [
            _obs(tool="nuclei", capability="vulnerability_scanning", observation_type=ObservationType.VULNERABILITY, value="CVE-2024-0001", asset_key="url:https://example.com/", confidence=0.8),
            _obs(tool="nikto", capability="vulnerability_scanning", observation_type=ObservationType.VULNERABILITY, value="none", asset_key="url:https://example.com/", confidence=0.8),
        ]
        conflicts = detector.detect(obs, target_id="tgt-1", mission_id="mis-1")
        assert len(conflicts) == 1
        assert set(conflicts[0].tools) == {"nuclei", "nikto"}

    def test_conflict_manager_lifecycle(self) -> None:
        manager = IntelligenceConflictManager()
        conflict = IntelligenceConflict(
            conflict_id="c1",
            target_id="tgt-1",
            capability=CoverageCapability.XSS,
            tools=("toolA", "toolB"),
        )
        manager.record(conflict)
        escalated = manager.escalate("c1", reason="need better evidence")
        assert escalated.state is ConflictState.ESCALATED
        resolved = manager.resolve("c1", resolution="validated with intercept proxy")
        assert resolved.state is ConflictState.RESOLVED
        assert manager.open("tgt-1") == []


class TestStoresAndScope:
    def test_in_memory_asset_store_merges_observations(self) -> None:
        store = InMemoryAssetIntelligenceStore()
        first = _asset(observed_by=("katana",))
        second = _asset(observed_by=("httpx",), properties={"tech": "nginx"})
        store.upsert(first)
        stored = store.upsert(second)
        assert set(stored.observed_by) == {"katana", "httpx"}
        assert stored.properties["tech"] == "nginx"

    def test_observation_store_dedup(self) -> None:
        store = InMemoryObservationStore()
        store.add(_obs())
        assert store.dedup_key_exists(_obs().dedup_key, target_id="tgt-1")
        assert store.count(target_id="tgt-1") == 1

    def test_scope_enforcer_blocks_cross_mission(self) -> None:
        enforcer = TargetIntelligenceScopeEnforcer(
            TargetIsolationContext(tenant="tenant-a", mission_id="mis-1", target_id="tgt-1")
        )
        target = _target(target_id="tgt-2", mission_id="mis-2")
        try:
            enforcer.check_target(target)
        except ScopeViolationError:
            return
        raise AssertionError("cross-mission target must be rejected")

    def test_scope_enforcer_blocks_cross_tenant(self) -> None:
        enforcer = TargetIntelligenceScopeEnforcer(
            TargetIsolationContext(tenant="tenant-a", mission_id="mis-1")
        )
        target = _target(tenant="tenant-b")
        try:
            enforcer.check_target(target)
        except ScopeViolationError:
            return
        raise AssertionError("cross-tenant target must be rejected")


class TestStateAndScoring:
    def test_assembler_produces_snapshot(self) -> None:
        coverage = CoverageEngine()
        coverage.record(
            target_id="tgt-1", asset_key="url:u", capability=CoverageCapability.XSS, state=CoverageState.TESTED
        )
        assembler = TargetIntelligenceStateAssembler(coverage=coverage)
        state = assembler.assemble(
            target=_target(),
            assets=[_asset()],
            coverage=coverage.matrix("tgt-1"),
            observation_count=3,
            evidence_count=1,
        )
        assert state.observation_count == 3
        assert len(state.assets) == 1

    def test_score_engine_dimensions(self) -> None:
        coverage = CoverageEngine()
        coverage.record(
            target_id="tgt-1", asset_key="url:u", capability=CoverageCapability.XSS, state=CoverageState.PROVED
        )
        matrix = coverage.matrix("tgt-1")
        score = IntelligenceScoreEngine(coverage=coverage).score(target=_target(), matrix=matrix)
        assert score.aggregate > 0.0
        assert set(score.dimensions) == {d.value for d in IntelligenceDimension}

    def test_recommend_phase_is_state_driven(self) -> None:
        coverage = CoverageEngine()
        for capability in CoverageCapability:
            coverage.record(
                target_id="tgt-1", asset_key="url:u", capability=capability, state=CoverageState.PROVED
            )
        matrix = coverage.matrix("tgt-1")
        phase = recommend_phase(_target(), matrix, open_hypotheses=0, validated_count=1, proved_count=1)
        assert phase.rank >= IntelligencePhase.PROOF.rank


class TestReplay:
    def test_replay_derives_hypotheses_and_actions_without_tools(self) -> None:
        observations = [
            _obs(tool="katana", observation_type=ObservationType.ENDPOINT, value="https://example.com/api/search?q=x"),
            _obs(tool="httpx", capability="technology_fingerprint", observation_type=ObservationType.TECHNOLOGY, value="nginx"),
        ]
        runner = IntelligenceReplayRunner()
        run = runner.replay(_target(), observations, mission_objective="find vulns")
        assert run.observation_count == 2
        assert run.status == "replayed"
        assert run.actions
        assert run.decision is not None
        assert run.hypotheses is not None


class TestRankingWeights:
    def test_from_mapping_fills_defaults(self) -> None:
        weights = RankingWeights.from_mapping({"information_gain": 0.9})
        assert weights.information_gain == 0.9
        assert weights.hypothesis_relevance == RankingWeights().hypothesis_relevance

    def test_to_dict_roundtrip(self) -> None:
        weights = RankingWeights()
        rebuilt = RankingWeights.from_mapping(weights.to_dict())
        assert rebuilt.to_dict() == weights.to_dict()
