# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for Target Memory & Campaign Intelligence domain engines.

Covers freshness classification, memory assembly with first/last seen
tracking, deterministic snapshots and diffs, change significance, revalidation
planning, coverage-gap detection, finding recurrence detection, preserved
contradictions, memory confidence/poisoning defense, next-action
recommendations, risk evolution and campaign intelligence.
"""

from __future__ import annotations

from hunterx.domain.target_memory.engines import (
    CampaignIntelligenceEngine,
    ChangeSignificanceEngine,
    ContradictionDetector,
    CoverageGapEngine,
    FindingRecurrenceDetector,
    MemoryConfidenceEngine,
    NextActionRecommender,
    ObservationFreshnessEngine,
    RevalidationPlanner,
    TargetDiffEngine,
    TargetMemoryAssembler,
    TargetRiskEvaluator,
    build_memory,
)
from hunterx.domain.target_memory.enums import (
    CampaignStatus,
    ChangeSignificance,
    DiffChangeKind,
    FreshnessState,
    HypothesisOutcome,
    RecurrenceKind,
    RiskLevel,
)
from hunterx.domain.target_memory.models import (
    Campaign,
    FindingMemory,
    HypothesisMemory,
    TargetMemory,
    TargetSnapshot,
)


def _obs(**overrides: object) -> dict[str, object]:
    values: dict[str, object] = {
        "target_id": "t1",
        "mission_id": "m1",
        "tool": "nmap",
        "observation_type": "port",
        "value": "80/tcp",
        "normalized_value": "80/tcp",
        "asset_key": "hostname:www.example.com",
        "source": "nmap-parser",
        "confidence": 1.0,
        "timestamp": "2026-08-01T00:00:00+00:00",
        "expires_at": None,
    }
    values.update(overrides)
    return values


class TestFreshnessEngine:
    def test_classify_by_type_policy(self) -> None:
        engine = ObservationFreshnessEngine()
        now = "2026-08-10T00:00:00+00:00"
        # DNS: 6h TTL -> a 3h-old observation is fresh.
        assert engine.classify("dns_record", "2026-08-10T03:00:00+00:00", now) == FreshnessState.FRESH
        # port: 12h TTL -> 20h old is stale.
        assert engine.classify("port", "2026-08-09T04:00:00+00:00", now) == FreshnessState.STALE
        # persistent finding -> always fresh
        assert engine.classify("finding", "2020-01-01T00:00:00+00:00", now) == FreshnessState.FRESH

    def test_expires_at_overrides_policy(self) -> None:
        engine = ObservationFreshnessEngine()
        now = "2026-08-10T00:00:00+00:00"
        assert engine.classify("port", "2026-08-10T00:00:00+00:00", now, expires_at="2026-08-09T00:00:00+00:00") == FreshnessState.EXPIRED
        assert engine.classify("port", "2026-08-10T00:00:00+00:00", now, expires_at="2026-08-11T00:00:00+00:00") == FreshnessState.FRESH

    def test_custom_policies(self) -> None:
        engine = ObservationFreshnessEngine(policies={"secret": 60})
        now = "2026-08-10T00:00:00+00:00"
        assert engine.ttl_for("secret") == 60
        assert engine.classify("secret", "2026-08-09T00:00:00+00:00", now) == FreshnessState.EXPIRED


class TestMemoryAssembly:
    def test_first_last_seen_tracking(self) -> None:
        assembler = TargetMemoryAssembler(now="2026-08-10T00:00:00+00:00")
        memory_observations = assembler.assemble(
            [
                _obs(value="80/tcp", normalized_value="80/tcp", timestamp="2026-08-01T00:00:00+00:00", mission_id="m1", source="nmap-a"),
                _obs(value="80/tcp", normalized_value="80/tcp", timestamp="2026-08-05T00:00:00+00:00", mission_id="m2", source="nmap-b"),
            ]
        )
        assert len(memory_observations) == 1
        observation = memory_observations[0]
        assert observation.observation_key == "port:80/tcp"
        assert observation.observation_count == 2
        assert observation.first_seen == "2026-08-01T00:00:00+00:00"
        assert observation.last_seen == "2026-08-05T00:00:00+00:00"
        assert observation.first_mission == "m1"
        assert observation.last_mission == "m2"
        assert observation.first_source == "nmap-a"
        assert observation.last_source == "nmap-b"

    def test_deterministic_output_ordering(self) -> None:
        assembler = TargetMemoryAssembler(now="2026-08-10T00:00:00+00:00")
        first = assembler.assemble([_obs(value="z", timestamp="2026-08-01T00:00:00+00:00"), _obs(value="a", timestamp="2026-08-01T00:00:00+00:00")])
        second = assembler.assemble([_obs(value="a", timestamp="2026-08-01T00:00:00+00:00"), _obs(value="z", timestamp="2026-08-01T00:00:00+00:00")])
        assert [obs.observation_key for obs in first] == [obs.observation_key for obs in second]

    def test_build_memory_aggregate(self) -> None:
        memory = build_memory([_obs()], now="2026-08-10T00:00:00+00:00")
        assert isinstance(memory, TargetMemory)
        assert memory.target_id == "t1"
        assert "port:80/tcp" in memory.observations


class TestSnapshotsAndDiffs:
    def _snapshot(self, state: dict[str, object], target_id: str = "t1") -> TargetSnapshot:
        return TargetSnapshot(target_id=target_id, observation_count=len(state), state=state)

    def test_snapshot_hash_is_deterministic(self) -> None:
        state = {"observations": {"port:80/tcp": {"value": "80/tcp", "last_seen": "x"}, "port:443/tcp": {"value": "443/tcp", "last_seen": "y"}}}
        a = self._snapshot(state)
        b = self._snapshot({k: v for k, v in reversed(list(state.items()))})
        assert a.state_hash == b.state_hash
        assert len(a.state_hash) == 64

    def test_diff_added_and_removed(self) -> None:
        engine = TargetDiffEngine()
        snap_a = self._snapshot({"observations": {"port:80/tcp": {"value": "80/tcp"}, "port:443/tcp": {"value": "443/tcp"}}})
        snap_b = self._snapshot({"observations": {"port:80/tcp": {"value": "80/tcp"}, "port:8080/tcp": {"value": "8080/tcp"}}})
        diff = engine.diff(snap_a, snap_b)
        kinds = {change.kind: change.key for change in diff.changes}
        assert kinds[DiffChangeKind.ADDED] == "port:8080/tcp"
        assert kinds[DiffChangeKind.REMOVED] == "port:443/tcp"
        assert diff.deterministic

    def test_diff_is_deterministic(self) -> None:
        engine = TargetDiffEngine()
        snap_a = self._snapshot({"observations": {"port:80/tcp": {"value": "80/tcp"}}})
        snap_b = self._snapshot({"observations": {"port:80/tcp": {"value": "80/tcp"}, "port:443/tcp": {"value": "443/tcp"}}})
        diff_one = engine.diff(snap_a, snap_b)
        diff_two = engine.diff(snap_a, snap_b)
        assert [change.to_dict() for change in diff_one.changes] == [change.to_dict() for change in diff_two.changes]
        assert diff_one.state_hash_a == diff_two.state_hash_a
        assert diff_one.state_hash_b == diff_two.state_hash_b

    def test_reappeared_requires_baseline(self) -> None:
        engine = TargetDiffEngine()
        baseline = self._snapshot({"observations": {"port:80/tcp": {"value": "80/tcp"}}})
        snap_a = self._snapshot({"observations": {}})
        snap_b = self._snapshot({"observations": {"port:80/tcp": {"value": "80/tcp"}}})
        diff = engine.diff(snap_a, snap_b, baseline=baseline)
        assert any(change.kind == DiffChangeKind.REAPPEARED for change in diff.changes)

    def test_disappeared_requires_baseline(self) -> None:
        engine = TargetDiffEngine()
        baseline = self._snapshot({"observations": {"port:80/tcp": {"value": "80/tcp"}}})
        snap_a = self._snapshot({"observations": {"port:80/tcp": {"value": "80/tcp"}}})
        snap_b = self._snapshot({"observations": {}})
        diff = engine.diff(snap_a, snap_b, baseline=baseline)
        assert any(change.kind == DiffChangeKind.DISAPPEARED for change in diff.changes)

    def test_finding_reopened_and_remediated(self) -> None:
        engine = TargetDiffEngine()
        snap_a = self._snapshot({"findings": {"f1": {"status": "validated", "remediation_state": "open"}}})
        snap_b = self._snapshot({"findings": {"f1": {"status": "validated", "remediation_state": "closed"}}})
        diff = engine.diff(snap_a, snap_b)
        assert any(change.kind == DiffChangeKind.REMEDIATED for change in diff.changes)


class TestChangeSignificance:
    def test_new_secret_is_critical(self) -> None:
        engine = ChangeSignificanceEngine()
        from hunterx.domain.target_memory.models import TargetChange

        change = TargetChange(key="secret:aws-key", kind=DiffChangeKind.ADDED)
        assert engine.classify(change) == ChangeSignificance.CRITICAL

    def test_new_admin_endpoint_is_high(self) -> None:
        engine = ChangeSignificanceEngine()
        from hunterx.domain.target_memory.models import TargetChange

        change = TargetChange(key="endpoint:/admin/console", kind=DiffChangeKind.ADDED)
        assert engine.classify(change) == ChangeSignificance.HIGH

    def test_new_subdomain_is_low(self) -> None:
        engine = ChangeSignificanceEngine()
        from hunterx.domain.target_memory.models import TargetChange

        change = TargetChange(key="subdomain:api.example.com", kind=DiffChangeKind.ADDED)
        assert engine.classify(change) == ChangeSignificance.LOW

    def test_significance_capped_by_confidence(self) -> None:
        engine = ChangeSignificanceEngine()
        from hunterx.domain.target_memory.models import TargetChange

        low_confidence = TargetChange(key="secret:aws-key", kind=DiffChangeKind.ADDED, confidence=0.3)
        assert engine.classify(low_confidence) == ChangeSignificance.LOW


class TestRevalidationPlanning:
    def test_prioritizes_stale_and_contradicted(self) -> None:
        memory = build_memory(
            [_obs(observation_type="secret", value="k", timestamp="2026-07-01T00:00:00+00:00")],
            now="2026-08-10T00:00:00+00:00",
        )
        for observation in memory.observations.values():
            object.__setattr__(observation, "contradiction_state", "open")
        plan = RevalidationPlanner().plan(memory, now="2026-08-10T00:00:00+00:00")
        assert plan.items
        assert plan.items[0].priority.value == "high"


class TestCoverageGaps:
    def test_discovered_untested_asset(self) -> None:
        memory = build_memory([_obs(observation_type="endpoint", value="/login", timestamp="2026-08-01T00:00:00+00:00")], now="2026-08-10T00:00:00+00:00")
        gaps = CoverageGapEngine().detect(target_id="t1", observations=list(memory.observations.values()), coverage={})
        assert any(gap.kind.value == "discovered_untested" for gap in gaps)

    def test_stale_observation_gap(self) -> None:
        memory = build_memory([_obs(timestamp="2020-01-01T00:00:00+00:00")], now="2026-08-10T00:00:00+00:00")
        gaps = CoverageGapEngine().detect(target_id="t1", observations=list(memory.observations.values()), coverage={})
        assert any(gap.kind.value == "stale_observation" for gap in gaps)


class TestFindingRecurrence:
    def test_new_location_recurrence(self) -> None:
        closed = FindingMemory(
            finding_id="f1",
            target_id="t1",
            vulnerability_class="sql_injection",
            remediation_state="closed",
            root_cause="unsafe query building",
            affected_endpoints=["/api/search"],
        )
        reopened_elsewhere = FindingMemory(
            finding_id="f2",
            target_id="t1",
            vulnerability_class="sql_injection",
            remediation_state="open",
            root_cause="unsafe query building",
            affected_endpoints=["/api/export"],
        )
        recurrences = FindingRecurrenceDetector().detect([closed, reopened_elsewhere])
        assert recurrences
        assert recurrences[0].kind == RecurrenceKind.NEW_LOCATION
        assert recurrences[0].original_finding_id == "f1"
        assert recurrences[0].new_finding_id == "f2"


class TestContradictions:
    def test_preserves_both_sides(self) -> None:
        detector = ContradictionDetector()
        contradictions = detector.detect(
            [
                _obs(observation_type="port", value="80/tcp", normalized_value="80/tcp", tool="nmap"),
                _obs(observation_type="port", value="443/tcp", normalized_value="443/tcp", tool="masscan"),
            ]
        )
        assert contradictions
        contradiction = contradictions[0]
        assert contradiction.state.value == "open"
        assert len(contradiction.observations) == 2
        assert set(contradiction.tools) == {"nmap", "masscan"}


class TestMemoryConfidence:
    def test_high_confidence_current(self) -> None:
        memory = build_memory([_obs(confidence=1.0, timestamp="2026-08-10T00:00:00+00:00")], now="2026-08-10T00:00:00+00:00")
        observation = memory.observations["port:80/tcp"]
        object.__setattr__(observation, "source_reliability", "verified")
        object.__setattr__(observation, "corroboration_count", 2)
        engine = MemoryConfidenceEngine()
        assert engine.evaluate(observation) >= 0.8
        assert not engine.is_poisoned(observation)

    def test_low_confidence_contradicted_is_poisoned(self) -> None:
        memory = build_memory([_obs(confidence=0.2)], now="2026-08-10T00:00:00+00:00")
        observation = memory.observations["port:80/tcp"]
        object.__setattr__(observation, "source_reliability", "low")
        object.__setattr__(observation, "contradiction_state", "open")
        engine = MemoryConfidenceEngine()
        assert engine.is_poisoned(observation)


class TestNextActions:
    def test_recommends_revalidation_for_stale(self) -> None:
        memory = build_memory([_obs(timestamp="2020-01-01T00:00:00+00:00")], now="2026-08-10T00:00:00+00:00")
        recommendations = NextActionRecommender().recommend(memory)
        assert any(rec.action == "revalidate" for rec in recommendations)


class TestRiskEvolution:
    def test_risk_escalates_and_never_overwrites(self) -> None:
        evaluator = TargetRiskEvaluator()
        low = evaluator.evaluate(target_id="t1", campaign_id="c1", mission_id="m1", findings=[], changes=[])
        assert low.risk_level == RiskLevel.LOW
        critical_finding = FindingMemory(finding_id="f1", target_id="t1", severity="critical", remediation_state="open")
        critical = evaluator.evaluate(
            target_id="t1",
            campaign_id="c1",
            mission_id="m2",
            findings=[critical_finding],
            changes=[],
            previous=low.risk_level,
        )
        assert critical.risk_level == RiskLevel.CRITICAL
        assert critical.previous_risk_level == RiskLevel.LOW
        # Historical low entry is untouched.
        assert low.risk_level == RiskLevel.LOW


class TestCampaign:
    def test_lifecycle(self) -> None:
        campaign = Campaign(name="C1", objective="o", scope="example.com", target_ids=["t1"])
        assert campaign.status == CampaignStatus.PLANNED
        campaign.add_mission("m1")
        campaign.add_mission("m1")
        assert campaign.mission_ids == ["m1"]
        campaign.start()
        assert campaign.status == CampaignStatus.ACTIVE
        campaign.complete()
        assert campaign.status == CampaignStatus.COMPLETED
        assert campaign.ended_at is not None

    def test_campaign_intelligence_answers(self) -> None:
        from hunterx.domain.target_memory.models import FindingRecurrence

        campaign = Campaign(campaign_id="c1", target_ids=["t1"])
        engine = CampaignIntelligenceEngine()
        intelligence = engine.analyze(
            campaign=campaign,
            findings=[
                FindingMemory(finding_id="open-1", remediation_state="open"),
                FindingMemory(finding_id="fixed-1", remediation_state="closed"),
                FindingMemory(finding_id="validated-1", first_validated="2026-08-01T00:00:00+00:00"),
            ],
            recurrences=[FindingRecurrence(target_id="t1", original_finding_id="f1", new_finding_id="f2")],
            diffs=[],
        )
        assert "open-1" in intelligence.discovered
        assert "validated-1" in intelligence.validated
        assert "fixed-1" in intelligence.fixed
        assert "f2" in intelligence.regressed


class TestHypothesisMemory:
    def test_successful_pattern_retained(self) -> None:
        memory = HypothesisMemory(
            target_id="t1",
            outcome=HypothesisOutcome.SUCCEEDED,
            hypothesis_type="sql_injection",
            vulnerability_type="sql_injection",
            technology="PostgreSQL",
            endpoint_pattern="/api/search?id=",
            validation_strategy="safe_boolean",
            tool="safe-validation",
        )
        assert memory.succeeded
        payload = memory.to_dict()
        assert payload["outcome"] == "succeeded"
        assert payload["technology"] == "PostgreSQL"
        assert payload["validation_strategy"] == "safe_boolean"
