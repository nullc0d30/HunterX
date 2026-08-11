# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Golden datasets for Target Memory & Campaign Intelligence.

Sprint 030 requires that memory correctly classifies the canonical scenarios:
new asset, removed asset, changed IP, new/removed endpoint, technology change,
new/remediated vulnerability, regression, failed/successful hypothesis,
contradictory tool output, stale observation, coverage gap, attack-path change
and cloud resource change.

Each scenario records observations via the application service and asserts the
resulting memory classification and derived intelligence.
"""

from __future__ import annotations

from hunterx.application.target_memory import TargetMemoryQueryService, TargetMemoryService
from hunterx.domain.target_memory.enums import (
    ChangeSignificance,
    DiffChangeKind,
    HypothesisOutcome,
    MemoryObservationState,
)
from hunterx.domain.target_memory.models import (
    AttackPathMemory,
    FindingMemory,
    HypothesisMemory,
    MissionMemory,
    ToolObservation,
)
from hunterx.infrastructure.db.sql.memory import InMemoryTidbRepositoryFactory

NOW = "2026-08-10T00:00:00+00:00"
M1 = "2026-08-01T00:00:00+00:00"
M2 = "2026-08-05T00:00:00+00:00"


def _obs(**overrides: object) -> dict[str, object]:
    values: dict[str, object] = {
        "target_id": "t1",
        "mission_id": "m1",
        "tool": "nmap",
        "observation_type": "asset",
        "value": "",
        "normalized_value": "",
        "asset_key": "hostname:www.example.com",
        "source": "golden-parser",
        "confidence": 1.0,
        "timestamp": M1,
        "expires_at": None,
    }
    values.update(overrides)
    return values


class _GoldenHarness:
    def __init__(self) -> None:
        self.stores = InMemoryTidbRepositoryFactory()
        self.service = TargetMemoryService(stores=self.stores, tenant="tenant-a", now=NOW)
        self.query = TargetMemoryQueryService(stores=self.stores)
        self.service.authorize(tenant="tenant-a", target_id="t1")
        self._snapshots: list[str] = []

    def observe(self, observations: list[dict[str, object]], *, mission_id: str = "m1") -> None:
        for observation in observations:
            observation["mission_id"] = mission_id
        self.service.record_observations("t1", observations, mission_id=mission_id, tenant="tenant-a")

    def snapshot(self, *, mission_id: str = "m1") -> str:
        snapshot = self.service.create_snapshot("t1", mission_id=mission_id, tenant="tenant-a")
        self._snapshots.append(snapshot.snapshot_id)
        return snapshot.snapshot_id


def _host_asset(host: str) -> dict[str, object]:
    return _obs(observation_type="asset", value=host, normalized_value=host, asset_key=f"hostname:{host}")


class TestGoldenNewAsset:
    def test_new_asset_is_tracked_and_diffed(self) -> None:
        harness = _GoldenHarness()
        snap_a = harness.snapshot()
        harness.observe([_host_asset("api.example.com")], mission_id="m2")
        snap_b = harness.snapshot(mission_id="m2")
        diff = harness.service.diff_snapshots(snap_a, snap_b, tenant="tenant-a")
        added = [c for c in diff.changes if c.kind == DiffChangeKind.ADDED]
        assert any("api.example.com" in change.key for change in added)


class TestGoldenRemovedAsset:
    def test_removed_asset_is_tracked(self) -> None:
        harness = _GoldenHarness()
        harness.observe([_host_asset("old.example.com")])
        snap_a = harness.snapshot()
        harness.observe([_host_asset("new.example.com")], mission_id="m2")
        snap_b = harness.snapshot(mission_id="m2")
        diff = harness.service.diff_snapshots(snap_a, snap_b, tenant="tenant-a")
        assert any(change.kind == DiffChangeKind.REMOVED and "old.example.com" in change.key for change in diff.changes)


class TestGoldenChangedIp:
    def test_ip_change_is_detected(self) -> None:
        harness = _GoldenHarness()
        harness.observe([_obs(observation_type="host", value="1.2.3.4", normalized_value="1.2.3.4", asset_key="hostname:www.example.com")])
        snap_a = harness.snapshot()
        harness.observe([_obs(observation_type="host", value="5.6.7.8", normalized_value="5.6.7.8", asset_key="hostname:www.example.com", timestamp=M2)], mission_id="m2")
        snap_b = harness.snapshot(mission_id="m2")
        diff = harness.service.diff_snapshots(snap_a, snap_b, tenant="tenant-a")
        changed = [c for c in diff.changes if c.kind == DiffChangeKind.ADDED]
        assert any("5.6.7.8" in c.key for c in changed)


class TestGoldenEndpoints:
    def test_new_and_removed_endpoint(self) -> None:
        harness = _GoldenHarness()
        harness.observe([_obs(observation_type="endpoint", value="/old", normalized_value="/old", asset_key="url:https://www.example.com/old")])
        snap_a = harness.snapshot()
        harness.observe(
            [_obs(observation_type="endpoint", value="/admin/console", normalized_value="/admin/console", asset_key="url:https://www.example.com/admin/console", timestamp=M2)],
            mission_id="m2",
        )
        snap_b = harness.snapshot(mission_id="m2")
        diff = harness.service.diff_snapshots(snap_a, snap_b, tenant="tenant-a")
        kinds = {change.kind: change.key for change in diff.changes}
        assert kinds[DiffChangeKind.REMOVED] == "endpoint:/old"
        assert kinds[DiffChangeKind.ADDED] == "endpoint:/admin/console"
        # New admin endpoint is HIGH significance.
        added = next(c for c in diff.changes if c.kind == DiffChangeKind.ADDED)
        assert added.significance == ChangeSignificance.HIGH


class TestGoldenTechnologyChange:
    def test_technology_change_is_detected(self) -> None:
        harness = _GoldenHarness()
        harness.observe([_obs(observation_type="technology", value="nginx", normalized_value="nginx", asset_key="hostname:www.example.com")])
        snap_a = harness.snapshot()
        harness.observe(
            [_obs(observation_type="technology", value="apache", normalized_value="apache", asset_key="hostname:www.example.com", timestamp=M2)],
            mission_id="m2",
        )
        snap_b = harness.snapshot(mission_id="m2")
        diff = harness.service.diff_snapshots(snap_a, snap_b, tenant="tenant-a")
        assert any("apache" in c.key for c in diff.changes)


class TestGoldenVulnerabilityLifecycle:
    def test_new_and_remediated_vulnerability(self) -> None:
        harness = _GoldenHarness()
        harness.service.record_finding(
            FindingMemory(finding_id="f1", target_id="t1", severity="high", remediation_state="open", vulnerability_class="sql_injection"),
            tenant="tenant-a",
        )
        snap_a = harness.snapshot()
        harness.service.record_finding(
            FindingMemory(finding_id="f1", target_id="t1", severity="high", remediation_state="closed", vulnerability_class="sql_injection"),
            tenant="tenant-a",
        )
        snap_b = harness.snapshot(mission_id="m2")
        diff = harness.service.diff_snapshots(snap_a, snap_b, tenant="tenant-a")
        assert any(change.kind == DiffChangeKind.REMEDIATED for change in diff.changes)

    def test_regression_detected_via_recurrence(self) -> None:
        harness = _GoldenHarness()
        harness.service.record_finding(
            FindingMemory(finding_id="f1", target_id="t1", vulnerability_class="sql_injection", remediation_state="closed", root_cause="unsafe query", affected_endpoints=["/api/search"]),
            tenant="tenant-a",
        )
        harness.service.record_finding(
            FindingMemory(finding_id="f2", target_id="t1", vulnerability_class="sql_injection", remediation_state="open", root_cause="unsafe query", affected_endpoints=["/api/export"]),
            tenant="tenant-a",
        )
        recurrences = harness.service.detect_recurrences("t1", tenant="tenant-a")
        assert recurrences
        assert recurrences[0].new_finding_id == "f2"


class TestGoldenHypotheses:
    def test_failed_hypothesis_is_remembered(self) -> None:
        harness = _GoldenHarness()
        harness.service.record_hypothesis(
            HypothesisMemory(
                hypothesis_id="h-fail",
                target_id="t1",
                statement="XSS in search",
                hypothesis_type="xss",
                outcome=HypothesisOutcome.FAILED,
                tool="dalfox",
                evidence_observed="no reflection",
                reason="output encoded; no payload reflected",
                tenant="tenant-a",
            ),
            tenant="tenant-a",
        )
        history = harness.query.hypothesis_history("t1")
        assert len(history) == 1
        assert history[0].outcome == HypothesisOutcome.FAILED

    def test_successful_hypothesis_retains_pattern(self) -> None:
        harness = _GoldenHarness()
        harness.service.record_hypothesis(
            HypothesisMemory(
                hypothesis_id="h-ok",
                target_id="t1",
                statement="SQLi in search",
                hypothesis_type="sql_injection",
                outcome=HypothesisOutcome.SUCCEEDED,
                tool="safe-validation",
                validation_strategy="safe_boolean",
                technology="PostgreSQL",
                endpoint_pattern="/api/search?id=",
                tenant="tenant-a",
            ),
            tenant="tenant-a",
        )
        history = harness.query.hypothesis_history("t1", outcome="succeeded")
        assert history
        assert history[0].technology == "PostgreSQL"


class TestGoldenContradictions:
    def test_contradictory_tool_output_preserved(self) -> None:
        harness = _GoldenHarness()
        contradictions = harness.service.detect_contradictions(
            "t1",
            [
                _obs(observation_type="port", value="80/open", normalized_value="80/open", tool="nmap"),
                _obs(observation_type="port", value="80/closed", normalized_value="80/closed", tool="masscan"),
            ],
            tenant="tenant-a",
        )
        assert contradictions
        stored = harness.query.contradictions("t1")
        assert stored
        assert len(stored[0].observations) == 2


class TestGoldenStaleObservation:
    def test_stale_observation_flagged(self) -> None:
        harness = _GoldenHarness()
        harness.observe([_obs(observation_type="dns_record", value="www.example.com", normalized_value="www.example.com", timestamp="2020-01-01T00:00:00+00:00")])
        memory = harness.query.memory("t1")
        observation = memory.observations["dns_record:www.example.com"]
        assert observation.current_state == MemoryObservationState.NEEDS_REVALIDATION
        plan = harness.service.build_revalidation_plan("t1", tenant="tenant-a")
        assert plan.items
        assert any(item.observation_key == observation.observation_key for item in plan.items)


class TestGoldenCoverageGap:
    def test_coverage_gap_detected(self) -> None:
        harness = _GoldenHarness()
        harness.observe([_obs(observation_type="endpoint", value="/login", normalized_value="/login", asset_key="url:https://www.example.com/login")])
        gaps = harness.service.detect_coverage_gaps("t1", tenant="tenant-a")
        assert gaps
        assert any(gap.kind.value == "discovered_untested" for gap in gaps)


class TestGoldenAttackPath:
    def test_attack_path_memory_and_change(self) -> None:
        harness = _GoldenHarness()
        harness.service.record_mission_memory(MissionMemory(mission_id="m1", target_id="t1", scope="example.com"), tenant="tenant-a")
        first = AttackPathMemory(path_id="p1", target_id="t1", nodes=["n1", "n2"], confidence=0.6, status="theoretical", first_seen=M1, last_seen=M1, tenant="tenant-a")
        from hunterx.application.target_memory import _attack_path_to_record

        harness.stores.repository_for(type(_attack_path_to_record(first))).save(_attack_path_to_record(first))
        assert harness.query.attack_paths("t1")
        assert not harness.query.attack_paths("t9")


class TestGoldenCloudResource:
    def test_cloud_resource_change(self) -> None:
        harness = _GoldenHarness()
        harness.observe([_obs(observation_type="cloud_resource", value="s3://bucket-a", normalized_value="s3://bucket-a", asset_key="cloud_resource:s3://bucket-a")])
        snap_a = harness.snapshot()
        harness.observe(
            [_obs(observation_type="cloud_resource", value="s3://bucket-b", normalized_value="s3://bucket-b", asset_key="cloud_resource:s3://bucket-b", timestamp=M2)],
            mission_id="m2",
        )
        snap_b = harness.snapshot(mission_id="m2")
        diff = harness.service.diff_snapshots(snap_a, snap_b, tenant="tenant-a")
        assert any("bucket-b" in c.key for c in diff.changes)


class TestGoldenToolProvenance:
    def test_tool_observation_provenance(self) -> None:
        harness = _GoldenHarness()
        harness.service.record_tool_observation(
            ToolObservation(tool="nmap", tool_version="7.94", execution_id="ex-1", target_id="t1", normalized_result={"hosts": ["www.example.com"]}, evidence_refs=["evidence/ev-1"], tenant="tenant-a"),
            tenant="tenant-a",
        )
        records = harness.query.tool_observations("t1", tool="nmap")
        assert records
        assert records[0].tool_version == "7.94"
        assert records[0].execution_id == "ex-1"
