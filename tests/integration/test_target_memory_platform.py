# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""End-to-end Target Memory & Campaign Intelligence test.

Runs the Sprint 030 acceptance scenario through the composed platform:

* MISSION 1 discovers assets/endpoints/technologies, validates a finding and
  stores memory (observations, mission memory, hypothesis memory, tool
  provenance, findings, snapshot).
* MISSION 2 loads target memory, detects changes, identifies stale
  observations and coverage gaps, prioritizes the changed attack surface,
  executes planned validation and updates memory (second snapshot + diff).
* CAMPAIGN INTELLIGENCE answers what changed, was discovered, was fixed,
  remains vulnerable/untested and what should happen next.
"""

from __future__ import annotations

from hunterx.application.target_memory import TargetMemoryQueryService, TargetMemoryService
from hunterx.domain.target_memory.enums import (
    DiffChangeKind,
    HypothesisOutcome,
)
from hunterx.domain.target_memory.models import (
    FindingMemory,
    HypothesisMemory,
    MissionMemory,
    ToolObservation,
)
from hunterx.platform import build_platform


def _obs(**overrides: object) -> dict[str, object]:
    values: dict[str, object] = {
        "target_id": "shop-1",
        "mission_id": "mission-1",
        "tool": "subfinder",
        "observation_type": "host",
        "value": "",
        "normalized_value": "",
        "asset_key": "hostname:www.shop.example",
        "source": "subfinder",
        "confidence": 1.0,
        "timestamp": "2026-08-01T00:00:00+00:00",
        "expires_at": None,
    }
    values.update(overrides)
    return values


class TestEndToEndMultiMission:
    def test_mission_to_campaign_intelligence(self) -> None:
        platform = build_platform()
        service: TargetMemoryService = platform.target_memory_service
        query: TargetMemoryQueryService = platform.target_memory_query_service
        target_id = "shop-1"

        # -- MISSION 1: recon, discover, validate, store memory ----------------
        mission_one_observations = [
            _obs(observation_type="host", value="www.shop.example", normalized_value="www.shop.example", asset_key="hostname:www.shop.example"),
            _obs(observation_type="host", value="api.shop.example", normalized_value="api.shop.example", asset_key="hostname:api.shop.example"),
            _obs(observation_type="technology", value="nginx", normalized_value="nginx", asset_key="hostname:api.shop.example", tool="whatweb"),
            _obs(observation_type="endpoint", value="https://api.shop.example/login", normalized_value="https://api.shop.example/login", asset_key="url:https://api.shop.example/login", tool="katana"),
        ]
        service.record_observations(target_id, mission_one_observations, mission_id="mission-1")
        service.record_mission_memory(
            MissionMemory(
                mission_id="mission-1",
                target_id=target_id,
                scope="shop.example",
                tools_used=["subfinder", "whatweb", "katana"],
                assets_discovered=["hostname:www.shop.example", "hostname:api.shop.example"],
                findings_discovered=["finding-sqli"],
                coverage_achieved={"asset_discovery": 1.0, "endpoint_enumeration": 0.5},
            )
        )
        service.record_hypothesis(
            HypothesisMemory(
                hypothesis_id="hyp-sqli",
                target_id=target_id,
                mission_id="mission-1",
                statement="SQL injection in login",
                hypothesis_type="sql_injection",
                outcome=HypothesisOutcome.SUCCEEDED,
                tool="safe-validation",
                validation_strategy="safe_boolean",
                evidence_pattern="boolean-based difference in responses",
            )
        )
        service.record_hypothesis(
            HypothesisMemory(
                hypothesis_id="hyp-xss",
                target_id=target_id,
                mission_id="mission-1",
                statement="XSS in search",
                hypothesis_type="xss",
                outcome=HypothesisOutcome.FAILED,
                tool="dalfox",
                evidence_observed="no reflection",
                reason="output encoded",
            )
        )
        service.record_tool_observation(
            ToolObservation(tool="subfinder", tool_version="2.6.0", execution_id="ex-m1-1", target_id=target_id, scope="shop.example", normalized_result={"hosts": ["www.shop.example", "api.shop.example"]}, evidence_refs=["evidence/ev-m1-1"])
        )
        service.record_finding(
            FindingMemory(
                finding_id="finding-sqli",
                target_id=target_id,
                mission_id="mission-1",
                title="SQL injection in login",
                vulnerability_class="sql_injection",
                severity="high",
                remediation_state="open",
                first_detected="2026-08-01T00:00:00+00:00",
                first_validated="2026-08-01T00:00:00+00:00",
                affected_endpoints=["https://api.shop.example/login"],
                root_cause="unsafe query building",
            )
        )
        snapshot_one = service.create_snapshot(target_id, mission_id="mission-1")

        # Memory knows what mission 1 discovered.
        memory_one = query.memory(target_id)
        assert len(memory_one.observations) == 4
        assert "host:www.shop.example" in memory_one.observations
        assert len(query.finding_history(target_id)) == 1
        assert query.hypothesis_history(target_id, outcome="succeeded")
        assert query.hypothesis_history(target_id, outcome="failed")

        # -- MISSION 2: load memory, detect changes, revalidate, update ---------
        service.record_observations(
            target_id,
            [
                _obs(observation_type="host", value="admin.shop.example", normalized_value="admin.shop.example", asset_key="hostname:admin.shop.example", mission_id="mission-2", timestamp="2026-08-05T00:00:00+00:00"),
                _obs(observation_type="endpoint", value="https://admin.shop.example/console", normalized_value="https://admin.shop.example/console", asset_key="url:https://admin.shop.example/console", mission_id="mission-2", timestamp="2026-08-05T00:00:00+00:00", tool="katana"),
            ],
            mission_id="mission-2",
        )
        snapshot_two = service.create_snapshot(target_id, mission_id="mission-2")
        diff = service.diff_snapshots(snapshot_one.snapshot_id, snapshot_two.snapshot_id)
        added_keys = {change.key for change in diff.changes if change.kind == DiffChangeKind.ADDED}
        removed_keys = {change.key for change in diff.changes if change.kind == DiffChangeKind.REMOVED}
        assert "endpoint:https://admin.shop.example/console" in added_keys
        assert any("admin.shop.example" in key for key in added_keys)
        assert "technology:nginx" in removed_keys or "host:www.shop.example" in removed_keys

        # Stale observations identified and prioritized for revalidation.
        revalidation = service.build_revalidation_plan(target_id)
        assert revalidation.items

        # Coverage gaps surfaced.
        gaps = service.detect_coverage_gaps(target_id)
        assert any(gap.kind.value == "discovered_untested" for gap in gaps)

        # The failed hypothesis is remembered so it is not blindly re-tested.
        failed = query.hypothesis_history(target_id, outcome="failed")
        assert failed and failed[0].hypothesis_id == "hyp-xss"
        assert "no reflection" in failed[0].evidence_observed

        # Next-action recommendations are advisory and reference memory.
        recommendations = service.recommend(target_id)
        assert recommendations
        assert all(rec.target_id == target_id for rec in recommendations)

        # -- CAMPAIGN INTELLIGENCE ----------------------------------------------
        campaign = service.create_campaign(
            name="Shop Q3 Assessment",
            objective="assess shop.example",
            scope="shop.example",
            target_ids=[target_id],
        )
        campaign.add_mission("mission-1")
        campaign.add_mission("mission-2")
        service.update_campaign(campaign)
        intelligence = query.campaign_intelligence(campaign.campaign_id)
        assert intelligence.changed  # diff changes surfaced
        assert "finding-sqli" in intelligence.validated
        assert "hyp-xss" in intelligence.failed
        assert intelligence.next or intelligence.untested
        assert campaign.campaign_id in {c.campaign_id for c in query.campaigns()}

        # Risk history reflects the high-severity open finding.
        service.evaluate_risk(target_id=target_id, campaign_id=campaign.campaign_id, mission_id="mission-2")
        risk_history = query.risk_history(target_id)
        assert risk_history and risk_history[-1].risk_level.value == "high"

        # The planner receives a memory-aware context, never raw data.
        context = service.build_planner_context(target_id, failed_hypotheses=[failed[0].hypothesis_id])
        assert context.to_dict()["target_id"] == target_id

    def test_platform_resolves_memory_services(self) -> None:
        platform = build_platform()
        assert platform.target_memory_service is not None
        assert platform.target_memory_query_service is not None
        assert platform.resolve(platform.target_memory_service.__class__) is platform.target_memory_service
