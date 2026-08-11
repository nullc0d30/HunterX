# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Acceptance tests for the Adaptive Mission & Attack-Path Planning engine.

The golden end-to-end test (Sprint 027 §50) drives a controlled synthetic
target through the assembled platform: create mission → establish scope →
initial plan → discovery actions → observations → graph update → information
gaps → plan revision → hypothesis validation → tool-capability selection →
proof requirements → minimal safe proof → finding state → attack-path
reassessment → final plan delta → report-ready evidence. The exact sequence of
tools is NOT hardcoded — it emerges from the plan.
"""

from __future__ import annotations

from hunterx.domain.adaptive_mission_planning.enums import (
    MissionObjective,
    MissionState,
    ReplanTrigger,
)
from hunterx.domain.adaptive_mission_planning.models import Gap
from hunterx.platform.assembler import build_platform


def _surface(mission_id: str):
    """Controlled synthetic target: minimal starting information."""
    from hunterx.domain.target_intelligence.graph import AttackSurfaceGraph
    from hunterx.domain.target_intelligence.models import IntelligenceAsset
    from hunterx.domain.topology.enums import EntityKind

    surface = AttackSurfaceGraph()
    assets = [
        IntelligenceAsset(
            asset_id="url-1",
            target_id="t1",
            mission_id=mission_id,
            kind=EntityKind.URL,
            name="http://demo.example.com",
            key="url:http://demo.example.com",
            label="Demo app",
            in_scope=True,
            source="seed",
        ),
        IntelligenceAsset(
            asset_id="host-1",
            target_id="t1",
            mission_id=mission_id,
            kind=EntityKind.HOSTNAME,
            name="demo.example.com",
            key="hostname:demo.example.com",
            label="Demo host",
            in_scope=True,
            source="seed",
        ),
        IntelligenceAsset(
            asset_id="ip-1",
            target_id="t1",
            mission_id=mission_id,
            kind=EntityKind.IP,
            name="203.0.113.20",
            key="ip:203.0.113.20",
            label="Demo ip",
            in_scope=True,
            source="seed",
        ),
    ]
    for asset in assets:
        surface.upsert_asset(asset)
    return surface


def test_golden_end_to_end_adaptive_mission() -> None:
    platform = build_platform()
    service = platform.adaptive_mission_planning_service

    # 1. create mission, 2. establish scope, 3. initial plan
    mission = service.create_mission(
        objective=MissionObjective.WEB_SECURITY_ASSESSMENT,
        target="demo.example.com",
        included_targets=("demo.example.com",),
        authorization_context="validation",
        safety_ceiling="controlled",
    )
    assert mission.state is MissionState.SCOPING
    assert mission.plan_version == 1
    assert service.graph(mission.mission_id)

    # 4. execute authorized discovery actions (deterministic plan expansion)
    service.transition(mission.mission_id, MissionState.DISCOVERY)

    # 5-6. ingest observations -> update target graph (via attack-surface graph)
    surface = _surface(mission.mission_id)
    paths = service.discover_attack_paths(mission.mission_id, surface)
    assert isinstance(paths, list)

    # 7. identify information gaps -> 8. revise plan (replan on new endpoint)
    delta = service.replan(
        mission.mission_id,
        trigger=ReplanTrigger.NEW_ENDPOINT_DISCOVERED,
        asset_key="url:http://demo.example.com/login",
        reason="login endpoint discovered",
    )
    assert delta.plan_version == 2
    assert not delta.is_empty()

    # 9-10. discover application surface -> generate hypotheses
    result = service.candidate_actions(mission.mission_id)
    assert result.proposals
    scheduled = service.propose_actions(mission.mission_id, result)
    assert scheduled

    # 11. prioritize validation; 12. select appropriate tool capability
    action_id = scheduled[0].action.action_id
    selection = service.select_tool(mission.mission_id, action_id)
    assert selection.action_id == action_id

    # 13. validate findings -> 14. identify proof requirements
    proof_gap = platform.adaptive_mission_planning.record_gap(
        mission.mission_id,
        Gap(
            mission_id=mission.mission_id,
            finding_id="finding-1",
            kind="proof_gap",
            asset_key="url:http://demo.example.com/login",
            required_evidence=("proof_replay",),
            minimum_action="replay_proof",
            priority=0.9,
        ),
    )
    assert service.proof_gaps(mission.mission_id)
    assert proof_gap is not None

    # 15. collect minimal safe proof -> 16. update finding state
    proof_result = service.candidate_actions(
        mission.mission_id,
        hypotheses=(_hypothesis("ssrf", 0.9),),
        ai_assisted=False,
    )
    assert proof_result.proposals

    # 17. reassess attack paths
    service.reassess_paths(
        mission.mission_id,
        evidence_map={"url:http://demo.example.com": ["ev-1"]},
        validated_map={"url:http://demo.example.com": True},
        proved_map={},
    )
    service.transition(mission.mission_id, MissionState.REASSESSMENT)

    # 18. generate final plan delta
    final_delta = service.replan(
        mission.mission_id,
        trigger=ReplanTrigger.PROOF_FAILED,
        asset_key="url:http://demo.example.com/login",
        reason="proof not yet replayable; revalidate",
    )
    assert final_delta.plan_version == 3

    # 19. produce report-ready evidence (explainable decisions + coverage)
    explanation = service.explain_next(mission.mission_id)
    assert "action_id" in explanation or "explanation" in explanation
    coverage = service.coverage(mission.mission_id)
    assert coverage["action_count"] > 0

    # The exact tool sequence is never hardcoded: it emerges from the plan.
    actions = service.graph(mission.mission_id)
    assert actions


def test_scope_restriction_blocks_action_during_e2e() -> None:
    platform = build_platform()
    service = platform.adaptive_mission_planning_service
    mission = service.create_mission(
        objective="pentest_assessment",
        target="demo.example.com",
        included_targets=("demo.example.com",),
        excluded_capabilities=("port_discovery",),
    )
    service.replan(
        mission.mission_id,
        trigger=ReplanTrigger.SCOPE_CHANGED,
        detail={"excluded_assets": ["demo.example.com"]},
        reason="operator narrowed scope",
    )
    result = service.candidate_actions(mission.mission_id)
    for proposal in result.proposals:
        assert proposal.action.asset not in ("demo.example.com",)


def _hypothesis(hypothesis_type: str, confidence: float) -> object:
    class _Hypothesis:
        def __init__(self, htype: str, conf: float) -> None:
            self.hypothesis_id = "h-ssrf"
            self.asset_key = "url:http://demo.example.com/login"
            self.confidence = conf
            self.statement = "suspected SSRF"
            self.category = htype

    return _Hypothesis(hypothesis_type, confidence)
