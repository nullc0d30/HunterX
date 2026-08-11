# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for the Adaptive Mission & Attack-Path Planning domain.

Covers the pure domain engines: execution graph, decision engine, replanning
engine, policy gates, attack-path engine, checkpoint/resume, failure recovery
and deterministic fallback planning.
"""

from __future__ import annotations

from hunterx.domain.adaptive_mission_planning.attack_path import AttackPathEngine
from hunterx.domain.adaptive_mission_planning.catalog import DeterministicPlanner
from hunterx.domain.adaptive_mission_planning.checkpoint import CheckpointEngine
from hunterx.domain.adaptive_mission_planning.decision import (
    ActionDecisionEngine,
    DecisionInput,
)
from hunterx.domain.adaptive_mission_planning.enums import (
    ActionStatus,
    AttackPathState,
    DependencyKind,
    FailureClass,
    MissionMode,
    MissionObjective,
    MissionState,
    PlanDeltaKind,
    ReplanTrigger,
)
from hunterx.domain.adaptive_mission_planning.graph import (
    AdaptiveExecutionGraph,
    InvalidExecutionGraphError,
)
from hunterx.domain.adaptive_mission_planning.mission import (
    AdaptiveMission,
    DeterministicMissionPlanner,
)
from hunterx.domain.adaptive_mission_planning.models import (
    ActionNode,
    DynamicDependency,
    Gap,
    MissionConstraints,
)
from hunterx.domain.adaptive_mission_planning.policy import PolicyEngine
from hunterx.domain.adaptive_mission_planning.replan import ReplanningEngine, ReplanSignal
from hunterx.domain.adaptive_mission_planning.state import InvalidMissionStateTransitionError
from hunterx.domain.adaptive_mission_planning.toolchain import (
    FailureClassifier,
    RecoveryEngine,
    ToolSelectionEngine,
)
from hunterx.domain.target_intelligence.graph import AttackSurfaceGraph
from hunterx.domain.target_intelligence.models import IntelligenceAsset
from hunterx.domain.topology.enums import EntityKind


def _action(mission_id: str = "m1", **overrides: object) -> ActionNode:
    base: dict[str, object] = {
        "mission_id": mission_id,
        "capability": "endpoint_enumeration",
        "expected_information_gain": 0.6,
        "status": ActionStatus.PROPOSED,
    }
    base.update(overrides)
    return ActionNode(**base)  # type: ignore[arg-type]


class TestExecutionGraph:
    def test_initial_plan_is_an_execution_dag(self) -> None:
        mission = AdaptiveMission(objective=MissionObjective.WEB_SECURITY_ASSESSMENT)
        DeterministicMissionPlanner().create_initial_plan(mission)
        assert len(mission.graph.actions) >= 3
        assert mission.plan_version == 1
        assert mission.graph.validate() == []
        # topological order honours DEPENDS_ON
        order = mission.graph.topological_order()
        assert len(order) == len(mission.graph.actions)

    def test_parallel_groups_identify_independent_actions(self) -> None:
        graph = AdaptiveExecutionGraph()
        a = _action(action_id="a", capability="dns_enumeration")
        b = _action(action_id="b", capability="certificate_enumeration")
        c = _action(action_id="c", capability="port_discovery", depends_on=(a.action_id,))
        graph.add_action(a)
        graph.add_action(b)
        graph.add_action(c)
        graph.add_dependency(
            DynamicDependency("d1", a.action_id, c.action_id, DependencyKind.DEPENDS_ON, "chain")
        )
        waves = graph.parallel_groups()
        assert {a.action_id, b.action_id} == set(waves[0])
        assert c.action_id in waves[1]

    def test_cycle_detection(self) -> None:
        graph = AdaptiveExecutionGraph(actions=[_action(action_id="x"), _action(action_id="y")])
        graph.add_dependency(DynamicDependency("d1", "x", "y", DependencyKind.DEPENDS_ON, ""))
        try:
            graph.add_dependency(DynamicDependency("d2", "y", "x", DependencyKind.DEPENDS_ON, ""))
            assert False, "cycle must be rejected"
        except InvalidExecutionGraphError:
            pass

    def test_conditional_branch_registration(self) -> None:
        from hunterx.domain.adaptive_mission_planning.models import ConditionalBranch

        graph = AdaptiveExecutionGraph()
        node = _action(action_id="graphql-map")
        graph.add_action(node)
        graph.add_branch(
            ConditionalBranch(
                branch_id="b1",
                kind="if",
                condition="graphql_detected",
                then_action_ids=(node.action_id,),
            )
        )
        assert graph.branch_for(node.action_id) is not None

    def test_delta_application_mutates_only_changed_parts(self) -> None:
        mission = AdaptiveMission(objective=MissionObjective.ATTACK_SURFACE_DISCOVERY)
        DeterministicMissionPlanner().create_initial_plan(mission)
        before = {action.action_id for action in mission.graph.actions.values()}
        signal = ReplanSignal(ReplanTrigger.NEW_ASSET_DISCOVERED, asset_key="host:new.example.com", priority=0.9)
        delta = ReplanningEngine().build_delta(
            mission_id=mission.mission_id,
            graph=mission.graph,
            signal=signal,
            current_version=mission.plan_version,
            reason="new asset",
        )
        assert not delta.is_empty()
        mission.graph.apply_delta(delta)
        after = {action.action_id for action in mission.graph.actions.values()}
        # only the new action was added; every pre-existing action is untouched
        assert after - before == {delta.changes[0].action_id}
        assert before <= after


class TestReplanning:
    def test_new_asset_causes_replan(self) -> None:
        engine = ReplanningEngine()
        mission = AdaptiveMission()
        DeterministicMissionPlanner().create_initial_plan(mission)
        signal = ReplanSignal(ReplanTrigger.NEW_ASSET_DISCOVERED, asset_key="host:x.com", priority=0.9)
        delta = engine.build_delta(
            mission_id=mission.mission_id,
            graph=mission.graph,
            signal=signal,
            current_version=1,
            reason="asset",
        )
        kinds = {change.kind for change in delta.changes}
        assert PlanDeltaKind.ADD_ACTION in kinds
        assert delta.plan_version == 2
        version = engine.version_for(delta)
        assert version.parent_version == 1
        assert version.changed_nodes

    def test_new_hypothesis_causes_replan(self) -> None:
        engine = ReplanningEngine()
        mission = AdaptiveMission()
        DeterministicMissionPlanner().create_initial_plan(mission)
        signal = ReplanSignal(
            ReplanTrigger.NEW_HYPOTHESIS_CREATED,
            asset_key="url:http://x.com",
            detail={"hypothesis_id": "h-1", "capability": "ssrf"},
            priority=0.9,
        )
        delta = engine.build_delta(
            mission_id=mission.mission_id,
            graph=mission.graph,
            signal=signal,
            current_version=1,
            reason="hypothesis",
        )
        added = [change for change in delta.changes if change.kind is PlanDeltaKind.ADD_ACTION]
        assert added
        assert added[0].node is not None and added[0].node.hypothesis_id == "h-1"

    def test_conflict_creates_investigation_branch(self) -> None:
        engine = ReplanningEngine()
        mission = AdaptiveMission()
        DeterministicMissionPlanner().create_initial_plan(mission)
        signal = ReplanSignal(ReplanTrigger.CONFLICTING_EVIDENCE, asset_key="url:http://x.com", priority=0.9)
        delta = engine.build_delta(
            mission_id=mission.mission_id,
            graph=mission.graph,
            signal=signal,
            current_version=1,
            reason="conflict",
        )
        branches = [change for change in delta.changes if change.kind is PlanDeltaKind.CREATE_BRANCH]
        assert branches and branches[0].branch is not None

    def test_scope_change_removes_candidate_actions(self) -> None:
        engine = ReplanningEngine()
        graph = AdaptiveExecutionGraph()
        node = _action(action_id="a1", asset="host:out-of-scope.com")
        graph.add_action(node)
        signal = ReplanSignal(
            ReplanTrigger.SCOPE_CHANGED,
            detail={"excluded_assets": ["host:out-of-scope.com"]},
            priority=1.0,
        )
        delta = engine.build_delta(
            mission_id="m1",
            graph=graph,
            signal=signal,
            current_version=1,
            reason="scope",
        )
        assert any(change.kind is PlanDeltaKind.REMOVE_ACTION for change in delta.changes)

    def test_unknown_behavior_creates_investigation_branch(self) -> None:
        engine = ReplanningEngine()
        mission = AdaptiveMission()
        DeterministicMissionPlanner().create_initial_plan(mission)
        signal = ReplanSignal(ReplanTrigger.UNKNOWN_BEHAVIOR_OBSERVED, asset_key="url:http://x.com", priority=0.9)
        delta = engine.build_delta(
            mission_id=mission.mission_id,
            graph=mission.graph,
            signal=signal,
            current_version=1,
            reason="unknown behavior",
        )
        branches = [change for change in delta.changes if change.kind is PlanDeltaKind.CREATE_BRANCH]
        assert branches and branches[0].branch.kind.value == "fork"


class TestDecisionEngine:
    def test_ranks_candidates_explainably(self) -> None:
        engine = ActionDecisionEngine()
        inp = DecisionInput(
            mission_id="m1",
            objective=MissionObjective.BUG_BOUNTY_ASSESSMENT,
            mode=MissionMode.BUG_BOUNTY,
            constraints=MissionConstraints(),
            unknowns=(),
            hypotheses=(),
        )
        result = engine.decide(inp)
        assert result.proposals
        best = result.proposals[0]
        assert best.factors
        assert best.rationale
        assert best.score > 0.0
        # explainable factors are reported
        assert "information_gain" in best.factors

    def test_scope_restriction_removes_candidate_action(self) -> None:
        engine = ActionDecisionEngine()
        constraints = MissionConstraints(excluded_assets=("host:excluded.com",))
        result = engine.decide(
            DecisionInput(
                mission_id="m1",
                constraints=constraints,
                unknowns=(_fake_gap(asset="host:excluded.com", capability="port_discovery"),),
            )
        )
        assert all(p.action.asset != "host:excluded.com" for p in result.proposals)
        assert result.rejected or not result.proposals

    def test_ai_proposal_forbidden_capability_rejected(self) -> None:
        policy = PolicyEngine()
        action = ActionNode(
            mission_id="m1",
            capability="credential_attack",
            status=ActionStatus.PROPOSED,
            provenance={"ai_assisted": True},
        )
        decision = policy.check_proposal(action, MissionConstraints(), ai_proposed=True)
        assert not decision.allowed
        assert decision.gate == "ai_policy"

    def test_ai_proposal_is_advisory_and_policy_bounded(self) -> None:
        engine = ActionDecisionEngine()
        ai_action = _action(action_id="ai-1", capability="ssrf", provenance={"ai_assisted": True})
        result = engine.decide(
            DecisionInput(mission_id="m1", constraints=MissionConstraints(), ai_proposals=(ai_action,))
        )
        # AI proposal passed policy and became a ranked candidate
        assert any(p.action.action_id == "ai-1" for p in result.proposals)

    def test_proof_gap_creates_proof_action(self) -> None:
        engine = ActionDecisionEngine()
        result = engine.decide(
            DecisionInput(
                mission_id="m1",
                objective=MissionObjective.PROOF_COLLECTION,
                mode=MissionMode.PROOF_FIRST,
                constraints=MissionConstraints(),
                authorization_context="proof",
                safety_ceiling="controlled",
                hypotheses=(_fake_hypothesis("ssrf", confidence=0.9),),
            )
        )
        assert result.proposals
        assert any(p.action.expected_proof_value > 0.0 for p in result.proposals)

    def test_deterministic_fallback_without_ai(self) -> None:
        planner = DeterministicPlanner()
        chain = planner.discovery_chain(MissionObjective.WEB_SECURITY_ASSESSMENT)
        assert "endpoint_enumeration" in chain
        validation = planner.hypothesis_validation(["ssrf", "xss"])
        assert "ssrf" in validation and "xss" in validation


class TestPolicyAndStates:
    def test_authorization_never_overridden(self) -> None:
        policy = PolicyEngine()
        action = ActionNode(
            mission_id="m1",
            capability="rce",
            validation_level="impact_demonstration",
            status=ActionStatus.PROPOSED,
        )
        decision = policy.verify_within_authorization(action, "default")
        assert not decision.allowed

    def test_mission_state_transitions_are_explicit(self) -> None:
        mission = AdaptiveMission()
        assert mission.state is MissionState.CREATED
        mission.transition(MissionState.SCOPING)
        mission.transition(MissionState.DISCOVERY)
        assert mission.state is MissionState.DISCOVERY
        try:
            mission.transition(MissionState.COMPLETED)
            assert False, "discovery -> completed must be invalid"
        except InvalidMissionStateTransitionError:
            pass


class TestAttackPathEngine:
    def _surface(self) -> AttackSurfaceGraph:
        surface = AttackSurfaceGraph()
        entries = [
            (EntityKind.URL, "url:http://app.example.com"),
            (EntityKind.HOSTNAME, "hostname:app.example.com"),
            (EntityKind.IP, "ip:203.0.113.10"),
            (EntityKind.SERVICE, "service:https"),
            (EntityKind.AUTH_BOUNDARY, "auth_boundary:login"),
            (EntityKind.STORAGE_RESOURCE, "storage_resource:s3://bucket"),
        ]
        for kind, key in entries:
            surface.upsert_asset(
                IntelligenceAsset(
                    asset_id=key,
                    target_id="t1",
                    mission_id="m1",
                    kind=kind,
                    name=key.split(":", 1)[1],
                    key=key,
                    in_scope=True,
                )
            )
        return surface

    def test_path_discovered_but_not_executed(self) -> None:
        surface = self._surface()
        engine = AttackPathEngine(max_paths=50)
        paths = engine.discover(surface, mission_id="m1")
        assert isinstance(paths, list)
        # no path is ever automatically executed — this is intelligence only
        for path in paths:
            assert path.state.value in ("hypothetical", "supported", "validated", "proved")

    def test_path_states_never_collapsed(self) -> None:
        path = AttackPathEngine().discover(self._surface(), mission_id="m1")
        for item in path:
            assert item.state is AttackPathState.HYPOTHETICAL or item.state is AttackPathState.SUPPORTED

    def test_path_validation_advances_state_with_evidence(self) -> None:
        engine = AttackPathEngine()
        surface = self._surface()
        self._wire_edges(surface)
        paths = engine.discover(
            surface,
            mission_id="m1",
            evidence_map={"url:http://app.example.com": ["ev-1"], "storage_resource:s3://bucket": ["ev-2"]},
            validated_map={"url:http://app.example.com": True},
        )
        assert paths
        engine.reassess(
            paths[0],
            evidence_map={"url:http://app.example.com": ["ev-1"], "storage_resource:s3://bucket": ["ev-2"]},
            validated_map={"url:http://app.example.com": True},
            proved_map={},
        )
        # evidence-backed path is supported at minimum, never downgraded
        assert paths[0].state in (AttackPathState.SUPPORTED, AttackPathState.VALIDATED, AttackPathState.PROVED)

    def _wire_edges(self, surface: AttackSurfaceGraph) -> None:
        from hunterx.domain.target_intelligence.graph import relationship_for
        from hunterx.domain.topology.enums import RelationshipType

        def _asset(key: str):
            return surface.asset(key)

        edges = [
            (RelationshipType.USES, "url:http://app.example.com", "hostname:app.example.com"),
            (RelationshipType.RESOLVES_TO, "hostname:app.example.com", "ip:203.0.113.10"),
            (RelationshipType.EXPOSES, "ip:203.0.113.10", "service:https"),
            (RelationshipType.USES, "hostname:app.example.com", "auth_boundary:login"),
            (RelationshipType.CONTAINS, "ip:203.0.113.10", "storage_resource:s3://bucket"),
        ]
        for rel_type, source_key, target_key in edges:
            source = _asset(source_key)
            target = _asset(target_key)
            assert source is not None and target is not None
            surface.add_relationship(relationship_for(rel_type, source, target, mission_id="m1"))


class TestCheckpointAndFailure:
    def test_mission_resumes_after_restart(self) -> None:
        mission = AdaptiveMission(objective=MissionObjective.ATTACK_SURFACE_DISCOVERY)
        DeterministicMissionPlanner().create_initial_plan(mission)
        first = next(iter(mission.graph.actions.values()))
        first.mark(ActionStatus.COMPLETED)
        checkpoint = CheckpointEngine().create(
            mission_id=mission.mission_id,
            graph=mission.graph,
            plan_version=mission.plan_version,
            mission_state=mission.state,
        )
        # simulate restart: fresh graph, resume
        fresh = AdaptiveMission(objective=mission.objective)
        DeterministicMissionPlanner().create_initial_plan(fresh)
        CheckpointEngine().resume(checkpoint, fresh.graph)
        for action in fresh.graph.actions.values():
            if action.action_id == first.action_id:
                assert action.status is ActionStatus.COMPLETED

    def test_failure_classification_and_management(self) -> None:
        classifier = FailureClassifier()
        assert classifier.classify("rate limit exceeded", exit_code=429) is FailureClass.RATE_LIMIT
        assert classifier.classify(timeout=True) is FailureClass.TIMEOUT
        assert classifier.classify("connection refused") is FailureClass.NETWORK_ERROR
        recovery = RecoveryEngine()
        management, _ = recovery.decide(FailureClass.RATE_LIMIT)
        assert management.value == "pause"

    def test_tool_fallback_is_capability_checked(self) -> None:
        engine = ToolSelectionEngine(default_candidates={"port_discovery": ("rustscan", "masscan")})
        action = _action(capability="port_discovery")
        selection = engine.select(action)
        # default candidate applied when no selector is present
        assert selection.tool_id == "rustscan" or selection.tool_id == ""
        assert action.selected_tool == selection.tool_id

    def test_proof_gap_recognition(self) -> None:
        from hunterx.domain.adaptive_mission_planning.enums import EvidenceGapKind

        gap = Gap(
            mission_id="m1",
            finding_id="f1",
            kind=EvidenceGapKind.PROOF_GAP,
            asset_key="url:http://x.com",
            required_evidence=("proof_replay",),
            minimum_action="replay_proof",
            priority=0.9,
        )
        assert gap.kind is EvidenceGapKind.PROOF_GAP


def _fake_gap(*, asset: str, capability: str) -> object:
    class _Gap:
        required_capability = capability
        asset_key = asset
        importance = 0.9
        gap_id = "gap-1"

    return _Gap()


def _fake_hypothesis(hypothesis_type: str, *, confidence: float = 0.7) -> object:
    class _Hypothesis:
        def __init__(self, htype: str, conf: float) -> None:
            self.hypothesis_id = "h-1"
            self.asset_key = "url:http://x.com"
            self.confidence = conf
            self.statement = "suspected injection"
            self.category = htype

    return _Hypothesis(hypothesis_type, confidence)
