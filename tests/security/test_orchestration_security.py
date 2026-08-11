# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Security tests for the offensive tool orchestration capability.

Validates that the orchestration layer cannot be tricked into scope bypass,
safety bypass, cross-mission leakage or unrestricted execution: out-of-scope
targets are blocked, exclusions always win, forbidden parameters are refused,
replanning never expands scope, and deduplication cannot leak cross-mission
state.
"""

from __future__ import annotations

from dataclasses import replace

from hunterx.domain.orchestration.enums import MissionState, MissionType, TaskState
from hunterx.domain.orchestration.models import (
    MissionScope,
    MissionStep,
    SafetyPolicy,
)
from hunterx.engines.orchestration.api import OffensiveOrchestrationAPI
from hunterx.engines.orchestration.executor import MissionExecutor
from hunterx.engines.orchestration.planner import IntelligenceSummary, MissionPlanner
from hunterx.engines.orchestration.replan import DiscoveredAsset
from hunterx.engines.orchestration.selector import MissionToolSelector
from hunterx.infrastructure.memory.orchestration import build_in_memory_orchestration_repositories
from tests.framework.orchestration import fake_engine


def _plan(targets=("example.com",)):
    planner = MissionPlanner()
    intelligence = IntelligenceSummary(
        mission_type=MissionType.WEB_PENTEST,
        targets=tuple(targets),
        endpoints=("web",),
    )
    return planner.plan(
        mission_id="m1",
        objective="assess example.com",
        intelligence=intelligence,
        scope=MissionScope(roots=tuple(targets)),
    )


def _executor(engine=None):
    engine = engine or fake_engine()
    return MissionExecutor(engine=engine, selector=MissionToolSelector(engine=engine))


class TestScopeBypass:
    def test_scope_bypass_attempt_blocked(self) -> None:
        plan = _plan()
        first = plan.phases[0]
        extra = MissionStep(
            step_id="bypass",
            phase_id=first.phase_id,
            capability="web-crawling",
            target="evil.org",
            target_type="domain",
        )
        phases = (replace(first, steps=first.steps + (extra,)),) + plan.phases[1:]
        plan = replace(plan, phases=phases)
        run = _executor().run(mission_id="m1", plan=plan)
        outcome = run.outcomes["bypass"]
        assert outcome.state is TaskState.BLOCKED
        assert "scope" in outcome.error


    def test_exclusion_always_wins(self) -> None:
        plan = _plan(targets=("example.com", "internal.example.com"))
        first = plan.phases[0]
        extra = MissionStep(
            step_id="internal",
            phase_id=first.phase_id,
            capability="web-crawling",
            target="internal.example.com",
            target_type="domain",
        )
        phases = (replace(first, steps=first.steps + (extra,)),) + plan.phases[1:]
        excluded_scope = MissionScope(roots=("example.com",), excludes=("internal.example.com",))
        plan = replace(plan, phases=phases, scope=excluded_scope)
        run = _executor().run(mission_id="m1", plan=plan)
        assert "internal" in run.blocked


    def test_cidr_escape_blocked(self) -> None:
        plan = _plan(targets=("10.0.0.0/24",))
        first = plan.phases[0]
        extra = MissionStep(
            step_id="cidr-escape",
            phase_id=first.phase_id,
            capability="port-discovery",
            target="10.1.0.5",
            target_type="ip",
        )
        phases = (replace(first, steps=first.steps + (extra,)),) + plan.phases[1:]
        plan = replace(plan, phases=phases)
        run = _executor().run(mission_id="m1", plan=plan)
        assert "cidr-escape" in run.blocked


    def test_redirect_target_requires_scope(self) -> None:
        guard = __import__("hunterx.engines.orchestration.scope", fromlist=["MissionScopeGuard"]).MissionScopeGuard(
            MissionScope(roots=("example.com",))
        )
        assert not guard.allows("evil.com", redirected=True)


class TestSafetyBypass:
    def test_forbidden_parameter_refused(self) -> None:
        plan = _plan()
        first = plan.phases[0]
        unsafe = replace(first.steps[0], step_id="unsafe", parameters={"cmd": "rm -rf /"})
        steps = (unsafe,) + first.steps[1:]
        phases = (replace(first, steps=steps),) + plan.phases[1:]
        plan = replace(plan, phases=phases)
        run = _executor().run(mission_id="m1", plan=plan)
        assert "unsafe" in run.blocked


    def test_forbidden_action_refused(self) -> None:
        plan = _plan()
        first = plan.phases[0]
        unsafe = replace(first.steps[0], step_id="danger", capability="credential-dumping")
        steps = (unsafe,) + first.steps[1:]
        phases = (replace(first, steps=steps),) + plan.phases[1:]
        plan = replace(plan, phases=phases)
        run = _executor().run(mission_id="m1", plan=plan)
        assert "danger" in run.blocked


    def test_destructive_safety_policy_never_allows_destructive(self) -> None:
        from hunterx.domain.orchestration.enums import ExecutionPolicyLevel
        from hunterx.engines.orchestration.safety import MissionSafetyEnforcer

        policy = SafetyPolicy(destructive_allowed=True)
        enforcer = MissionSafetyEnforcer(ExecutionPolicyLevel.AUTHORIZED_RED_TEAM, policy)
        decision = enforcer.decides(action="weaponized-exploit-execution", safety_class="controlled")
        assert not decision.allowed


class TestCrossMissionIsolation:
    def test_deduplication_does_not_leak_across_missions(self) -> None:
        from hunterx.engines.orchestration.dedup import (
            ExecutionDeduplicator,
            ExecutionRecord,
            execution_hash,
        )

        dedup = ExecutionDeduplicator(freshness_window_seconds=3600)
        h1 = execution_hash(tool_id="subfinder", target="a.com")
        dedup.record(ExecutionRecord(execution_id="e1", input_hash=h1, tool_id="subfinder", target="a.com"))
        h2 = execution_hash(tool_id="subfinder", target="b.com")
        assert not dedup.is_duplicate(h2)
        assert dedup.is_duplicate(h1)


    def test_memory_isolated_per_target(self) -> None:
        from hunterx.engines.orchestration.memory import MissionMemoryStore

        store = MissionMemoryStore()
        store.memory(target="a.com").add_asset("sub.a.com")
        assert "sub.a.com" not in store.memory(target="b.com").discovered_assets


class TestReplanScopeSafety:
    def test_replan_never_expands_scope(self) -> None:
        repos = build_in_memory_orchestration_repositories()
        api = OffensiveOrchestrationAPI(
            missions=repos["offensive_missions"],
            plans=repos["execution_plans"],
            execution_engine=fake_engine(),
        )
        mission = api.create_mission(
            objective="assess",
            mission_type=MissionType.WEB_PENTEST,
            scope=MissionScope(roots=("example.com",)),
            targets=("example.com",),
        ).value
        result = api.engine.replan_mission(
            mission.mission_id,
            reason="new assets",
            discovered_assets=[
                DiscoveredAsset(identifier="sub.example.com"),
                DiscoveredAsset(identifier="evil.org"),
            ],
        )
        assert result.ok
        decision = result.value
        assert "sub.example.com" in decision.in_scope_assets
        assert "evil.org" in decision.blocked_assets
        assert "evil.org" not in decision.in_scope_assets


    def test_engine_blocks_scope_expansion_run(self) -> None:
        repos = build_in_memory_orchestration_repositories()
        api = OffensiveOrchestrationAPI(
            missions=repos["offensive_missions"],
            plans=repos["execution_plans"],
            execution_engine=fake_engine(),
        )
        mission = api.create_mission(
            objective="assess",
            mission_type=MissionType.WEB_PENTEST,
            scope=MissionScope(roots=("example.com",)),
            targets=("example.com",),
        ).value
        plan = api.plan_mission(mission.mission_id).value
        # Attempt to run a step against an out-of-scope host.
        first = plan.phases[0]
        extra = MissionStep(
            step_id="evil-step",
            phase_id=first.phase_id,
            capability="web-crawling",
            target="evil.org",
            target_type="domain",
        )
        phases = (replace(first, steps=first.steps + (extra,)),) + plan.phases[1:]
        api.engine._plans.save(replace(plan, phases=phases))
        run = api.run_mission(mission.mission_id).value
        assert "evil-step" in run.run.blocked
        assert run.mission.state is MissionState.PARTIAL
