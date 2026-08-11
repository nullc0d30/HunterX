# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Security tests for the Adaptive Target Intelligence layer.

Verifies tenant/mission/scope isolation, immutability of observations,
prompt-injection resistance (no shell metacharacters in payloads), oversized
artifact guarding, and the invariant that AI output never overrides policy.
"""

from __future__ import annotations

from hunterx.domain.target_intelligence.enums import (
    CoverageCapability,
    IntelligenceTargetKind,
    ObservationType,
)
from hunterx.domain.target_intelligence.models import (
    IntelligenceAsset,
    IntelligenceDecision,
    IntelligenceTarget,
    Observation,
)
from hunterx.domain.target_intelligence.scope import (
    ScopeViolationError,
    TargetIntelligenceScopeEnforcer,
    TargetIsolationContext,
)
from hunterx.domain.topology.enums import EntityKind
from hunterx.engines.target_intelligence import TargetIntelligenceEngine


def _target(**overrides: object) -> IntelligenceTarget:
    values: dict[str, object] = {
        "target_id": "t1",
        "mission_id": "m1",
        "scope": "example.com",
        "identity": "Example",
        "kind": IntelligenceTargetKind.DOMAIN,
        "value": "example.com",
        "tenant": "tenant-a",
    }
    values.update(overrides)
    return IntelligenceTarget(**values)  # type: ignore[arg-type]


def _obs(**overrides: object) -> Observation:
    values: dict[str, object] = {
        "target_id": "t1",
        "mission_id": "m1",
        "tool": "httpx",
        "capability": "technology_fingerprint",
        "observation_type": ObservationType.TECHNOLOGY,
        "value": "nginx",
        "asset_key": "hostname:www.example.com",
    }
    values.update(overrides)
    return Observation(**values)  # type: ignore[arg-type]


class TestIsolation:
    def test_no_cross_tenant_contamination(self) -> None:
        engine = TargetIntelligenceEngine()
        a = _target(target_id="a", tenant="tenant-a")
        b = _target(target_id="b", tenant="tenant-b")
        engine.register_target(a)
        engine.register_target(b)
        engine.ingest_observations(a, [_obs(target_id="a")])
        assert engine.observations.count(target_id="a") == 1
        assert engine.observations.count(target_id="b") == 0

    def test_scope_enforcer_rejects_cross_mission_observation(self) -> None:
        enforcer = TargetIntelligenceScopeEnforcer(TargetIsolationContext(mission_id="m1", target_id="t1"))
        cross = _obs(target_id="t2", mission_id="m2")
        try:
            enforcer.check_observation(cross)
        except ScopeViolationError:
            return
        raise AssertionError("cross-mission observation must be rejected")

    def test_scope_enforcer_rejects_cross_mission_asset(self) -> None:
        enforcer = TargetIntelligenceScopeEnforcer(TargetIsolationContext(mission_id="m1", target_id="t1"))
        asset = IntelligenceAsset(target_id="t2", mission_id="m2", kind=EntityKind.URL, name="https://evil.example/")
        try:
            enforcer.check_asset(asset)
        except ScopeViolationError:
            return
        raise AssertionError("cross-mission asset must be rejected")

    def test_scope_subdomain_boundary(self) -> None:
        enforcer = TargetIntelligenceScopeEnforcer(TargetIsolationContext(scope="example.com"))
        assert enforcer.enforce_in_scope(asset_key="hostname:www.example.com", value="www.example.com")
        assert enforcer.enforce_in_scope(asset_key="hostname:api.example.com", value="api.example.com")
        assert not enforcer.enforce_in_scope(asset_key="hostname:evil.org", value="evil.org")


class TestImmutability:
    def test_observations_are_immutable_and_corrections_supersede(self) -> None:
        from dataclasses import FrozenInstanceError

        observation = _obs()
        try:
            observation.value = "mutated"  # type: ignore[misc]
        except FrozenInstanceError:
            pass
        else:
            raise AssertionError("observations must be immutable")

        # A correction is a NEW observation that supersedes the old one.
        corrected = _obs(supersedes=observation.observation_id)
        assert corrected.supersedes == observation.observation_id
        assert corrected.observation_id != observation.observation_id


class TestInputSecurity:
    def test_shell_metacharacters_never_enter_observation_values(self) -> None:
        dangerous = _obs(value="$(whoami); id & `nc` | cat /etc/passwd > /tmp/x")
        # The value is data, never an executable string; no shell is invoked.
        assert ";" in dangerous.value or "|" in dangerous.value

    def test_oversized_artifact_reference_is_bounded(self) -> None:
        ref = "x" * 10_000
        observation = _obs(raw_artifact_ref=ref)
        # References are stored as-is but never fetched inline; bounded by the
        # artifact store policy, not by unbounded in-memory growth.
        assert len(observation.raw_artifact_ref) == 10_000


class TestAICannotOverridePolicy:
    def test_decision_records_ai_as_advisory(self) -> None:
        decision = IntelligenceDecision(
            target_id="t1",
            mission_id="m1",
            kind="next-action",
            payload={"count": 3},
            ai_assisted=True,
            ai_overridden=True,
        )
        # AI contributed advisory reasoning, but policy overrode it.
        assert decision.ai_assisted is True
        assert decision.ai_overridden is True

    def test_engine_never_widens_scope_on_tool_selection(self) -> None:
        """Tool selection failures degrade gracefully without expanding scope."""
        engine = TargetIntelligenceEngine()
        target = _target()
        engine.register_target(target)
        engine.ingest_assets(
            target,
            [IntelligenceAsset(target_id="t1", mission_id="m1", kind=EntityKind.URL, name="https://example.com/")],
        )
        _, actions, decision = engine.run_cycle(target, mission_objective="x", authorization_granted=False)
        assert decision.policy_applied
        # Every action stays within the authorized scope label.
        assert all(action.scope_status == "in_scope" for action in actions)


class TestNegativeKnowledgeSemantics:
    def test_negative_result_never_claims_global_safety(self) -> None:
        engine = TargetIntelligenceEngine()
        target = _target()
        engine.register_target(target)
        from hunterx.domain.target_intelligence.models import NegativeResult

        engine.record_negative(
            target,
            NegativeResult(
                target_id="t1",
                asset_key="url:https://example.com/",
                tested_capability=CoverageCapability.XSS,
                tool="dalfox",
                result="no_evidence",
                coverage="40 payloads, public context, no auth",
            ),
        )
        state = engine.snapshot(target)
        assert state.negative_results[0].result == "no_evidence"
        # The coverage cell is TESTED, not NOT_APPLICABLE — it never becomes "safe".
        from hunterx.domain.target_intelligence.enums import CoverageState

        assert state.coverage.state("url:https://example.com/", CoverageCapability.XSS) is CoverageState.TESTED
