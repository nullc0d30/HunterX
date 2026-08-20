# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for the aggressive-but-bounded adaptive attack engine.

Covers feedback classification, the attack state machine, bounded controls
(aggression/pacing/concurrency/backoff/retry), multi-vector selection, probe
plan escalation and generic workflow representation. Every test uses synthetic,
abstract surfaces — never a real product's routes or objects.
"""

from __future__ import annotations

from hunterx.domain.adaptive_attack.control import AdaptiveRateController, AttackControlConfig
from hunterx.domain.adaptive_attack.enums import (
    AggressionLevel,
    AttackState,
    AttackVector,
    FeedbackSignal,
)
from hunterx.domain.adaptive_attack.feedback import FeedbackClassifier, FeedbackMonitor
from hunterx.domain.adaptive_attack.probe import (
    AttackProbePlan,
    ProbeStep,
    bounded_mutations,
    bounded_payloads,
    profile_for,
)
from hunterx.domain.adaptive_attack.vector import VectorSelector
from hunterx.domain.adaptive_attack.workflow import build_workflow_from_attributes
from hunterx.domain.attack_surface.enums import AuthContextState, SurfaceKind
from hunterx.domain.attack_surface.models import SurfaceContext, SurfaceNode


class TestFeedbackClassifier:
    def _classifier(self) -> FeedbackClassifier:
        return FeedbackClassifier(high_latency_ms=1000)

    def test_rate_limit_signal(self) -> None:
        assert self._classifier().classify(status_code=429) is FeedbackSignal.RATE_LIMITED

    def test_access_denied_signal(self) -> None:
        assert self._classifier().classify(status_code=403) is FeedbackSignal.ACCESS_DENIED

    def test_server_error_signal(self) -> None:
        assert self._classifier().classify(status_code=503) is FeedbackSignal.SERVER_ERROR

    def test_timeout_signal(self) -> None:
        assert self._classifier().classify(error="request timed out") is FeedbackSignal.TIMEOUT
        assert self._classifier().classify(failure_kind="timeout") is FeedbackSignal.TIMEOUT

    def test_connection_failure_signal(self) -> None:
        assert self._classifier().classify(error="connection reset by peer") is FeedbackSignal.CONNECTION_FAILURE

    def test_high_latency_signal(self) -> None:
        assert self._classifier().classify(duration_ms=5000) is FeedbackSignal.HIGH_LATENCY

    def test_waf_signal(self) -> None:
        assert self._classifier().classify(body_hint="request blocked by cloudflare waf") is FeedbackSignal.WAF_BLOCKED

    def test_normal_signal(self) -> None:
        assert self._classifier().classify(status_code=200, duration_ms=5) is FeedbackSignal.NORMAL


class TestFeedbackMonitor:
    def test_rolling_window_is_bounded(self) -> None:
        monitor = FeedbackMonitor(window_size=5)
        for _ in range(10):
            monitor.observe(status_code=200)
        assert len(monitor.signals()) == 5

    def test_defensive_ratio(self) -> None:
        monitor = FeedbackMonitor(window_size=10)
        monitor.observe(status_code=200)
        monitor.observe(status_code=429)
        assert monitor.defensive_ratio() == 0.5

    def test_healthy_and_defensive_streaks(self) -> None:
        monitor = FeedbackMonitor()
        monitor.observe(status_code=200)
        monitor.observe(status_code=200)
        assert monitor.healthy_streak() == 2
        monitor.observe(status_code=429)
        assert monitor.defensive_streak() == 1
        assert monitor.healthy_streak() == 0

    def test_is_healthy(self) -> None:
        monitor = FeedbackMonitor()
        monitor.observe(status_code=200)
        monitor.observe(status_code=200)
        assert monitor.is_healthy()
        monitor.observe(status_code=500)
        assert not monitor.is_healthy()


class TestAdaptiveRateController:
    def test_healthy_escalates_to_aggressive(self) -> None:
        controller = AdaptiveRateController(config=AttackControlConfig(aggressive_after=3))
        assert controller.state is AttackState.NORMAL
        for _ in range(3):
            controller.observe(FeedbackSignal.NORMAL)
        assert controller.state is AttackState.AGGRESSIVE

    def test_defensive_throttles(self) -> None:
        controller = AdaptiveRateController()
        controller.observe(FeedbackSignal.RATE_LIMITED)
        assert controller.state is AttackState.THROTTLED
        assert controller.pacing_seconds() > 0
        assert controller.concurrency_limit() < controller.config.max_concurrency

    def test_throttled_to_backing_off_on_hard_signal(self) -> None:
        controller = AdaptiveRateController()
        controller.observe(FeedbackSignal.RATE_LIMITED)
        controller.observe(FeedbackSignal.WAF_BLOCKED)
        assert controller.state is AttackState.BACKING_OFF
        assert controller.concurrency_limit() == 1

    def test_gradual_recovery_returns_to_normal(self) -> None:
        config = AttackControlConfig(recover_after=2, resume_after=2)
        controller = AdaptiveRateController(config=config)
        controller.observe(FeedbackSignal.RATE_LIMITED)
        controller.observe(FeedbackSignal.CONNECTION_FAILURE)
        assert controller.state is AttackState.BACKING_OFF
        controller.observe(FeedbackSignal.NORMAL)
        controller.observe(FeedbackSignal.NORMAL)
        assert controller.state is AttackState.RECOVERING
        controller.observe(FeedbackSignal.NORMAL)
        controller.observe(FeedbackSignal.NORMAL)
        assert controller.state is AttackState.RESUMING
        controller.observe(FeedbackSignal.NORMAL)
        controller.observe(FeedbackSignal.NORMAL)
        assert controller.state is AttackState.NORMAL

    def test_persistent_blocking_reaches_blocked(self) -> None:
        config = AttackControlConfig(block_after=2)
        controller = AdaptiveRateController(config=config)
        for _ in range(2):
            controller.observe(FeedbackSignal.RATE_LIMITED)
        assert controller.state is AttackState.BLOCKED
        assert controller.concurrency_limit() == 1

    def test_blocked_recovers_only_after_sustained_health(self) -> None:
        config = AttackControlConfig(block_after=2, unblock_after=3)
        controller = AdaptiveRateController(config=config)
        for _ in range(2):
            controller.observe(FeedbackSignal.WAF_BLOCKED)
        assert controller.state is AttackState.BLOCKED
        controller.observe(FeedbackSignal.NORMAL)
        assert controller.state is AttackState.BLOCKED  # one healthy is not enough
        for _ in range(3):
            controller.observe(FeedbackSignal.NORMAL)
        assert controller.state is AttackState.RESUMING

    def test_recovery_defensive_retreats(self) -> None:
        controller = AdaptiveRateController(config=AttackControlConfig(recover_after=2))
        controller.observe(FeedbackSignal.RATE_LIMITED)
        controller.observe(FeedbackSignal.NORMAL)
        controller.observe(FeedbackSignal.NORMAL)
        assert controller.state is AttackState.RECOVERING
        controller.observe(FeedbackSignal.SERVER_ERROR)
        assert controller.state is AttackState.THROTTLED

    def test_aggression_level_maps_from_state(self) -> None:
        controller = AdaptiveRateController()
        assert controller.aggression_level() is AggressionLevel.MEDIUM
        controller.observe(FeedbackSignal.RATE_LIMITED)
        assert controller.aggression_level() is AggressionLevel.LOW
        for _ in range(4):
            controller.observe(FeedbackSignal.NORMAL)
        assert controller.state is not AttackState.THROTTLED


class TestBoundedControls:
    def test_concurrency_never_exceeds_config(self) -> None:
        controller = AdaptiveRateController(config=AttackControlConfig(max_concurrency=4))
        for signal in (FeedbackSignal.NORMAL, FeedbackSignal.AGGRESSIVE if False else FeedbackSignal.NORMAL, FeedbackSignal.RATE_LIMITED, FeedbackSignal.WAF_BLOCKED, FeedbackSignal.TIMEOUT):
            controller.observe(signal)
            assert 1 <= controller.concurrency_limit() <= 4

    def test_pacing_is_capped(self) -> None:
        config = AttackControlConfig(max_pacing_s=5.0, pacing_base_s=10.0)
        controller = AdaptiveRateController(config=config)
        controller.observe(FeedbackSignal.RATE_LIMITED)
        assert controller.pacing_seconds() <= 5.0

    def test_backoff_is_capped(self) -> None:
        config = AttackControlConfig(max_backoff_s=4.0, pacing_base_s=1.0, pacing_factor=2.0)
        controller = AdaptiveRateController(config=config)
        assert controller.backoff_seconds(0) == 1.0
        assert controller.backoff_seconds(10) == 4.0

    def test_retry_is_bounded(self) -> None:
        config = AttackControlConfig(max_retries=2)
        controller = AdaptiveRateController(config=config)
        assert controller.should_retry(FeedbackSignal.RATE_LIMITED, attempts=0)
        assert controller.should_retry(FeedbackSignal.RATE_LIMITED, attempts=1)
        assert not controller.should_retry(FeedbackSignal.RATE_LIMITED, attempts=2)

    def test_never_retry_through_block(self) -> None:
        config = AttackControlConfig(block_after=2)
        controller = AdaptiveRateController(config=config)
        for _ in range(2):
            controller.observe(FeedbackSignal.WAF_BLOCKED)
        assert not controller.should_retry(FeedbackSignal.TIMEOUT, attempts=0)

    def test_non_retryable_signals_never_retried(self) -> None:
        controller = AdaptiveRateController()
        assert not controller.should_retry(FeedbackSignal.ACCESS_DENIED, attempts=0)


class TestVectorSelector:
    def _surface(self, kind: SurfaceKind, **attributes: object) -> SurfaceNode:
        return SurfaceNode(kind=kind, name=kind.value, attributes=attributes)

    def test_query_parameter_selects_query(self) -> None:
        selector = VectorSelector()
        assert selector.select(self._surface(SurfaceKind.PARAMETER)) == [AttackVector.QUERY]

    def test_header_and_cookie_select_their_vectors(self) -> None:
        selector = VectorSelector()
        assert AttackVector.HEADERS in selector.select(self._surface(SurfaceKind.HEADER))
        assert AttackVector.COOKIES in selector.select(self._surface(SurfaceKind.COOKIE))

    def test_json_field_selects_json_and_api_body(self) -> None:
        selector = VectorSelector()
        vectors = selector.select(self._surface(SurfaceKind.JSON_FIELD))
        assert AttackVector.JSON in vectors
        assert AttackVector.API_BODY in vectors

    def test_form_field_selects_form(self) -> None:
        selector = VectorSelector()
        assert AttackVector.FORM in selector.select(self._surface(SurfaceKind.FORM_FIELD))

    def test_upload_selects_multipart(self) -> None:
        selector = VectorSelector()
        assert AttackVector.MULTIPART in selector.select(self._surface(SurfaceKind.UPLOAD))

    def test_graphql_selects_graphql(self) -> None:
        selector = VectorSelector()
        vectors = selector.select(self._surface(SurfaceKind.GRAPHQL_OPERATION))
        assert AttackVector.GRAPHQL in vectors

    def test_object_selects_object_identifier(self) -> None:
        selector = VectorSelector()
        assert AttackVector.OBJECT_IDENTIFIER in selector.select(self._surface(SurfaceKind.OBJECT))

    def test_workflow_selects_workflow_state(self) -> None:
        selector = VectorSelector()
        assert AttackVector.WORKFLOW_STATE in selector.select(self._surface(SurfaceKind.WORKFLOW))

    def test_auth_surface_selects_auth_state(self) -> None:
        selector = VectorSelector()
        assert AttackVector.AUTH_STATE in selector.select(self._surface(SurfaceKind.AUTH_SURFACE))

    def test_post_endpoint_selects_body_vectors(self) -> None:
        selector = VectorSelector()
        node = SurfaceNode(kind=SurfaceKind.ENDPOINT, name="submit", context=SurfaceContext(method="POST"))
        vectors = selector.select(node)
        assert AttackVector.FORM in vectors
        assert AttackVector.API_BODY in vectors

    def test_json_content_type_selects_json(self) -> None:
        selector = VectorSelector()
        node = SurfaceNode(
            kind=SurfaceKind.ENDPOINT,
            name="api",
            context=SurfaceContext(content_type="application/json"),
        )
        assert AttackVector.JSON in selector.select(node)

    def test_fetch_hint_selects_url(self) -> None:
        selector = VectorSelector()
        node = SurfaceNode(kind=SurfaceKind.PARAMETER, name="url", context=SurfaceContext(fetch_hint=True))
        assert AttackVector.URL in selector.select(node)

    def test_authenticated_object_selects_authorization_context(self) -> None:
        selector = VectorSelector()
        node = SurfaceNode(
            kind=SurfaceKind.OBJECT,
            name="order",
            context=SurfaceContext(auth_state=AuthContextState.AUTHENTICATED, object_hint=True),
        )
        vectors = selector.select(node)
        assert AttackVector.AUTHORIZATION_CONTEXT in vectors


class TestAggressionProfiles:
    def test_profiles_are_bounded_and_monotonic(self) -> None:
        previous = 0
        for level in (AggressionLevel.LOW, AggressionLevel.MEDIUM, AggressionLevel.HIGH, AggressionLevel.MAXIMUM):
            profile = profile_for(level)
            assert profile.payload_budget > previous
            assert profile.payload_budget <= 50
            previous = profile.payload_budget

    def test_bounded_payloads_truncates(self) -> None:
        payloads = tuple(f"p{i}" for i in range(100))
        low = bounded_payloads(payloads, AggressionLevel.LOW)
        maximum = bounded_payloads(payloads, AggressionLevel.MAXIMUM)
        assert len(low) <= 5
        assert len(maximum) <= 50
        assert len(maximum) > len(low)

    def test_bounded_mutations_truncates(self) -> None:
        mutations = [{"m": i} for i in range(10)]
        assert len(bounded_mutations(mutations, AggressionLevel.LOW)) <= 1
        assert len(bounded_mutations(mutations, AggressionLevel.MAXIMUM)) <= 4


class TestProbePlanEscalation:
    def test_ladder_has_required_steps(self) -> None:
        plan = AttackProbePlan(surface_key="parameter:q", capability_id="xss")
        assert plan.steps == (
            ProbeStep.BASELINE,
            ProbeStep.PROBE,
            ProbeStep.DIFFERENTIAL_ANALYSIS,
            ProbeStep.STRONGER_STRATEGY,
            ProbeStep.VERIFICATION,
        )

    def test_escalation_is_bounded(self) -> None:
        plan = AttackProbePlan(
            surface_key="parameter:q",
            capability_id="sql-injection",
            aggression=AggressionLevel.MAXIMUM,
            payloads=tuple(f"p{i}" for i in range(100)),
        )
        escalated = plan.escalated()
        assert escalated.aggression is AggressionLevel.MAXIMUM
        assert len(escalated.payloads) <= 50

    def test_escalation_raises_tier_and_preserves_bounded_payloads(self) -> None:
        plan = AttackProbePlan(
            surface_key="parameter:q",
            capability_id="xss",
            aggression=AggressionLevel.LOW,
            payloads=tuple(f"p{i}" for i in range(3)),
        )
        escalated = plan.escalated()
        assert escalated.aggression is AggressionLevel.MEDIUM
        # The escalated profile's budget (12) covers the 3-source payloads, so
        # escalation never truncates an already-applicable set.
        assert len(escalated.payloads) == 3
        assert escalated.retry_limit >= plan.retry_limit


class TestAttackWorkflow:
    def test_builds_from_steps(self) -> None:
        workflow = build_workflow_from_attributes(
            name="checkout",
            attributes={"steps": ["cart", "payment", "confirmation"]},
            security_properties=("authorization",),
        )
        assert workflow.state_names() == ["cart", "payment", "confirmation"]
        assert len(workflow.transitions) == 2
        assert workflow.security_properties() == {"authorization"}

    def test_builds_from_transitions(self) -> None:
        workflow = build_workflow_from_attributes(
            name="onboarding",
            attributes={
                "transitions": [
                    {"from": "pending", "to": "approved", "action": "review"},
                    {"from": "approved", "to": "rejected", "action": "escalate"},
                ]
            },
        )
        assert len(workflow.transitions) == 2
        assert workflow.transitions[0].from_state == "pending"
        assert workflow.transitions[0].action == "review"

    def test_unknown_attributes_degrades_to_single_state(self) -> None:
        workflow = build_workflow_from_attributes(name="solo", attributes={})
        assert workflow.state_names() == ["solo"]
        assert not workflow.transitions

    def test_serialization_roundtrip(self) -> None:
        workflow = build_workflow_from_attributes(
            name="checkout",
            attributes={"steps": ["a", "b"]},
        )
        payload = workflow.to_dict()
        assert payload["name"] == "checkout"
        assert len(payload["states"]) == 2
        assert len(payload["transitions"]) == 1
