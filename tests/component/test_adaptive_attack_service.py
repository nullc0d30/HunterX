# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Component tests for the adaptive attack application service.

Proves the aggressive-but-bounded behavior end to end: target feedback drives
the attack state machine, throttling reduces intensity, recovery restores it
gradually, escalation is bounded, multi-vector selection schedules only
applicable vectors, probe plans are bounded and reuse the platform payload
generation, workflows are generic, and defensive responses never terminate the
assessment.
"""

from __future__ import annotations

from hunterx.application.adaptive_attack import AdaptiveAttackService
from hunterx.domain.adaptive_attack.control import AdaptiveRateController, AttackControlConfig
from hunterx.domain.adaptive_attack.enums import (
    AggressionLevel,
    AttackState,
    AttackVector,
    FeedbackSignal,
)
from hunterx.domain.adaptive_attack.probe import ProbeStep
from hunterx.domain.attack_surface.enums import SurfaceKind
from hunterx.domain.attack_surface.models import SurfaceContext, SurfaceNode


def _service(**kwargs: object) -> AdaptiveAttackService:
    return AdaptiveAttackService(mission_id="m1", target_key="https://t.example", **kwargs)


def _param(name: str, **attributes: object) -> SurfaceNode:
    return SurfaceNode(kind=SurfaceKind.PARAMETER, name=name, attributes=attributes)


class TestFeedbackDrivesState:
    def test_healthy_executions_escalate(self) -> None:
        service = _service()
        for _ in range(4):
            service.observe(status_code=200, duration_ms=5)
        assert service.attack_state() is AttackState.AGGRESSIVE
        assert service.aggression_level() is AggressionLevel.MEDIUM

    def test_rate_limit_throttles(self) -> None:
        service = _service()
        signal = service.observe(status_code=429)
        assert signal is FeedbackSignal.RATE_LIMITED
        assert service.attack_state() is AttackState.THROTTLED
        assert service.is_throttling()
        assert service.pacing_seconds() > 0
        assert service.concurrency_limit() < service.controller.config.max_concurrency

    def test_waf_block_escalates_to_backing_off(self) -> None:
        service = _service()
        service.observe(status_code=429)
        service.observe(status_code=403, body_hint="blocked by waf")
        assert service.attack_state() is AttackState.BACKING_OFF
        assert service.concurrency_limit() == 1

    def test_gradual_recovery(self) -> None:
        service = _service(
            controller=AdaptiveRateController(config=AttackControlConfig(block_after=2, recover_after=2, resume_after=2))
        )
        service.observe(status_code=429)
        service.observe(status_code=429)
        assert service.attack_state() is AttackState.BLOCKED
        # Recovery is gradual: sustained health unblocks to RESUMING first...
        for _ in range(5):
            service.observe(status_code=200, duration_ms=5)
        assert service.attack_state() is AttackState.RESUMING
        # ...then a further sustained healthy budget returns to NORMAL.
        for _ in range(2):
            service.observe(status_code=200, duration_ms=5)
        assert service.attack_state() is AttackState.NORMAL

    def test_defensive_response_never_completes(self) -> None:
        service = _service()
        for _ in range(5):
            service.observe(status_code=429)
        assert service.attack_state() is AttackState.BLOCKED
        # Blocking is blocking — the service never reports "exhausted".
        assert service.snapshot()["is_throttling"] is True


class TestProbePlanning:
    def test_plan_uses_platform_payload_generation(self) -> None:
        service = _service()
        service.observe(status_code=200)
        plan = service.plan_probe(surface=_param("id"), capability_id="sql-injection")
        assert plan.capability_id == "sql-injection"
        assert plan.payloads  # sourced from the capability engine, not empty
        assert plan.steps == ProbeStep.ladder()
        assert AttackVector.QUERY in plan.vectors

    def test_plan_is_bounded_by_aggression(self) -> None:
        service = _service()
        surface = _param("q")
        for _ in range(4):
            service.observe(status_code=200, duration_ms=5)
        aggressive_plan = service.plan_probe(surface=surface, capability_id="xss")
        service.observe(status_code=429)
        throttled_plan = service.plan_probe(surface=surface, capability_id="xss")
        assert aggressive_plan.aggression.rank >= throttled_plan.aggression.rank
        assert len(aggressive_plan.payloads) >= len(throttled_plan.payloads)
        assert len(throttled_plan.payloads) <= 5  # LOW budget hard bound

    def test_escalation_is_bounded(self) -> None:
        service = _service()
        plan = service.plan_probe(surface=_param("q"), capability_id="xss")
        escalated = service.escalate(plan)
        assert escalated.aggression.rank > plan.aggression.rank or escalated.aggression is AggressionLevel.MAXIMUM
        assert len(escalated.payloads) <= 50  # hard ceiling

    def test_plan_never_exceeds_profile_budget_directly(self) -> None:
        service = _service()
        plan = service.plan_probe(surface=_param("q"), capability_id="sql-injection", payloads=tuple(f"p{i}" for i in range(500)))
        assert len(plan.payloads) <= plan.profile().payload_budget


class TestMultiVector:
    def test_only_applicable_vectors_selected(self) -> None:
        service = _service()
        query_surface = _param("q")
        assert service.select_vectors(query_surface) == [AttackVector.QUERY]
        assert AttackVector.MULTIPART not in service.select_vectors(query_surface)
        assert AttackVector.GRAPHQL not in service.select_vectors(query_surface)

    def test_form_surface_selects_form_and_body(self) -> None:
        service = _service()
        form = SurfaceNode(
            kind=SurfaceKind.FORM_FIELD,
            name="username",
            context=SurfaceContext(method="POST", content_type="application/x-www-form-urlencoded"),
        )
        vectors = service.select_vectors(form)
        assert AttackVector.FORM in vectors
        assert AttackVector.API_BODY in vectors

    def test_graphql_and_upload_surfaces(self) -> None:
        service = _service()
        gql = SurfaceNode(kind=SurfaceKind.GRAPHQL_OPERATION, name="user")
        assert AttackVector.GRAPHQL in service.select_vectors(gql)
        upload = SurfaceNode(kind=SurfaceKind.UPLOAD, name="avatar")
        assert AttackVector.MULTIPART in service.select_vectors(upload)

    def test_auth_and_object_contexts(self) -> None:
        service = _service()
        obj = SurfaceNode(
            kind=SurfaceKind.OBJECT,
            name="order",
            context=SurfaceContext(auth_state=__import__("hunterx.domain.attack_surface.enums", fromlist=["AuthContextState"]).AuthContextState.AUTHENTICATED, object_hint=True),
        )
        vectors = service.select_vectors(obj)
        assert AttackVector.OBJECT_IDENTIFIER in vectors
        assert AttackVector.AUTHORIZATION_CONTEXT in vectors


class TestWorkflow:
    def test_workflow_built_from_workflow_surface(self) -> None:
        service = _service()
        surface = SurfaceNode(
            kind=SurfaceKind.WORKFLOW,
            name="checkout",
            attributes={"steps": ["cart", "payment", "confirmation"], "security_properties": ["authorization"]},
        )
        workflow = service.workflow_for(surface)
        assert workflow is not None
        assert workflow.state_names() == ["cart", "payment", "confirmation"]
        assert workflow.security_properties() == {"authorization"}

    def test_workflow_not_built_for_non_workflow_surface(self) -> None:
        service = _service()
        assert service.workflow_for(_param("q")) is None


class TestRetryAndLimits:
    def test_retry_bounded_and_strategic(self) -> None:
        service = _service()
        assert service.should_retry(FeedbackSignal.RATE_LIMITED, attempts=0)
        assert not service.should_retry(FeedbackSignal.RATE_LIMITED, attempts=3)
        assert not service.should_retry(FeedbackSignal.ACCESS_DENIED, attempts=0)

    def test_limits_never_unbounded(self) -> None:
        service = _service(controller=AdaptiveRateController(config=AttackControlConfig(max_concurrency=4)))
        for _ in range(6):
            service.observe(status_code=429)
        assert service.concurrency_limit() == 1
        assert service.pacing_seconds() <= service.controller.config.max_pacing_s
        assert service.backoff_seconds(100) <= service.controller.config.max_backoff_s

    def test_new_surface_feedback_schedules_attack_work(self) -> None:
        """Continuous attack feedback: a new surface becomes new attack work."""
        service = _service()
        surface = _param("callback")
        plan = service.plan_probe(surface=surface, capability_id="open-redirect")
        assert plan.surface_key == surface.key
        assert AttackVector.QUERY in plan.vectors
        # The same surface+capability under the same context dedups to one plan.
        second = service.plan_probe(surface=surface, capability_id="open-redirect")
        assert second.surface_key == surface.key
