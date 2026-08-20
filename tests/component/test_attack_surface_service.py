# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Component tests for the attack-surface application service.

Every test drives one of the abstract synthetic target shapes (simple web app,
REST API, GraphQL API, authenticated application, multi-user application,
file-handling application, workflow-driven application) through the surface
service and asserts the generic model represents and schedules what was
actually discovered — never a hardcoded target.
"""

from __future__ import annotations

from hunterx.application.attack_surface import AttackSurfaceService, CapabilityCatalog
from hunterx.domain.attack_surface.enums import (
    AssessmentStatus,
    AuthContextState,
    CompletionVerdict,
    SurfaceLayer,
    VerificationState,
)
from hunterx.domain.attack_surface.models import SurfaceContext
from tests.framework.surfaces import (
    ALL_SHAPES,
    AUTHENTICATED_APP,
    FILE_HANDLING_APP,
    GRAPHQL_API,
    MULTI_USER_APP,
    REST_API,
    SIMPLE_WEB_APP,
    WORKFLOW_DRIVEN_APP,
    TargetShape,
    feed,
)


def _service(shape: TargetShape) -> AttackSurfaceService:
    return AttackSurfaceService(mission_id=f"mission-{shape.name}", target_key=shape.target)


def _settle_all(service: AttackSurfaceService, state: VerificationState) -> None:
    for assignment in service.graph.assignments():
        assignment.mark(AssessmentStatus.COMPLETED)
        assignment.settle(state)
    for task in service.queue.tasks():
        service.queue.mark(task.task_id, AssessmentStatus.COMPLETED)
        service.queue.settle(task.task_id, state)


class TestCatalogIsPlatformSourced:
    def test_capability_catalog_comes_from_the_live_platform_catalog(self) -> None:
        catalog = CapabilityCatalog.from_platform()
        assert isinstance(catalog, list)
        assert catalog
        # The probeable capability classes must come from the existing
        # vulnerability-capability registry — never a hardcoded Phase-1 list.
        from hunterx.domain.vulnerability_capability.registry import registered_classes

        assert set(registered_classes()).issubset(set(catalog))

    def test_catalog_contains_core_injection_classes(self) -> None:
        catalog = set(CapabilityCatalog.from_platform())
        assert {"sql-injection", "xss", "ssrf", "authorization", "idor"}.issubset(catalog)


class TestRepresentation:
    def test_simple_web_app_shape(self) -> None:
        service = _service(SIMPLE_WEB_APP)
        feed(service, SIMPLE_WEB_APP)
        snapshot = service.snapshot()
        assert snapshot["surfaces"] >= 4
        assert snapshot["inputs"] >= 2
        kinds = set(snapshot["kinds"])
        assert kinds >= set(SIMPLE_WEB_APP.expected_kinds)

    def test_rest_api_shape(self) -> None:
        service = _service(REST_API)
        feed(service, REST_API)
        snapshot = service.snapshot()
        assert set(snapshot["kinds"]) >= set(REST_API.expected_kinds)
        objects = {obj.object_type for obj in service.graph.objects()}
        assert "order" in objects

    def test_graphql_shape(self) -> None:
        service = _service(GRAPHQL_API)
        feed(service, GRAPHQL_API)
        kinds = set(service.snapshot()["kinds"])
        assert "graphql_operation" in kinds

    def test_authenticated_shape_carries_auth_context(self) -> None:
        service = _service(AUTHENTICATED_APP)
        feed(service, AUTHENTICATED_APP)
        auth_nodes = [
            node for node in service.graph.nodes() if node.kind_value() == "auth_surface"
        ]
        assert auth_nodes
        assert auth_nodes[0].layer is SurfaceLayer.STATE

    def test_multi_user_shape_captures_dynamic_objects(self) -> None:
        service = _service(MULTI_USER_APP)
        feed(service, MULTI_USER_APP)
        object_types = {obj.object_type for obj in service.graph.objects()}
        assert {"workspace", "document"}.issubset(object_types)

    def test_file_handling_shape(self) -> None:
        service = _service(FILE_HANDLING_APP)
        feed(service, FILE_HANDLING_APP)
        capabilities = {a.capability_id for a in service.graph.assignments()}
        assert {"lfi", "xxe"}.issubset(capabilities)

    def test_workflow_shape_captures_workflows(self) -> None:
        service = _service(WORKFLOW_DRIVEN_APP)
        feed(service, WORKFLOW_DRIVEN_APP)
        workflows = {node.name for node in service.graph.surfaces_for(layer=SurfaceLayer.WORKFLOW)}
        assert {"checkout", "onboarding"}.issubset(workflows)


class TestCapabilityScheduling:
    def test_every_shape_schedules_assessments(self) -> None:
        for shape in ALL_SHAPES:
            service = _service(shape)
            feed(service, shape)
            assert service.queue.total() > 0, f"{shape.name} must schedule assessments"
            assert service.queue.remaining() > 0

    def test_mapping_respects_context(self) -> None:
        # A plain non-fetch parameter must not schedule SSRF; a fetch hint must.
        service = _service(SIMPLE_WEB_APP)
        feed(service, SIMPLE_WEB_APP)
        plain = service.graph.upsert(
            "endpoint:https://shop.example.com/search",
            kind="parameter",
            name="q",
            context=SurfaceContext(fetch_hint=False),
        )
        service._map_and_schedule(plain[0])
        assert not any(
            task.capability_id == "ssrf" for task in service.queue.by_surface("parameter:q")
        )
        fetch = service.graph.upsert(
            "endpoint:https://shop.example.com/search",
            kind="parameter",
            name="url",
            context=SurfaceContext(fetch_hint=True),
        )
        service._map_and_schedule(fetch[0])
        assert any(
            task.capability_id == "ssrf" for task in service.queue.by_surface("parameter:url")
        )

    def test_authenticated_object_schedules_authorization(self) -> None:
        service = _service(MULTI_USER_APP)
        service.on_observation(
            observation_type="object",
            content={
                "objects": [
                    {
                        "object_type": "document",
                        "id": "doc-7",
                        "identifiers": ["doc-7"],
                        "multi_tenant": True,
                    }
                ]
            },
            asset_key="https://collab.example.com/api/documents",
            source="fixture",
            session_state="multi_user",
        )
        tasks = {
            task.capability_id
            for task in service.queue.tasks()
            if task.context.auth_state is AuthContextState.MULTI_USER
        }
        assert "authorization" in tasks

    def test_discovery_capabilities_scheduled_for_assets(self) -> None:
        service = _service(SIMPLE_WEB_APP)
        feed(service, SIMPLE_WEB_APP)
        discovery_tasks = {task.capability_id for task in service.queue.tasks()}
        assert "parameter_discovery" in discovery_tasks


class TestExhaustionFlow:
    def test_service_reaches_exhaustion_after_full_assessment(self) -> None:
        service = _service(SIMPLE_WEB_APP)
        feed(service, SIMPLE_WEB_APP)
        _settle_all(service, VerificationState.VERIFIED)
        for _ in range(4):
            service.on_observation(
                observation_type="endpoint",
                content={},
                asset_key=SIMPLE_WEB_APP.target,
                source="fixture",
            )
        report = service.exhaustion()
        assert report.verdict is CompletionVerdict.EXHAUSTED
        assert report.satisfied()

    def test_service_not_exhausted_with_pending_assessments(self) -> None:
        service = _service(SIMPLE_WEB_APP)
        feed(service, SIMPLE_WEB_APP)
        report = service.exhaustion()
        assert report.verdict is CompletionVerdict.NOT_EXHAUSTED

    def test_target_unavailable_is_explicit(self) -> None:
        service = _service(SIMPLE_WEB_APP)
        service.mark_unavailable("dns resolution failed")
        report = service.exhaustion()
        assert report.verdict is CompletionVerdict.TARGET_UNAVAILABLE


class TestIsolation:
    def test_services_are_mission_scoped(self) -> None:
        one = _service(SIMPLE_WEB_APP)
        two = _service(MULTI_USER_APP)
        feed(one, SIMPLE_WEB_APP)
        assert two.graph.node_count() == 0
        assert two.queue.total() == 0
