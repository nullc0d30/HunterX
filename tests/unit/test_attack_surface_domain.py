# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for the target-agnostic attack-surface domain model.

Covers the generic data model, surface-kind registry, layered graph, the
``Capability × Surface × Context`` mapper, the universal assessment queue and
the exhaustion completion gate. Every test uses synthetic, abstract surfaces —
never a real product's routes or objects.
"""

from __future__ import annotations

from hunterx.domain.attack_surface.capability_map import CapabilityMapper
from hunterx.domain.attack_surface.completion import CompletionGate
from hunterx.domain.attack_surface.enums import (
    AssessmentStatus,
    AuthContextState,
    CompletionVerdict,
    ExhaustionCriterion,
    SurfaceKind,
    SurfaceLayer,
    VerificationState,
)
from hunterx.domain.attack_surface.graph import SurfaceGraph
from hunterx.domain.attack_surface.models import (
    AssessmentTask,
    CapabilityAssignment,
    DynamicObject,
    SurfaceContext,
    SurfaceNode,
    layer_for,
    surface_key,
)
from hunterx.domain.attack_surface.queue import AssessmentQueue, schedule_assignments
from hunterx.domain.attack_surface.registry import SurfaceKindRegistry

_CATALOG = [
    "api-security",
    "authentication",
    "authorization",
    "command-injection",
    "graphql-security",
    "http-access-differential",
    "idor",
    "lfi",
    "nosql-injection",
    "open-redirect",
    "sql-injection",
    "ssrf",
    "ssti",
    "xss",
    "xxe",
]


class TestSurfaceKindsAndLayers:
    def test_every_surface_kind_maps_to_a_layer(self) -> None:
        for kind in SurfaceKind:
            assert layer_for(kind) is not SurfaceLayer.TARGET or kind is SurfaceKind.TARGET

    def test_input_surfaces_map_to_input_layer(self) -> None:
        for kind in (SurfaceKind.PARAMETER, SurfaceKind.JSON_FIELD, SurfaceKind.FORM_FIELD, SurfaceKind.COOKIE):
            assert layer_for(kind) is SurfaceLayer.INPUT

    def test_object_surfaces_map_to_object_layer(self) -> None:
        assert layer_for(SurfaceKind.OBJECT) is SurfaceLayer.OBJECT
        assert layer_for(SurfaceKind.OBJECT_IDENTIFIER) is SurfaceLayer.OBJECT

    def test_workflow_surfaces_map_to_workflow_layer(self) -> None:
        assert layer_for(SurfaceKind.WORKFLOW) is SurfaceLayer.WORKFLOW
        assert layer_for(SurfaceKind.STATE_TRANSITION) is SurfaceLayer.WORKFLOW

    def test_assessment_status_terminal_and_actionable(self) -> None:
        assert AssessmentStatus.COMPLETED.is_terminal
        assert AssessmentStatus.FAILED.is_terminal
        assert not AssessmentStatus.PENDING.is_terminal
        assert AssessmentStatus.READY.is_actionable
        assert not AssessmentStatus.SKIPPED.is_actionable

    def test_verification_settled_states(self) -> None:
        for state in (VerificationState.VERIFIED, VerificationState.CONFIRMED, VerificationState.NOT_APPLICABLE):
            assert state.is_settled
        assert not VerificationState.UNVERIFIED.is_settled


class TestSurfaceModels:
    def test_surface_key_is_kind_colon_name(self) -> None:
        assert surface_key(SurfaceKind.ENDPOINT, "https://example.com/x") == "endpoint:https://example.com/x"

    def test_surface_node_key_derived_when_empty(self) -> None:
        node = SurfaceNode(kind=SurfaceKind.PARAMETER, name="id")
        assert node.key == "parameter:id"

    def test_surface_node_to_dict_roundtrip(self) -> None:
        node = SurfaceNode(kind=SurfaceKind.API_ENDPOINT, name="https://api.example.com/v1/orders")
        payload = node.to_dict()
        assert payload["kind"] == "api_endpoint"
        assert payload["layer"] == SurfaceLayer.SURFACE.value

    def test_dynamic_object_holds_arbitrary_target_object_types(self) -> None:
        obj = DynamicObject(
            mission_id="m1",
            target_key="https://api.example.com",
            object_type="order",
            name="ord-9",
            identifiers=("ord-9",),
        )
        assert obj.object_type == "order"
        assert obj.key.startswith("object:order:")
        assert obj.to_dict()["object_type"] == "order"

    def test_context_key_changes_with_auth_state(self) -> None:
        base = SurfaceContext(auth_state=AuthContextState.ANONYMOUS)
        authed = SurfaceContext(auth_state=AuthContextState.AUTHENTICATED)
        assert base.context_key() != authed.context_key()

    def test_assessment_task_dedup_key_includes_context(self) -> None:
        one = AssessmentTask(surface_key="parameter:id", capability_id="xss", context=SurfaceContext())
        two = AssessmentTask(
            surface_key="parameter:id",
            capability_id="xss",
            context=SurfaceContext(auth_state=AuthContextState.AUTHENTICATED),
        )
        assert one.dedup_key() == one.dedup_key()
        assert one.dedup_key() != two.dedup_key()


class TestSurfaceKindRegistry:
    def test_classifies_observation_types(self) -> None:
        registry = SurfaceKindRegistry()
        assert registry.classify("endpoint") == SurfaceKind.ENDPOINT.value
        assert registry.classify("parameter") == SurfaceKind.PARAMETER.value
        assert registry.classify("api") == SurfaceKind.API_ENDPOINT.value
        assert registry.classify("auth") == SurfaceKind.AUTH_SURFACE.value
        assert registry.classify("object") == SurfaceKind.OBJECT.value

    def test_classifies_unknown_honestly(self) -> None:
        registry = SurfaceKindRegistry()
        assert registry.classify("wibble") == SurfaceKind.UNKNOWN.value

    def test_registers_new_kinds_without_core_changes(self) -> None:
        registry = SurfaceKindRegistry()
        spec = registry.register_kind(
            "smart_widget",
            layer=SurfaceLayer.OBJECT,
            observation_types=("widget",),
            capability_hints=("authorization",),
            description="a synthetic target-specific object kind",
        )
        assert spec.kind == "smart_widget"
        assert registry.classify("widget") == "smart_widget"
        assert registry.layer("smart_widget") is SurfaceLayer.OBJECT
        assert registry.default_capabilities("smart_widget") == ("authorization",)


class TestSurfaceGraph:
    def _graph(self) -> SurfaceGraph:
        graph = SurfaceGraph()
        graph.set_target(mission_id="m1", target_key="https://example.com")
        graph.upsert("https://example.com", kind=SurfaceKind.HOST, name="example.com")
        endpoint, is_new = graph.upsert(
            "host:example.com",
            kind=SurfaceKind.ENDPOINT,
            name="https://example.com/search",
            context=SurfaceContext(method="GET"),
        )
        assert is_new
        return graph

    def test_layered_parent_child_walk(self) -> None:
        graph = self._graph()
        graph.upsert("endpoint:https://example.com/search", kind=SurfaceKind.PARAMETER, name="q")
        assert graph.parent("endpoint:https://example.com/search").name == "example.com"
        inputs = graph.inputs_of("endpoint:https://example.com/search")
        assert [node.name for node in inputs] == ["q"]
        kinds = {node.kind_value() for node in graph.nodes()}
        assert "endpoint" in kinds and "host" in kinds and "parameter" in kinds

    def test_upsert_is_idempotent(self) -> None:
        graph = self._graph()
        _, first = graph.upsert("endpoint:https://example.com/search", kind=SurfaceKind.PARAMETER, name="q")
        _, second = graph.upsert("endpoint:https://example.com/search", kind=SurfaceKind.PARAMETER, name="q")
        assert first is True and second is False
        assert graph.node_count() == 4

    def test_arbitrary_kinds_do_not_break_traversal(self) -> None:
        graph = self._graph()
        graph.upsert("endpoint:https://example.com/search", kind="smart_widget", name="wx-1")
        nodes = graph.nodes(kind="smart_widget")
        assert len(nodes) == 1
        assert nodes[0].layer is SurfaceLayer.SURFACE  # unknown kinds default to SURFACE

    def test_dynamic_objects_are_stored(self) -> None:
        graph = self._graph()
        graph.add_object(
            DynamicObject(
                mission_id="m1",
                target_key="https://example.com",
                object_type="product",
                name="sku-1",
                key="object:product:sku-1",
                identifiers=("sku-1",),
                parent_key="endpoint:https://example.com/search",
            )
        )
        assert graph.object_count() == 1
        assert graph.objects()[0].object_type == "product"


class TestCapabilityMapper:
    def test_maps_input_surface_to_injection_capabilities(self) -> None:
        mapper = CapabilityMapper(_CATALOG)
        surface = SurfaceNode(kind=SurfaceKind.PARAMETER, name="q", context=SurfaceContext())
        capabilities = mapper.applicable_capabilities(surface)
        assert "sql-injection" in {cap for cap, _, _ in capabilities}
        assert "xss" in {cap for cap, _, _ in capabilities}

    def test_fetch_surface_maps_to_ssrf(self) -> None:
        mapper = CapabilityMapper(_CATALOG)
        surface = SurfaceNode(
            kind=SurfaceKind.PARAMETER,
            name="url",
            context=SurfaceContext(fetch_hint=True),
        )
        capabilities = mapper.applicable_capabilities(surface)
        assert "ssrf" in {cap for cap, _, _ in capabilities}

    def test_object_surface_maps_to_authorization_and_idor(self) -> None:
        mapper = CapabilityMapper(_CATALOG)
        surface = SurfaceNode(
            kind=SurfaceKind.OBJECT,
            name="order",
            context=SurfaceContext(object_hint=True, auth_state=AuthContextState.AUTHENTICATED),
        )
        capabilities = {cap for cap, _, _ in mapper.applicable_capabilities(surface)}
        assert "authorization" in capabilities
        assert "idor" in capabilities

    def test_auth_surface_maps_to_authentication(self) -> None:
        mapper = CapabilityMapper(_CATALOG)
        surface = SurfaceNode(kind=SurfaceKind.AUTH_SURFACE, name="login")
        capabilities = {cap for cap, _, _ in mapper.applicable_capabilities(surface)}
        assert "authentication" in capabilities

    def test_graphql_surface_maps_to_graphql_security(self) -> None:
        mapper = CapabilityMapper(_CATALOG)
        surface = SurfaceNode(kind=SurfaceKind.GRAPHQL_OPERATION, name="user")
        capabilities = {cap for cap, _, _ in mapper.applicable_capabilities(surface)}
        assert "graphql-security" in capabilities

    def test_catalog_is_authoritative(self) -> None:
        mapper = CapabilityMapper(["sql-injection", "authorization"])
        surface = SurfaceNode(kind=SurfaceKind.PARAMETER, name="q")
        capabilities = {cap for cap, _, _ in mapper.applicable_capabilities(surface)}
        assert capabilities == {"sql-injection"}
        assert not mapper.is_capability_supported("xss")

    def test_workflow_surface_maps_to_access_control(self) -> None:
        mapper = CapabilityMapper(_CATALOG)
        surface = SurfaceNode(kind=SurfaceKind.WORKFLOW, name="checkout")
        capabilities = {cap for cap, _, _ in mapper.applicable_capabilities(surface)}
        assert "http-access-differential" in capabilities

    def test_map_for_returns_assignments_with_rationale(self) -> None:
        mapper = CapabilityMapper(_CATALOG)
        surface = SurfaceNode(kind=SurfaceKind.PARAMETER, name="q")
        assignments = mapper.map_for(surface)
        assert assignments
        assert all(assignment.applicable for assignment in assignments)
        assert all(assignment.rationale for assignment in assignments)
        assert len({assignment.capability_id for assignment in assignments}) == len(assignments)


class TestAssessmentQueue:
    def test_submit_deduplicates_by_surface_capability_context(self) -> None:
        queue = AssessmentQueue()
        first = queue.submit(surface_key="parameter:id", capability_id="xss")
        second = queue.submit(surface_key="parameter:id", capability_id="xss")
        assert first.task_id == second.task_id
        assert queue.total() == 1

    def test_context_change_creates_new_task(self) -> None:
        queue = AssessmentQueue()
        queue.submit(surface_key="parameter:id", capability_id="xss")
        queue.submit(
            surface_key="parameter:id",
            capability_id="xss",
            context=SurfaceContext(auth_state=AuthContextState.AUTHENTICATED),
        )
        assert queue.total() == 2

    def test_ready_ordered_by_priority(self) -> None:
        queue = AssessmentQueue()
        queue.submit(surface_key="a", capability_id="xss", priority=90.0)
        queue.submit(surface_key="b", capability_id="xss", priority=10.0)
        assert [task.surface_key for task in queue.ready()] == ["b", "a"]

    def test_exhausted_after_all_terminal(self) -> None:
        queue = AssessmentQueue()
        task = queue.submit(surface_key="a", capability_id="xss")
        assert not queue.exhausted()
        queue.mark(task.task_id, AssessmentStatus.COMPLETED)
        assert queue.exhausted()

    def test_schedule_assignments_maps_priority(self) -> None:
        queue = AssessmentQueue()
        assignment = CapabilityAssignment(surface_key="parameter:q", capability_id="xss", priority=0.8)
        tasks = schedule_assignments(queue, [assignment], mission_id="m1")
        assert len(tasks) == 1
        assert tasks[0].priority < 30.0  # high importance -> low scheduling value


class TestCompletionGate:
    def _service_state(self, queue: AssessmentQueue, graph: SurfaceGraph) -> tuple[CompletionGate, AssessmentQueue, SurfaceGraph]:
        gate = CompletionGate(stale_window=2)
        graph.set_target(mission_id="m1", target_key="https://example.com")
        graph.upsert("https://example.com", kind=SurfaceKind.ENDPOINT, name="https://example.com/x")
        graph.upsert("endpoint:https://example.com/x", kind=SurfaceKind.PARAMETER, name="q")
        return gate, queue, graph

    def _settle_all(self, graph: SurfaceGraph, queue: AssessmentQueue, state: VerificationState) -> None:
        for assignment in graph.assignments():
            assignment.mark(AssessmentStatus.COMPLETED)
            assignment.settle(state)
        for task in queue.tasks():
            queue.mark(task.task_id, AssessmentStatus.COMPLETED)
            queue.settle(task.task_id, state)

    def test_not_exhausted_while_assessments_pending(self) -> None:
        graph = SurfaceGraph()
        queue = AssessmentQueue()
        gate, _, _ = self._service_state(queue, graph)
        mapper = CapabilityMapper(_CATALOG)
        for node in graph.nodes():
            for assignment in mapper.map_for(node):
                graph.attach_assignment(assignment)
            schedule_assignments(queue, mapper.map_for(node), mission_id="m1")
        for _ in range(4):
            gate.record_observation(surfaces_before=graph.node_count(), surfaces_after=graph.node_count())
        report = gate.evaluate(graph, queue)
        assert report.verdict is CompletionVerdict.NOT_EXHAUSTED
        assert not report.criteria[ExhaustionCriterion.ASSESSMENT_QUEUE_EXHAUSTED.value]

    def test_exhausted_when_everything_done(self) -> None:
        graph = SurfaceGraph()
        queue = AssessmentQueue()
        gate, _, _ = self._service_state(queue, graph)
        mapper = CapabilityMapper(_CATALOG)
        for node in graph.nodes():
            for assignment in mapper.map_for(node):
                graph.attach_assignment(assignment)
            schedule_assignments(queue, mapper.map_for(node), mission_id="m1")
        self._settle_all(graph, queue, VerificationState.VERIFIED)
        for _ in range(4):
            gate.record_observation(surfaces_before=graph.node_count(), surfaces_after=graph.node_count())
        report = gate.evaluate(graph, queue)
        assert report.verdict is CompletionVerdict.EXHAUSTED
        assert report.satisfied()
        assert all(report.criteria.values())

    def test_target_unavailable_never_converts_to_completion(self) -> None:
        gate = CompletionGate()
        gate.mark_unavailable("connection reset")
        report = gate.evaluate(SurfaceGraph(), AssessmentQueue())
        assert report.verdict is CompletionVerdict.TARGET_UNAVAILABLE
        assert report.unavailable_reason == "connection reset"

    def test_blocked_never_converts_to_completion(self) -> None:
        gate = CompletionGate()
        gate.mark_blocked("no tools available")
        report = gate.evaluate(SurfaceGraph(), AssessmentQueue())
        assert report.verdict is CompletionVerdict.BLOCKED
        assert report.blocked_reason == "no tools available"

    def test_zero_surface_target_is_not_exhausted(self) -> None:
        gate = CompletionGate(stale_window=2)
        for _ in range(4):
            gate.record_observation(surfaces_before=0, surfaces_after=0)
        report = gate.evaluate(SurfaceGraph(), AssessmentQueue())
        assert report.verdict is CompletionVerdict.NOT_EXHAUSTED
        assert not report.criteria[ExhaustionCriterion.DISCOVERY_EXHAUSTED.value]


class TestExtensibility:
    def test_new_surface_kind_requires_no_core_changes(self) -> None:
        registry = SurfaceKindRegistry()
        registry.register_kind("edge_device", layer=SurfaceLayer.OBJECT)
        graph = SurfaceGraph(registry=registry)
        graph.set_target(mission_id="m1", target_key="https://iot.example.com")
        node, is_new = graph.upsert(
            "https://iot.example.com", kind="edge_device", name="cam-1", context=SurfaceContext()
        )
        assert is_new
        assert node.layer is SurfaceLayer.OBJECT
        # Core traversal still works over the unregistered kind string.
        assert graph.parent(node.key).key == "https://iot.example.com"
