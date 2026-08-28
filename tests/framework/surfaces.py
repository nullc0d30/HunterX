# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Synthetic abstract target shapes for attack-surface testing.

Phase 1 test fixtures only. Each shape is an *abstract target type* — a simple
web app, a REST API, a GraphQL API, an authenticated application, a multi-user
application, a file-handling application and a workflow-driven application.
They deliberately model no real product (and in particular not OWASP Juice
Shop); they exist solely to prove the target-agnostic surface model can
represent, map and schedule arbitrary discovered surfaces without knowing the
target in advance.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class ObservationEvent:
    """A single discovery observation fed to the attack-surface service.

    Attributes:
        observation_type: canonical observation-type string (endpoint,
            parameter, object, workflow, technology, ...).
        content: discovery payload dict (crawl/parameters/objects/...).
        asset_key: the asset the observation was collected against.
        session_state: optional session-state hint.

    """

    observation_type: str
    content: dict[str, Any]
    asset_key: str = ""
    session_state: str = ""


@dataclass(frozen=True, slots=True)
class TargetShape:
    """A synthetic abstract target with its discovery observation feed.

    Attributes:
        name: shape name (``simple_web_app``, ``rest_api``, ...).
        target: authorized target key.
        observations: ordered discovery events for the shape.
        expected_kinds: surface kinds the model should represent.
        expected_capabilities: capability ids the mapping should schedule.
        expected_objects: dynamic object types the model should capture.
        expected_workflows: workflow names the model should capture.

    """

    name: str
    target: str
    observations: tuple[ObservationEvent, ...] = ()
    expected_kinds: tuple[str, ...] = ()
    expected_capabilities: tuple[str, ...] = ()
    expected_objects: tuple[str, ...] = ()
    expected_workflows: tuple[str, ...] = ()


SIMPLE_WEB_APP = TargetShape(
    name="simple_web_app",
    target="https://shop.example.com",
    observations=(
        ObservationEvent(
            "endpoint",
            {"urls": ["https://shop.example.com/", "https://shop.example.com/search"]},
            "https://shop.example.com",
        ),
        ObservationEvent(
            "parameter",
            {"parameters": [{"name": "q", "method": "GET"}, {"name": "page"}]},
            "https://shop.example.com/search",
        ),
        ObservationEvent(
            "technology",
            {"name": "django", "technologies": ["Django", "PostgreSQL"]},
            "https://shop.example.com",
        ),
    ),
    expected_kinds=("endpoint", "parameter", "technology", "host"),
    expected_capabilities=("sql-injection", "xss", "ssrf"),
    expected_objects=(),
    expected_workflows=(),
)

REST_API = TargetShape(
    name="rest_api",
    target="https://api.example.com",
    observations=(
        ObservationEvent(
            "api",
            {"endpoints": ["https://api.example.com/v1/orders", "https://api.example.com/v1/users"]},
            "https://api.example.com/v1",
        ),
        ObservationEvent(
            "parameter",
            {
                "parameters": [
                    {"name": "id", "method": "GET"},
                    {"name": "status", "method": "GET"},
                    {"name": "url", "method": "GET"},
                ]
            },
            "https://api.example.com/v1/orders",
        ),
        ObservationEvent(
            "object",
            {"objects": [{"object_type": "order", "id": "ord-9", "identifiers": ["ord-9"]}]},
            "https://api.example.com/v1/orders",
        ),
    ),
    expected_kinds=("api_endpoint", "parameter", "object", "object_identifier"),
    expected_capabilities=("api-security", "authorization", "idor", "ssrf"),
    expected_objects=("order",),
    expected_workflows=(),
)

GRAPHQL_API = TargetShape(
    name="graphql_api",
    target="https://gql.example.com/graphql",
    observations=(
        ObservationEvent(
            "graphql",
            {"endpoints": ["https://gql.example.com/graphql"]},
            "https://gql.example.com/graphql",
        ),
        ObservationEvent(
            "parameter",
            {"parameters": [{"name": "query", "method": "POST"}, {"name": "id"}]},
            "https://gql.example.com/graphql",
        ),
    ),
    expected_kinds=("graphql_operation", "parameter"),
    expected_capabilities=("graphql-security", "authorization"),
    expected_objects=(),
    expected_workflows=(),
)

AUTHENTICATED_APP = TargetShape(
    name="authenticated_app",
    target="https://portal.example.com",
    observations=(
        ObservationEvent(
            "auth",
            {"url": "https://portal.example.com/login", "surface_kind": "login"},
            "https://portal.example.com/login",
        ),
        ObservationEvent(
            "endpoint",
            {"urls": ["https://portal.example.com/account", "https://portal.example.com/profile"]},
            "https://portal.example.com",
        ),
        ObservationEvent(
            "parameter",
            {"parameters": [{"name": "username"}, {"name": "password"}]},
            "https://portal.example.com/login",
            session_state="authenticated",
        ),
    ),
    expected_kinds=("auth_surface", "endpoint", "parameter"),
    expected_capabilities=("authentication", "authorization"),
    expected_objects=(),
    expected_workflows=(),
)

MULTI_USER_APP = TargetShape(
    name="multi_user_app",
    target="https://collab.example.com",
    observations=(
        ObservationEvent(
            "endpoint",
            {"urls": ["https://collab.example.com/api/workspaces", "https://collab.example.com/api/documents"]},
            "https://collab.example.com",
            session_state="multi_user",
        ),
        ObservationEvent(
            "object",
            {
                "objects": [
                    {"object_type": "workspace", "id": "ws-1", "identifiers": ["ws-1"], "multi_tenant": True},
                    {"object_type": "document", "id": "doc-42", "identifiers": ["doc-42"], "multi_tenant": True},
                ]
            },
            "https://collab.example.com/api/documents",
            session_state="multi_user",
        ),
    ),
    expected_kinds=("endpoint", "object", "object_identifier"),
    expected_capabilities=("authorization", "idor"),
    expected_objects=("workspace", "document"),
    expected_workflows=(),
)

FILE_HANDLING_APP = TargetShape(
    name="file_handling_app",
    target="https://files.example.com",
    observations=(
        ObservationEvent(
            "endpoint",
            {"urls": ["https://files.example.com/upload", "https://files.example.com/download"]},
            "https://files.example.com",
        ),
        ObservationEvent(
            "parameter",
            {
                "parameters": [
                    {"name": "file", "method": "POST"},
                    {"name": "filename", "method": "GET"},
                    {"name": "download", "method": "GET"},
                ]
            },
            "https://files.example.com/download",
        ),
        ObservationEvent(
            "upload",
            {"urls": ["https://files.example.com/upload"]},
            "https://files.example.com/upload",
        ),
    ),
    expected_kinds=("endpoint", "parameter"),
    expected_capabilities=("lfi", "xxe", "command-injection"),
    expected_objects=(),
    expected_workflows=(),
)

WORKFLOW_DRIVEN_APP = TargetShape(
    name="workflow_driven_app",
    target="https://flows.example.com",
    observations=(
        ObservationEvent(
            "endpoint",
            {"urls": ["https://flows.example.com/checkout", "https://flows.example.com/onboarding"]},
            "https://flows.example.com",
        ),
        ObservationEvent(
            "workflow",
            {"workflows": [{"name": "checkout", "steps": ["cart", "payment", "confirmation"]}]},
            "https://flows.example.com/checkout",
        ),
        ObservationEvent(
            "state_transition",
            {"workflows": [{"name": "onboarding", "transitions": ["pending", "approved", "rejected"]}]},
            "https://flows.example.com/onboarding",
        ),
    ),
    expected_kinds=("endpoint", "workflow"),
    expected_capabilities=("http-access-differential", "authorization"),
    expected_objects=(),
    expected_workflows=("checkout", "onboarding"),
)

CLIENT_HEAVY_APP = TargetShape(
    name="client_heavy_app",
    target="https://spa.example.com",
    observations=(
        ObservationEvent(
            "javascript",
            {"urls": ["https://spa.example.com/main.js", "https://spa.example.com/vendor.js"]},
            "https://spa.example.com",
        ),
        ObservationEvent(
            "client_route",
            {"routes": ["https://spa.example.com/#/dashboard", "https://spa.example.com/#/settings"]},
            "https://spa.example.com",
        ),
        ObservationEvent(
            "sink",
            {"urls": ["https://spa.example.com/main.js"], "sinks": ["innerHTML", "document.write"]},
            "https://spa.example.com/main.js",
        ),
        ObservationEvent(
            "source",
            {"urls": ["https://spa.example.com/main.js"], "sources": ["location.hash", "postMessage"]},
            "https://spa.example.com/main.js",
        ),
    ),
    expected_kinds=("javascript_endpoint", "client_route", "sink", "source"),
    expected_capabilities=("xss", "javascript_analysis"),
    expected_objects=(),
    expected_workflows=(),
)

API_HEAVY_APP = TargetShape(
    name="api_heavy_app",
    target="https://api-heavy.example.com",
    observations=(
        ObservationEvent(
            "api",
            {
                "endpoints": [
                    "https://api-heavy.example.com/v1/search",
                    "https://api-heavy.example.com/v1/upload",
                    "https://api-heavy.example.com/v1/reports",
                ]
            },
            "https://api-heavy.example.com",
        ),
        ObservationEvent(
            "parameter",
            {
                "parameters": [
                    {"name": "q", "method": "GET"},
                    {"name": "callback", "method": "GET"},
                    {"name": "file", "method": "POST"},
                    {"name": "id", "method": "GET"},
                ]
            },
            "https://api-heavy.example.com/v1/search",
        ),
        ObservationEvent(
            "upload",
            {"urls": ["https://api-heavy.example.com/v1/upload"]},
            "https://api-heavy.example.com/v1/upload",
        ),
    ),
    expected_kinds=("api_endpoint", "parameter", "upload"),
    expected_capabilities=("api-security", "lfi", "xxe", "open-redirect", "ssrf"),
    expected_objects=(),
    expected_workflows=(),
)

#: Every abstract target shape available to tests.
ALL_SHAPES: tuple[TargetShape, ...] = (
    SIMPLE_WEB_APP,
    REST_API,
    GRAPHQL_API,
    AUTHENTICATED_APP,
    MULTI_USER_APP,
    FILE_HANDLING_APP,
    WORKFLOW_DRIVEN_APP,
    CLIENT_HEAVY_APP,
    API_HEAVY_APP,
)


def feed(service: Any, shape: TargetShape) -> dict[str, Any]:
    """Feed a target shape's observation events into an attack-surface service.

    Returns the snapshot of the last observation.
    """
    summary: dict[str, Any] = {}
    for event in shape.observations:
        summary = service.on_observation(
            observation_type=event.observation_type,
            content=event.content,
            asset_key=event.asset_key,
            source=f"fixture:{shape.name}",
            session_state=event.session_state,
        )
    return summary


__all__ = [
    "ALL_SHAPES",
    "API_HEAVY_APP",
    "AUTHENTICATED_APP",
    "CLIENT_HEAVY_APP",
    "FILE_HANDLING_APP",
    "GRAPHQL_API",
    "MULTI_USER_APP",
    "ObservationEvent",
    "REST_API",
    "SIMPLE_WEB_APP",
    "TargetShape",
    "WORKFLOW_DRIVEN_APP",
    "feed",
]
