# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Universal discovery enums.

target-agnostic vocabulary for the universal discovery pipeline.
"""

from __future__ import annotations

from enum import StrEnum


class DiscoveryStage(StrEnum):
    """Canonical ordered layers of the universal discovery pipeline.

    The order is the pipeline's execution order: each layer expands the surface
    discovered so far, and newly discovered assets feed the following layers
    (continuous/recursive discovery).
    """

    ASSET = "asset"
    DNS = "dns"
    SUBDOMAIN = "subdomain"
    HOST = "host"
    PORT = "port"
    SERVICE = "service"
    TECHNOLOGY = "technology"
    HTTP = "http"
    API = "api"
    GRAPHQL = "graphql"
    JAVASCRIPT = "javascript"
    WORKFLOW = "workflow"
    AUTH = "auth"


class DiscoveryState(StrEnum):
    """Honest outcome states for one discovery provider or stage.

    A provider that cannot run is reported as ``UNAVAILABLE``, never as
    completion and never silently. ``NOT_APPLICABLE`` records a genuine "this
    capability does not apply to the target" verdict (e.g. no GraphQL surface
    was discovered), mirroring the attack-surface completion gate.
    """

    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"
    FAILED = "failed"
    PARTIAL = "partial"
    NOT_APPLICABLE = "not_applicable"
    COMPLETED = "completed"


class DiscoveryLayer(StrEnum):
    """Canonical asset-layer classification for a discovered asset.

    Mirrors the attack-surface graph layers so a discovered asset can be routed
    onto the right surface kind without any target-specific knowledge.
    """

    ASSET = "asset"
    SERVICE = "service"
    APPLICATION = "application"
    SURFACE = "surface"
    INPUT = "input"
    OBJECT = "object"
    STATE = "state"
    WORKFLOW = "workflow"


__all__ = ["DiscoveryLayer", "DiscoveryStage", "DiscoveryState"]
