# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Shared pytest fixtures.

NOTE: this repo still carries the retired v6 flat ``hunterx/`` package at the repo root.
"""

from __future__ import annotations

import os
import sys

_SRC = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
if _SRC in sys.path:
    sys.path.remove(_SRC)
sys.path.insert(0, _SRC)

import pytest

from hunterx.infrastructure.cache import MemoryCache
from hunterx.infrastructure.db.graph import InMemoryKnowledgeGraph
from hunterx.infrastructure.event_bus import InMemoryEventBus
from hunterx.infrastructure.queue import MemoryQueue
from tests.framework.inmemory import (
    InMemoryAssetRepository,
    InMemoryFindingRepository,
    InMemoryMissionRepository,
    InMemoryReportRepository,
    InMemoryScanRepository,
    InMemoryTargetRepository,
)


@pytest.fixture
def mission_repository() -> InMemoryMissionRepository:
    """A fresh in-memory mission repository."""
    return InMemoryMissionRepository()


@pytest.fixture
def finding_repository() -> InMemoryFindingRepository:
    """A fresh in-memory finding repository."""
    return InMemoryFindingRepository()


@pytest.fixture
def report_repository() -> InMemoryReportRepository:
    """A fresh in-memory report repository."""
    return InMemoryReportRepository()


@pytest.fixture
def target_repository() -> InMemoryTargetRepository:
    """A fresh in-memory target repository."""
    return InMemoryTargetRepository()


@pytest.fixture
def scan_repository() -> InMemoryScanRepository:
    """A fresh in-memory scan repository."""
    return InMemoryScanRepository()


@pytest.fixture
def asset_repository() -> InMemoryAssetRepository:
    """A fresh in-memory asset repository."""
    return InMemoryAssetRepository()


@pytest.fixture
def event_bus() -> InMemoryEventBus:
    """A fresh in-memory event bus."""
    return InMemoryEventBus()


@pytest.fixture
def queue() -> MemoryQueue:
    """A fresh in-memory queue."""
    return MemoryQueue()


@pytest.fixture
def cache() -> MemoryCache:
    """A fresh in-memory cache."""
    return MemoryCache()


@pytest.fixture
def knowledge_graph() -> InMemoryKnowledgeGraph:
    """A fresh in-memory knowledge graph store."""
    return InMemoryKnowledgeGraph()


@pytest.fixture(scope="session", autouse=True)
def loopback_fixture_server():
    """Serve the vulnerable test app on port 3010 for integration tests.

    Several integration and acceptance tests point at ``http://localhost:3010``
    and expect the local fixture app to be running. Starting it here keeps a
    plain ``pytest`` run self-contained; if the port is already in use we leave
    whatever is listening there alone.
    """
    import socket

    from tests.framework.vulnerable_app import VulnerableApp

    with socket.socket() as probe:
        if probe.connect_ex(("127.0.0.1", 3010)) == 0:
            yield None
            return
    try:
        app = VulnerableApp(port=3010).start()
    except OSError:
        yield None
        return
    try:
        yield app
    finally:
        app.stop()
