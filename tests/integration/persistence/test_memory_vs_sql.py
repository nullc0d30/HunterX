# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Memory vs SQL platform switching tests (Sprint 034.3 §16).

The platform composes the same repository ports for both backends. Application
behavior must remain consistent regardless of which backend is selected, and no
application code may depend directly on a concrete SQL repository.
"""

from __future__ import annotations

import pytest

pytest.importorskip("sqlalchemy")

from hunterx.config.settings import DatabaseSettings, Settings
from hunterx.infrastructure.db.sql.crud import SqlTidbRepositoryFactory
from hunterx.infrastructure.db.sql.memory import InMemoryTidbRepositoryFactory
from hunterx.platform import build_platform


@pytest.fixture()
def memory_platform():
    platform = build_platform(Settings())
    try:
        yield platform
    finally:
        session_factory = platform.repositories.get("session_factory")
        if session_factory is not None:
            session_factory.dispose()


@pytest.fixture()
def sql_platform():
    platform = build_platform(Settings(database=DatabaseSettings(url="sqlite:///:memory:")))
    try:
        yield platform
    finally:
        session_factory = platform.repositories.get("session_factory")
        if session_factory is not None:
            session_factory.dispose()


def test_both_backends_share_the_same_ports(memory_platform, sql_platform) -> None:
    # The TidbRepositoryFactory port resolves on both backends.
    assert memory_platform.tidb is not None
    assert sql_platform.tidb is not None

    # Default settings → in-memory TIDB factory; SQL URL → SQL factory.
    assert isinstance(memory_platform.tidb, InMemoryTidbRepositoryFactory)
    assert isinstance(sql_platform.tidb, SqlTidbRepositoryFactory)

    # Both platforms expose the entity repository roles.
    for role in ("missions", "findings", "targets", "scans", "assets", "reports"):
        assert role in memory_platform.repositories
        assert role in sql_platform.repositories


def test_mission_lifecycle_is_consistent_across_backends(memory_platform, sql_platform) -> None:
    """The same mission flow behaves identically on both backends."""
    results = {}
    for label, platform in (("memory", memory_platform), ("sql", sql_platform)):
        service = platform.mission_orchestration_service
        mission = service.create_mission(target="https://example.com", objective="web")
        mission_id = mission.mission_id
        service.start(mission_id)
        service.ingest_result(mission_id, tool_id="httpx", asset_key="https://example.com", raw={"status": 200})
        service.add_hypothesis(mission_id, statement="XSS on search", category="injection")
        status = service.status(mission_id)
        query = platform.mission_orchestration_query_service
        observations = query.observations(mission_id)
        hypotheses = query.hypotheses(mission_id)
        results[label] = {
            "mission_id": mission_id,
            "current_phase": status["current_phase"],
            "observations": len(observations),
            "hypotheses": len(hypotheses),
        }

    assert results["memory"]["current_phase"] == results["sql"]["current_phase"]
    assert results["memory"]["observations"] == results["sql"]["observations"] == 1
    assert results["memory"]["hypotheses"] == results["sql"]["hypotheses"] == 1


def test_target_intelligence_is_consistent_across_backends(memory_platform, sql_platform) -> None:
    from hunterx.domain.target_intelligence import IntelligenceTarget

    for platform in (memory_platform, sql_platform):
        service = platform.target_intelligence_service
        target = IntelligenceTarget(
            target_id="tgt-cross",
            mission_id="mis-cross",
            value="example.com",
            kind="domain",
            scope="prod",
            tenant="tenant-1",
        )
        service.register_target(target)
        query = platform.target_intelligence_query_service
        assert query.get_target("tgt-cross") is not None


def test_default_settings_remain_in_memory(sql_platform) -> None:
    """A default build (no explicit URL) must stay in-memory — the documented
    zero-dependency mode — while a non-default URL activates SQL."""
    default_platform = build_platform(Settings())
    try:
        assert isinstance(default_platform.tidb, InMemoryTidbRepositoryFactory)
        assert default_platform.repositories.get("session_factory") is None
        assert isinstance(sql_platform.tidb, SqlTidbRepositoryFactory)
        assert sql_platform.repositories.get("session_factory") is not None
    finally:
        sf = default_platform.repositories.get("session_factory")
        if sf is not None:
            sf.dispose()
