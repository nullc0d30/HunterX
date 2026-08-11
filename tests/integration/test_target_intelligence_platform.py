# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Integration tests: Target Intelligence wired into the platform and TIDB.

Builds the full platform, verifies the TargetIntelligenceService is wired with
the Sprint 025 selector, runs a complete intelligence cycle against the
in-memory TIDB, and verifies the SQL persistence path for the new entities.
"""

from __future__ import annotations

import pytest

from hunterx.domain.entities.tidb.target_intelligence import (
    CoverageRecord,
    IntelligenceActionRecord,
    IntelligenceAssetRecord,
    IntelligenceTargetRecord,
    ObservationRecord,
)
from hunterx.domain.target_intelligence.enums import (
    IntelligenceTargetKind,
    ObservationType,
)
from hunterx.domain.target_intelligence.models import (
    IntelligenceAsset,
    IntelligenceTarget,
    Observation,
)
from hunterx.domain.topology.enums import EntityKind
from hunterx.platform.assembler import build_platform


class TestTargetIntelligencePlatform:
    def test_platform_wires_service_and_selector(self) -> None:
        platform = build_platform()
        assert platform.target_intelligence_service is not None
        assert platform.target_intelligence_query_service is not None
        # The Sprint 025 mission-aware selector is wired into the next-action engine.
        assert platform.target_intelligence_service.engine.next_action.tool_selector is not None
        assert platform.core.target_intelligence is not None

    def test_full_cycle_via_platform(self) -> None:
        platform = build_platform()
        service = platform.target_intelligence_service
        target = IntelligenceTarget(
            target_id="platform-1",
            mission_id="mis-p",
            scope="shop.example.com",
            identity="Shop",
            kind=IntelligenceTargetKind.DOMAIN,
            value="shop.example.com",
        )
        service.register_target(target)
        service.ingest_assets(
            target,
            [
                IntelligenceAsset(
                    target_id="platform-1",
                    mission_id="mis-p",
                    kind=EntityKind.URL,
                    name="https://shop.example.com/api/items/search",
                    properties={"parameters": ["q"]},
                )
            ],
        )
        state, actions, decision = service.run_cycle(
            target, mission_objective="find exploitable vulnerabilities", authorization_granted=True
        )
        assert state.assets
        assert actions
        assert decision.rationale
        # Persisted to the in-memory TIDB (platform default).
        assert platform.target_intelligence_query_service.get_target("platform-1") is not None
        assert platform.target_intelligence_query_service.actions("platform-1")
        assert platform.target_intelligence_query_service.coverage_matrix("platform-1").entries

    def test_platform_query_service_reads_back_all_entities(self) -> None:
        platform = build_platform()
        service = platform.target_intelligence_service
        query = platform.target_intelligence_query_service
        target = IntelligenceTarget(
            target_id="platform-2",
            mission_id="mis-p",
            scope="example.org",
            identity="Org",
            kind=IntelligenceTargetKind.DOMAIN,
            value="example.org",
        )
        service.register_target(target)
        service.ingest_assets(
            target,
            [
                IntelligenceAsset(
                    target_id="platform-2",
                    mission_id="mis-p",
                    kind=EntityKind.URL,
                    name="https://www.example.org/api/search",
                    properties={"parameters": ["q"]},
                )
            ],
        )
        service.ingest_observations(
            target,
            [
                Observation(
                    target_id="platform-2",
                    mission_id="mis-p",
                    tool="httpx",
                    capability="technology_fingerprint",
                    observation_type=ObservationType.TECHNOLOGY,
                    value="nginx",
                    asset_key="hostname:www.example.org",
                )
            ],
        )
        service.run_cycle(target, mission_objective="assess")
        assert query.assets(target_id="platform-2")
        assert query.observations(target_id="platform-2")
        assert query.hypotheses("platform-2")
        assert query.gaps("platform-2")
        assert query.changes("platform-2") or query.history("platform-2")
        assert query.score("platform-2") is not None


sqlalchemy = pytest.importorskip("sqlalchemy")


class TestTargetIntelligenceSqlPersistence:
    def test_sql_repositories_persist_new_entities(self) -> None:
        from hunterx.config.settings import DatabaseSettings
        from hunterx.infrastructure.db.sql.crud import SqlTidbRepositoryFactory
        from hunterx.infrastructure.db.sql.factory import SessionFactory
        from hunterx.infrastructure.db.sql.tidb_models import Base

        session_factory = SessionFactory(DatabaseSettings(url="sqlite:///:memory:"))
        Base.metadata.create_all(session_factory.engine)
        stores = SqlTidbRepositoryFactory(session_factory)

        stores.repository_for(IntelligenceTargetRecord).save(
            IntelligenceTargetRecord(target_id="sql-1", mission_id="m", scope="example.com", identity="E", kind="domain", value="example.com")
        )
        stores.repository_for(IntelligenceAssetRecord).save(
            IntelligenceAssetRecord(asset_id="a1", target_id="sql-1", mission_id="m", kind="url", name="https://example.com/", asset_key="url:https://example.com/")
        )
        stores.repository_for(ObservationRecord).save(
            ObservationRecord(
                observation_id="o1",
                target_id="sql-1",
                mission_id="m",
                tool="httpx",
                capability="technology_fingerprint",
                observation_type="technology",
                value="nginx",
                asset_key="hostname:www.example.com",
            )
        )
        stores.repository_for(CoverageRecord).save(
            CoverageRecord(target_id="sql-1", asset_key="url:https://example.com/", capability="xss", state="tested", tool="dalfox")
        )
        stores.repository_for(IntelligenceActionRecord).save(
            IntelligenceActionRecord(target_id="sql-1", mission_id="m", objective="validate XSS", action_type="validate", required_capability="xss", tool="dalfox")
        )

        assert stores.repository_for(IntelligenceTargetRecord).count() == 1
        assert stores.repository_for(IntelligenceAssetRecord).count() == 1
        assert stores.repository_for(ObservationRecord).count() == 1
        assert stores.repository_for(CoverageRecord).count() == 1
        assert stores.repository_for(IntelligenceActionRecord).count() == 1
