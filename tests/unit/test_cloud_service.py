# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tests for the cloud & SaaS intelligence use-case service.

Exercises the full pipeline with the in-process analyzer on an in-memory TIDB:
scope admission, tool selection, classification, validation, correlation,
conflict preservation, confidence, history comparison, TIDB persistence,
topology updates and the ``cloud.*`` event stream.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from hunterx.application.cloud import CloudQueryService, CloudService
from hunterx.domain.cloud.scope import CloudScopePolicy
from hunterx.domain.entities.tidb.cloud_intelligence import (
    CloudProvider as TidbCloudProvider,
)
from hunterx.domain.entities.tidb.cloud_intelligence import CloudRun as TidbCloudRun
from hunterx.domain.entities.tidb.cloud_intelligence import (
    CloudService as TidbCloudService,
)
from hunterx.domain.entities.tidb.topology import TopologyRelationship
from hunterx.infrastructure.db.sql.memory import InMemoryTidbRepositoryFactory
from hunterx.tools.cloud.registry import register_cloud_adapters
from hunterx.tools.sdk.engine import ExecutionEngine

GOLDEN = Path(__file__).parent.parent / "golden" / "cloud"


def _golden(name: str) -> dict:
    return json.loads((GOLDEN / name).read_text(encoding="utf-8"))


def _make_engine() -> tuple[ExecutionEngine, dict]:
    engine = ExecutionEngine()
    adapters = register_cloud_adapters(engine)
    for tool_id in adapters:
        engine.install_hook(tool_id, lambda _tid, _version: "1.0.0")
        engine.install(tool_id, version="1.0.0")
    return engine, adapters


class TestCloudService:
    def test_run_persists_cloud_intelligence(self) -> None:
        engine, _ = _make_engine()
        stores = InMemoryTidbRepositoryFactory()
        service = CloudService(engine=engine, stores=stores)
        batch = service.run(
            mission_id="m1",
            target="acme.com",
            mode="passive",
            parameters={"cloud_input": _golden("aws_cdn_input.json")},
        )
        assert batch.record_count() > 0
        assert batch.provider_count() >= 1
        assert batch.service_count() >= 1
        assert stores.repository_for(TidbCloudProvider).count() >= 1
        assert stores.repository_for(TidbCloudService).count() >= 1
        assert stores.repository_for(TidbCloudRun).count() == 1
        assert stores.repository_for(TopologyRelationship).count() > 0

    def test_history_detects_change_across_runs(self) -> None:
        engine, _ = _make_engine()
        stores = InMemoryTidbRepositoryFactory()
        service = CloudService(engine=engine, stores=stores)
        first = service.run(
            mission_id="m1",
            target="acme.com",
            mode="passive",
            parameters={"cloud_input": _golden("aws_cdn_input.json")},
            with_history=True,
            historical=[],
        )
        assert first.change_count() >= 1
        second = service.run(
            mission_id="m1",
            target="acme.com",
            mode="passive",
            parameters={"cloud_input": _golden("aws_cdn_input.json")},
            with_history=True,
            historical=first.records,
        )
        assert second.change_count() == 0

    def test_out_of_scope_target_rejected(self) -> None:
        engine, _ = _make_engine()
        stores = InMemoryTidbRepositoryFactory()
        service = CloudService(
            engine=engine,
            stores=stores,
            scope=CloudScopePolicy(roots=frozenset({"example.com"})),
        )
        with pytest.raises(ValueError, match="out of scope"):
            service.run(mission_id="m1", target="evil.org", mode="passive", parameters={"cloud_input": {}})

    def test_unregistered_tool_rejected(self) -> None:
        engine, _ = _make_engine()
        stores = InMemoryTidbRepositoryFactory()
        service = CloudService(engine=engine, stores=stores)
        with pytest.raises(ValueError, match="not registered"):
            service.run(
                mission_id="m1",
                target="acme.com",
                mode="passive",
                tools=["not-a-tool"],
                parameters={"cloud_input": _golden("aws_cdn_input.json")},
            )

    def test_saas_and_webhooks_persisted(self) -> None:
        engine, _ = _make_engine()
        stores = InMemoryTidbRepositoryFactory()
        service = CloudService(engine=engine, stores=stores)
        batch = service.run(
            mission_id="m1",
            target="shop.example.org",
            mode="passive",
            parameters={"cloud_input": _golden("cloudflare_saas_input.json")},
        )
        assert any(type(record).__name__ == "SaaSProviderObservation" for record in batch.records)
        assert any(type(record).__name__ == "WebhookObservation" for record in batch.records)

    def test_exposure_indicators_persisted_as_intelligence(self) -> None:
        engine, _ = _make_engine()
        stores = InMemoryTidbRepositoryFactory()
        service = CloudService(engine=engine, stores=stores)
        batch = service.run(
            mission_id="m1",
            target="example.dev",
            mode="passive",
            parameters={"cloud_input": _golden("stale_dangling_input.json")},
        )
        assert any(type(record).__name__ == "CloudExposureObservation" for record in batch.records)

    def test_query_service_summary(self) -> None:
        engine, _ = _make_engine()
        stores = InMemoryTidbRepositoryFactory()
        service = CloudService(engine=engine, stores=stores)
        service.run(
            mission_id="m1",
            target="acme.com",
            mode="passive",
            parameters={"cloud_input": _golden("aws_cdn_input.json")},
        )
        query = CloudQueryService(stores=stores)
        summary = query.summary(mission_id="m1")
        assert summary["providers"] >= 1
        assert summary["services"] >= 1

    def test_no_raw_secrets_persisted(self) -> None:
        engine, _ = _make_engine()
        stores = InMemoryTidbRepositoryFactory()
        service = CloudService(engine=engine, stores=stores)
        service.run(
            mission_id="m1",
            target="shop.example.org",
            mode="passive",
            parameters={"cloud_input": _golden("cloudflare_saas_input.json")},
        )
        import dataclasses

        from hunterx.domain.entities.tidb.cloud_intelligence import CloudEvidence as TidbCloudEvidence

        blob = json.dumps([dataclasses.asdict(item) for item in stores.repository_for(TidbCloudEvidence).stream()])
        assert "pk_live_51ABCdefGHIjklMNO" not in blob
        assert "slack_token" not in blob
