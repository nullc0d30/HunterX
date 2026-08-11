# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tests for the authorization intelligence use-case service.

Exercises the full pipeline with the in-process analyzer on an in-memory TIDB:
scope admission, tool selection, classification, validation, correlation,
conflict preservation, confidence, history comparison, TIDB persistence,
topology updates and the ``authorization.*`` event stream.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from hunterx.application.authorization import AuthorizationQueryService, AuthorizationService
from hunterx.domain.entities.tidb.authorization_intelligence import (
    AuthorizationChange as TidbAuthorizationChange,
)
from hunterx.domain.entities.tidb.authorization_intelligence import (
    AuthorizationEvidence as TidbAuthorizationEvidence,
)
from hunterx.domain.entities.tidb.authorization_intelligence import (
    AuthorizationResource as TidbAuthorizationResource,
)
from hunterx.domain.entities.tidb.authorization_intelligence import (
    AuthorizationRole as TidbAuthorizationRole,
)
from hunterx.domain.entities.tidb.authorization_intelligence import (
    AuthorizationRun as TidbAuthorizationRun,
)
from hunterx.domain.entities.tidb.topology import TopologyRelationship as TidbTopologyRelationship
from hunterx.infrastructure.db.sql.memory import InMemoryTidbRepositoryFactory
from hunterx.tools.authorization.registry import register_authorization_adapters
from hunterx.tools.sdk.engine import ExecutionEngine

GOLDEN = Path(__file__).parent.parent / "golden" / "authorization"


def _golden(name: str) -> dict:
    return json.loads((GOLDEN / name).read_text(encoding="utf-8"))


def _make_engine() -> tuple[ExecutionEngine, dict]:
    engine = ExecutionEngine()
    adapters = register_authorization_adapters(engine)
    for tool_id in adapters:
        engine.install_hook(tool_id, lambda _tid, _version: "1.0.0")
        engine.install(tool_id, version="1.0.0")
    return engine, adapters


class TestAuthorizationService:
    def test_pipeline_correlates_and_persists(self) -> None:
        engine, _adapters = _make_engine()
        stores = InMemoryTidbRepositoryFactory()
        service = AuthorizationService(engine=engine, stores=stores)
        batch = service.run(
            mission_id="m1",
            target="https://acme.com/admin",
            mode="passive",
            parameters={"authorization_input": _golden("admin_rbac_api.json")},
        )
        assert batch.record_count() > 0
        assert batch.resource_count() >= 1
        assert batch.role_count() >= 1
        assert stores.repository_for(TidbAuthorizationResource).count() == batch.resource_count()
        assert stores.repository_for(TidbAuthorizationRole).count() == batch.role_count()
        assert stores.repository_for(TidbAuthorizationRun).count() == 1
        assert stores.repository_for(TidbTopologyRelationship).count() > 0

    def test_history_change_detection(self) -> None:
        engine, _adapters = _make_engine()
        stores = InMemoryTidbRepositoryFactory()
        service = AuthorizationService(engine=engine, stores=stores)
        first = service.run(
            mission_id="m1",
            target="https://acme.com/admin",
            mode="passive",
            parameters={"authorization_input": _golden("admin_rbac_api.json")},
            with_history=True,
            historical=[],
        )
        assert first.change_count() >= 1  # every record is 'added' vs empty history
        second = service.run(
            mission_id="m2",
            target="https://acme.com/admin",
            mode="passive",
            parameters={"authorization_input": _golden("admin_rbac_api.json")},
            with_history=True,
            historical=first.records,
        )
        assert second.change_count() == 0  # identical snapshots => no changes
        assert stores.repository_for(TidbAuthorizationChange).count() >= 1

    def test_out_of_scope_target_raises(self) -> None:
        engine, _adapters = _make_engine()
        from hunterx.domain.authorization.scope import AuthorizationScopePolicy

        service = AuthorizationService(
            engine=engine,
            scope=AuthorizationScopePolicy(roots=frozenset({"example.com"})),
        )
        with pytest.raises(ValueError):
            service.run(target="https://evil.com/admin", mode="passive")

    def test_unregistered_tool_raises(self) -> None:
        engine, _adapters = _make_engine()
        service = AuthorizationService(engine=engine)
        with pytest.raises(ValueError):
            service.run(target="https://example.com/api", mode="passive", tools=["not-a-tool"])

    def test_existing_intelligence_folded(self) -> None:
        engine, _adapters = _make_engine()
        stores = InMemoryTidbRepositoryFactory()
        service = AuthorizationService(engine=engine, stores=stores)
        service.run(
            mission_id="m1",
            target="https://acme.com/admin",
            mode="passive",
            parameters={"authorization_input": _golden("admin_rbac_api.json")},
        )
        # A second run with empty material folds the persisted intelligence back in.
        second = service.run(
            mission_id="m2",
            target="https://acme.com/admin",
            mode="passive",
            parameters={
                "authorization_input": {"url": "https://acme.com/admin", "status_code": 200, "html": ""}
            },
        )
        assert second.record_count() >= 1

    def test_query_service_summary(self) -> None:
        engine, _adapters = _make_engine()
        stores = InMemoryTidbRepositoryFactory()
        service = AuthorizationService(engine=engine, stores=stores)
        service.run(
            mission_id="m1",
            target="https://acme.com/admin",
            mode="passive",
            parameters={"authorization_input": _golden("admin_rbac_api.json")},
        )
        query = AuthorizationQueryService(stores=stores)
        summary = query.summary()
        assert summary["resources"] >= 1
        assert summary["roles"] >= 1
        assert summary["admin_surfaces"] >= 1
        resources = query.resources()
        assert any(resource["name"] == "users" for resource in resources)

    def test_no_raw_secrets_persisted(self) -> None:
        engine, _adapters = _make_engine()
        stores = InMemoryTidbRepositoryFactory()
        service = AuthorizationService(engine=engine, stores=stores)
        service.run(
            mission_id="m1",
            target="https://acme.com/admin",
            mode="passive",
            parameters={"authorization_input": _golden("admin_rbac_api.json")},
        )
        blob = " ".join(
            record.value
            for record in stores.repository_for(TidbAuthorizationEvidence).stream()
        )
        assert "eyJ" not in blob
