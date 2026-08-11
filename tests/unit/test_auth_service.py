# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tests for the authentication intelligence use-case service.

Exercises the full pipeline with the in-process analyzer on an in-memory TIDB:
scope admission, tool selection, classification, validation, correlation,
conflict preservation, confidence, history comparison, TIDB persistence,
topology updates and the ``auth.*`` event stream.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from hunterx.application.auth import AuthQueryService, AuthService
from hunterx.domain.entities.tidb.auth_intelligence import (
    AuthChange as TidbAuthChange,
)
from hunterx.domain.entities.tidb.auth_intelligence import (
    AuthEndpoint as TidbAuthEndpoint,
)
from hunterx.domain.entities.tidb.auth_intelligence import (
    AuthEvidence as TidbAuthEvidence,
)
from hunterx.domain.entities.tidb.auth_intelligence import AuthRun as TidbAuthRun
from hunterx.domain.entities.tidb.auth_intelligence import AuthSurface as TidbAuthSurface
from hunterx.domain.entities.tidb.auth_intelligence import IdentityProvider as TidbIdp
from hunterx.domain.entities.tidb.topology import TopologyRelationship as TidbTopologyRelationship
from hunterx.infrastructure.db.sql.memory import InMemoryTidbRepositoryFactory
from hunterx.tools.auth.registry import register_auth_adapters
from hunterx.tools.sdk.engine import ExecutionEngine

GOLDEN = Path(__file__).parent.parent / "golden" / "auth"


def _golden(name: str) -> dict:
    return json.loads((GOLDEN / name).read_text(encoding="utf-8"))


def _make_engine() -> tuple[ExecutionEngine, dict]:
    engine = ExecutionEngine()
    adapters = register_auth_adapters(engine)
    for tool_id in adapters:
        engine.install_hook(tool_id, lambda _tid, _version: "1.0.0")
        engine.install(tool_id, version="1.0.0")
    return engine, adapters


class TestAuthService:
    def test_pipeline_correlates_and_persists(self) -> None:
        engine, _adapters = _make_engine()
        stores = InMemoryTidbRepositoryFactory()
        service = AuthService(engine=engine, stores=stores)
        batch = service.run(
            mission_id="m1",
            target="https://acme.com/login",
            mode="passive",
            parameters={"auth_input": _golden("login_page_input.json")},
        )
        assert batch.record_count() > 0
        assert batch.surface_count() >= 1
        assert batch.endpoint_count() >= 1
        assert stores.repository_for(TidbAuthSurface).count() == batch.surface_count()
        assert stores.repository_for(TidbAuthEndpoint).count() == batch.endpoint_count()
        assert stores.repository_for(TidbAuthRun).count() == 1
        assert stores.repository_for(TidbTopologyRelationship).count() > 0

    def test_oidc_pipeline(self) -> None:
        engine, _adapters = _make_engine()
        stores = InMemoryTidbRepositoryFactory()
        service = AuthService(engine=engine, stores=stores)
        batch = service.run(
            mission_id="m1",
            target="https://acme.com/oauth/callback",
            mode="passive",
            parameters={"auth_input": _golden("oidc_callback_input.json")},
        )
        assert stores.repository_for(TidbIdp).count() >= 1
        assert batch.record_count() >= 5

    def test_history_change_detection(self) -> None:
        engine, _adapters = _make_engine()
        stores = InMemoryTidbRepositoryFactory()
        service = AuthService(engine=engine, stores=stores)
        first = service.run(
            mission_id="m1",
            target="https://acme.com/login",
            mode="passive",
            parameters={"auth_input": _golden("login_page_input.json")},
            with_history=True,
            historical=[],
        )
        assert first.change_count() >= 1  # every record is 'added' vs empty history
        second = service.run(
            mission_id="m2",
            target="https://acme.com/login",
            mode="passive",
            parameters={"auth_input": _golden("login_page_input.json")},
            with_history=True,
            historical=first.records,
        )
        assert second.change_count() == 0  # identical snapshots => no changes
        assert stores.repository_for(TidbAuthChange).count() >= 1

    def test_out_of_scope_target_raises(self) -> None:
        engine, _adapters = _make_engine()
        from hunterx.domain.auth.scope import AuthScopePolicy

        service = AuthService(
            engine=engine,
            scope=AuthScopePolicy(roots=frozenset({"example.com"})),
        )
        with pytest.raises(ValueError):
            service.run(target="https://evil.com/login", mode="passive")

    def test_unregistered_tool_raises(self) -> None:
        engine, _adapters = _make_engine()
        service = AuthService(engine=engine)
        with pytest.raises(ValueError):
            service.run(target="https://example.com/login", mode="passive", tools=["not-a-tool"])

    def test_existing_intelligence_folded(self) -> None:
        engine, _adapters = _make_engine()
        stores = InMemoryTidbRepositoryFactory()
        service = AuthService(engine=engine, stores=stores)
        service.run(
            mission_id="m1",
            target="https://acme.com/login",
            mode="passive",
            parameters={"auth_input": _golden("login_page_input.json")},
        )
        # A second run with empty material folds the persisted intelligence back in.
        second = service.run(
            mission_id="m2",
            target="https://acme.com/login",
            mode="passive",
            parameters={"auth_input": {"url": "https://acme.com/login", "status_code": 200, "html": ""}},
        )
        assert second.record_count() >= 1

    def test_query_service_summary(self) -> None:
        engine, _adapters = _make_engine()
        stores = InMemoryTidbRepositoryFactory()
        service = AuthService(engine=engine, stores=stores)
        service.run(
            mission_id="m1",
            target="https://acme.com/login",
            mode="passive",
            parameters={"auth_input": _golden("login_page_input.json")},
        )
        query = AuthQueryService(stores=stores)
        summary = query.summary()
        assert summary["surfaces"] >= 1
        assert summary["endpoints"] >= 1
        assert summary["cookies"] >= 1
        surfaces = query.surfaces()
        assert any(surface["surface_kind"] == "login" for surface in surfaces)

    def test_no_raw_secrets_persisted(self) -> None:
        engine, _adapters = _make_engine()
        stores = InMemoryTidbRepositoryFactory()
        service = AuthService(engine=engine, stores=stores)
        service.run(
            mission_id="m1",
            target="https://acme.com/login",
            mode="passive",
            parameters={"auth_input": _golden("login_page_input.json")},
        )
        blob = " ".join(
            record.value
            for record in stores.repository_for(TidbAuthEvidence).stream()
            for record in [record]
        )
        for secret in ("abc123", "deadbeef"):
            assert secret not in blob
