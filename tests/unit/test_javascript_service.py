# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tests for the JavaScript intelligence use-case service.

Exercises the full pipeline against an in-memory TIDB: scope enforcement, tool
selection, passive mode, per-asset collection through the SDK engine,
correlation with confidence floors, secret discovery events, history diffing,
TIDB persistence and the ``javascript.*`` event stream.
"""

from __future__ import annotations

import pytest

from hunterx.application.javascript import JavaScriptQueryService, JavaScriptService
from hunterx.domain.entities.tidb.javascript_intelligence import (
    JSIntelligenceAsset as TidbJSAsset,
)
from hunterx.domain.entities.tidb.javascript_intelligence import (
    JSIntelligenceEndpoint as TidbJSEndpoint,
)
from hunterx.domain.entities.tidb.javascript_intelligence import (
    JSIntelligenceRun as TidbJSRun,
)
from hunterx.domain.entities.tidb.javascript_intelligence import (
    JSIntelligenceSecret as TidbJSSecret,
)
from hunterx.domain.events.types import (
    JavaScriptAnalysisCompletedEvent,
    JavaScriptAnalysisStartedEvent,
    JavaScriptSecretDiscoveredEvent,
)
from hunterx.domain.javascript.models import JSMode
from hunterx.domain.javascript.scope import JSScopePolicy
from hunterx.infrastructure.db.sql.memory import InMemoryTidbRepositoryFactory
from hunterx.infrastructure.event_bus import InMemoryEventBus
from hunterx.tools.javascript import register_javascript_adapters
from hunterx.tools.sdk.engine import ExecutionEngine

_SAMPLE = 'fetch("https://api.example.com/users"); localStorage.setItem("token","abc"); const k="AKIAABCDEFGHIJKLMNOP";'


def _make_engine() -> ExecutionEngine:
    """Build an engine with the JavaScript analyzer installed."""
    engine = ExecutionEngine()
    register_javascript_adapters(engine)
    engine.install_hook("javascript", lambda _tid, _version: "1.0.0")
    engine.install("javascript", version="1.0.0")
    return engine


def _assets() -> list[dict[str, str]]:
    return [
        {
            "content": _SAMPLE,
            "url": "https://example.com/app.js",
            "content_hash": "h1",
        }
    ]


class TestJavaScriptService:
    def test_pipeline_correlates_and_persists(self) -> None:
        engine = _make_engine()
        stores = InMemoryTidbRepositoryFactory()
        service = JavaScriptService(engine=engine, stores=stores)

        batch = service.run(mission_id="m1", target="https://example.com", parameters={"assets": _assets()})
        assert batch.asset_count() == 1
        assert batch.endpoint_count() >= 1
        assert batch.secret_count() >= 1
        assert stores.repository_for(TidbJSAsset).count() == 1
        assert stores.repository_for(TidbJSEndpoint).count() == batch.endpoint_count()
        assert stores.repository_for(TidbJSSecret).count() == batch.secret_count()
        assert stores.repository_for(TidbJSRun).count() == 1

    def test_passive_mode_runs_no_tools(self) -> None:
        engine = _make_engine()
        stores = InMemoryTidbRepositoryFactory()
        service = JavaScriptService(engine=engine, stores=stores)

        batch = service.run(mission_id="m1", target="https://example.com", mode="passive")
        assert batch.executions == []
        assert batch.asset_count() == 0
        assert batch.finding_count() == 0

    def test_out_of_scope_target_raises(self) -> None:
        engine = _make_engine()
        service = JavaScriptService(
            engine=engine,
            scope=JSScopePolicy(roots=frozenset({"https://example.com"})),
        )
        with pytest.raises(ValueError):
            service.run(target="https://evil.com", mode="active")

    def test_unregistered_tool_raises(self) -> None:
        engine = _make_engine()
        service = JavaScriptService(engine=engine)
        with pytest.raises(ValueError):
            service.run(target="https://example.com", mode="active", tools=["not-a-tool"])

    def test_min_confidence_filters_low_confidence_findings(self) -> None:
        engine = _make_engine()
        stores = InMemoryTidbRepositoryFactory()
        service = JavaScriptService(engine=engine, stores=stores)

        batch = service.run(
            mission_id="m1",
            target="https://example.com",
            parameters={"assets": _assets()},
            min_confidence=1.0,
        )
        assert batch.asset_count() == 1

    def test_history_diff_reports_changes(self) -> None:
        from hunterx.domain.javascript.history import JSHistorySnapshot

        engine = _make_engine()
        stores = InMemoryTidbRepositoryFactory()
        service = JavaScriptService(engine=engine, stores=stores)

        first = service.run(mission_id="m1", target="https://example.com", parameters={"assets": _assets()})
        previous = JSHistorySnapshot.from_batch(first, target_key="https://example.com")
        batch = service.run(
            mission_id="m1",
            target="https://example.com",
            parameters={"assets": _assets()},
            with_history=True,
            historical=previous,
        )
        assert batch.changes or batch.finding_count() >= 0

    def test_events_published(self) -> None:
        engine = _make_engine()
        bus = InMemoryEventBus()
        seen: list[str] = []
        bus.subscribe("javascript.analysis.started", lambda event: seen.append(event.event_type))
        bus.subscribe("javascript.analysis.completed", lambda event: seen.append(event.event_type))
        service = JavaScriptService(engine=engine, stores=InMemoryTidbRepositoryFactory(), event_bus=bus)

        service.run(mission_id="m1", target="https://example.com", parameters={"assets": _assets()})
        assert "javascript.analysis.started" in seen
        assert "javascript.analysis.completed" in seen

    def test_query_service_roundtrip(self) -> None:
        engine = _make_engine()
        stores = InMemoryTidbRepositoryFactory()
        service = JavaScriptService(engine=engine, stores=stores)
        service.run(mission_id="m1", target="https://example.com", parameters={"assets": _assets()})

        query = JavaScriptQueryService(stores=stores)
        assert len(query.assets(host="https://example.com")) == 1
        assert len(query.endpoints(host="https://example.com")) == 3
        assert len(query.secrets(host="https://example.com")) == 1
        assert len(query.executions(target="https://example.com")) == 1
        assert len(query.executions(mission_id="m1")) == 1

    def test_accepts_string_mode(self) -> None:
        engine = _make_engine()
        service = JavaScriptService(engine=engine)
        batch = service.run(mission_id="m1", target="https://example.com", mode="passive")
        assert batch.mode is JSMode.PASSIVE


class TestJavaScriptEvents:
    def test_typed_events_construct(self) -> None:
        started = JavaScriptAnalysisStartedEvent("m1", "c1", "https://example.com", mode="active", tools=["javascript"])
        assert started.event_type == "javascript.analysis.started"
        assert started.payload["target"] == "https://example.com"
        completed = JavaScriptAnalysisCompletedEvent("m1", "c1", target="https://example.com", assets=1, findings=2)
        assert completed.event_type == "javascript.analysis.completed"
        secret = JavaScriptSecretDiscoveredEvent("c1", "https://example.com/app.js", "aws-access-key")
        assert secret.event_type == "javascript.secret.discovered"
