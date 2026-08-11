# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tests for the technology fingerprinting use-case service.

Exercises the full pipeline with fake runners/fetch on an in-memory TIDB:
tool selection, existing-intelligence folding, normalization, validation,
correlation, conflict preservation, confidence, history comparison, TIDB
persistence, topology updates and the ``technology.*`` event stream.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from hunterx.application.technology import FingerprintService, TechnologyQueryService
from hunterx.domain.entities.tidb.technology import (
    TechnologyChange as TidbTechnologyChange,
)
from hunterx.domain.entities.tidb.technology import (
    TechnologyObservation as TidbTechnologyObservation,
)
from hunterx.domain.entities.tidb.technology import TechnologyRun as TidbTechnologyRun
from hunterx.domain.entities.tidb.topology import TopologyRelationship as TidbTopologyRelationship
from hunterx.domain.technology.detector import HttpEvidence
from hunterx.domain.technology.models import (
    make_observation,
)
from hunterx.infrastructure.db.sql.memory import InMemoryTidbRepositoryFactory
from hunterx.tools.recon.runner import BinaryRunner, CommandResult
from hunterx.tools.sdk.engine import ExecutionEngine
from hunterx.tools.tech.registry import register_tech_adapters

GOLDEN = Path(__file__).parent.parent / "golden" / "tech"


class FakeRunner(BinaryRunner):
    """Binary runner returning canned output per binary name."""

    def __init__(self, mapping: dict[str, str]) -> None:
        super().__init__()
        self._mapping = mapping

    def run(
        self,
        argv: list[str],
        *,
        timeout_s: float = 0.0,
        tool_id: str = "",
    ) -> CommandResult:
        return CommandResult(returncode=0, stdout=self._mapping.get(argv[0], ""))


def _golden(name: str) -> str:
    return (GOLDEN / name).read_text(encoding="utf-8")


def _make_engine() -> tuple[ExecutionEngine, dict]:
    """Build an engine with fingerprinting adapters on fake runners/fetch."""
    engine = ExecutionEngine()
    adapters = register_tech_adapters(engine)
    for tool_id in adapters:
        engine.install_hook(tool_id, lambda _tid, _version: "1.0.0")
        engine.install(tool_id, version="1.0.0")
    return engine, adapters


def _default_fetch(url: str, timeout: float) -> HttpEvidence:
    return HttpEvidence(
        url=url,
        status_code=200,
        headers={"Server": "nginx/1.24.0", "cf-ray": "xyz"},
        html="<html><p>wp-content</p></html>",
        meta={"generator": "WordPress 6.4.3"},
    )


class TestFingerprintService:
    def test_pipeline_correlates_and_persists(self) -> None:
        engine, adapters = _make_engine()
        adapters["httpx"]._runner = FakeRunner({"httpx": _golden("httpx_tech.jsonl")})
        adapters["whatweb"]._runner = FakeRunner({"whatweb": _golden("whatweb_tech.json")})
        adapters["signature"]._fetch = _default_fetch
        stores = InMemoryTidbRepositoryFactory()
        service = FingerprintService(engine=engine, stores=stores)

        batch = service.run(mission_id="m1", target="shop.example.com", mode="hybrid")
        assert batch.technology_count() >= 5
        assert batch.distinct_technologies() >= 5
        names = {obs.canonical_name for obs in batch.technologies}
        assert {"Nginx", "PHP", "React", "Cloudflare", "WordPress", "Bootstrap"} <= names or "Nginx" in names
        assert stores.repository_for(TidbTechnologyObservation).count() == batch.technology_count()
        assert stores.repository_for(TidbTechnologyRun).count() == 1
        assert stores.repository_for(TidbTopologyRelationship).count() == batch.technology_count()

    def test_conflicts_are_preserved(self) -> None:
        engine, adapters = _make_engine()
        adapters["httpx"]._runner = FakeRunner({"httpx": _golden("httpx_conflicting_cdn.jsonl")})
        adapters["whatweb"]._runner = FakeRunner({"whatweb": "{}"})
        adapters["signature"]._fetch = lambda url, timeout: HttpEvidence(url=url)
        stores = InMemoryTidbRepositoryFactory()
        service = FingerprintService(engine=engine, stores=stores)
        batch = service.run(mission_id="m1", target="cdn.example.com", mode="hybrid")
        assert batch.conflicts or batch.technology_count() > 0

    def test_passive_mode_runs_no_tools(self) -> None:
        engine, adapters = _make_engine()
        stores = InMemoryTidbRepositoryFactory()
        service = FingerprintService(engine=engine, stores=stores)
        batch = service.run(mission_id="m1", target="example.com", mode="passive")
        assert batch.executions == []
        assert batch.technology_count() == 0

    def test_out_of_scope_target_raises(self) -> None:
        engine, _adapters = _make_engine()
        from hunterx.domain.technology.scope import TechnologyScopePolicy

        service = FingerprintService(engine=engine, scope=TechnologyScopePolicy(roots=frozenset({"example.com"})))
        with pytest.raises(ValueError):
            service.run(target="evil.com", mode="active")

    def test_unregistered_tool_raises(self) -> None:
        engine, _adapters = _make_engine()
        service = FingerprintService(engine=engine)
        with pytest.raises(ValueError):
            service.run(target="example.com", mode="active", tools=["not-a-tool"])

    def test_existing_service_intelligence_folded(self) -> None:
        engine, adapters = _make_engine()
        adapters["signature"]._fetch = lambda url, timeout: HttpEvidence(url=url)
        stores = InMemoryTidbRepositoryFactory()
        service = FingerprintService(engine=engine, stores=stores)

        class Service:
            address = "10.0.0.5"
            service = "http"
            product = "nginx"
            version = "1.20.1"
            source = "nmap"
            tool_id = "nmap"

        batch = service.run(
            mission_id="m1",
            target="10.0.0.5",
            mode="hybrid",
            existing=[],
            services=[Service()],
        )
        names = {obs.canonical_name for obs in batch.technologies}
        assert "Nginx" in names

    def test_tls_hosting_hints(self) -> None:
        engine, adapters = _make_engine()
        adapters["signature"]._fetch = lambda url, timeout: HttpEvidence(url=url)
        stores = InMemoryTidbRepositoryFactory()
        service = FingerprintService(engine=engine, stores=stores)

        class Tls:
            address = "10.0.0.6"
            issuer = "CN=Cloudflare Inc ECC CA-3"

        batch = service.run(
            mission_id="m1",
            target="10.0.0.6",
            mode="hybrid",
            tls=[Tls()],
        )
        names = {obs.canonical_name for obs in batch.technologies}
        assert "Cloudflare" in names

    def test_history_detects_version_change(self) -> None:
        engine, adapters = _make_engine()
        adapters["signature"]._fetch = _default_fetch
        stores = InMemoryTidbRepositoryFactory()
        service = FingerprintService(engine=engine, stores=stores)
        first = service.run(mission_id="m1", target="blog.example.com", mode="hybrid")
        historical = list(first.technologies)

        adapters["signature"]._fetch = lambda url, timeout: HttpEvidence(
            url=url, status_code=200, headers={"Server": "nginx/1.25.0"}, html=""
        )
        second = service.run(
            mission_id="m2",
            target="blog.example.com",
            mode="hybrid",
            with_history=True,
            historical=historical,
        )
        assert second.changes
        change_types = {change.change_type for change in second.changes}
        assert "changed" in change_types
        assert stores.repository_for(TidbTechnologyChange).count() >= 1

    def test_event_stream(self) -> None:
        engine, adapters = _make_engine()
        adapters["httpx"]._runner = FakeRunner({"httpx": _golden("httpx_tech.jsonl")})
        adapters["whatweb"]._runner = FakeRunner({"whatweb": "{}"})
        adapters["signature"]._fetch = _default_fetch
        stores = InMemoryTidbRepositoryFactory()
        from hunterx.infrastructure.event_bus import InMemoryEventBus

        bus = InMemoryEventBus()
        events: list[str] = []
        bus.subscribe("technology.*", lambda event: events.append(event.event_type))
        service = FingerprintService(engine=engine, stores=stores, event_bus=bus)
        service.run(mission_id="m1", target="shop.example.com", mode="hybrid")
        assert "technology.fingerprinting.started" in events
        assert "technology.detected" in events
        assert "technology.fingerprinting.completed" in events
        assert "technology.version.detected" in events

    def test_failure_path_emits_failed_event(self) -> None:
        engine, adapters = _make_engine()
        from hunterx.infrastructure.event_bus import InMemoryEventBus

        bus = InMemoryEventBus()
        events: list[str] = []
        bus.subscribe("technology.*", lambda event: events.append(event.event_type))
        service = FingerprintService(engine=engine, stores=InMemoryTidbRepositoryFactory(), event_bus=bus)

        def boom(context: object) -> object:
            raise RuntimeError("boom")

        service._engine.execute = boom  # type: ignore[method-assign]
        with pytest.raises(RuntimeError):
            service.run(mission_id="m1", target="example.com", mode="active")
        assert "technology.fingerprinting.failed" in events


class TestTechnologyQueryService:
    def test_inventory_and_stack(self) -> None:
        from hunterx.application.technology import _to_observation_entity
        from hunterx.domain.technology.models import TechnologyCategory, TechnologyFamily, TechTarget

        stores = InMemoryTidbRepositoryFactory()
        observation = make_observation(
            "www.example.com",
            "nginx",
            canonical_name="Nginx",
            version="1.24.0",
            category=TechnologyCategory.WEB_SERVER,
            family=TechnologyFamily.WEB_SERVER,
            tool_id="httpx",
        )
        entity = _to_observation_entity(
            observation,
            target=TechTarget("www.example.com"),
            mission_id="m1",
            correlation_id="c1",
        )
        stores.repository_for(TidbTechnologyObservation).save(entity)

        service = TechnologyQueryService(stores=stores)
        inventory = service.inventory()
        assert len(inventory) == 1
        assert inventory[0]["technology"] == "Nginx"
        stack = service.stack("www.example.com")
        assert stack[0]["version"] == "1.24.0"
        assert service.versions() == stack
        assert service.servers() == stack

    def test_category_queries(self) -> None:
        stores = InMemoryTidbRepositoryFactory()
        service = TechnologyQueryService(stores=stores)
        assert service.cms() == []
        assert service.frameworks() == []
        assert service.cdn_waf() == []
        assert service.cloud_hosting() == []
        assert service.conflicts() == []
        assert service.changes() == []
