# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Performance benchmarks for the authorization intelligence capability.

Establishes deterministic baselines for the analytical core: analyzing an HTTP
snapshot bundle, correlating 1k observations and running inventory queries.
"""

from __future__ import annotations

from dataclasses import replace

from hunterx.application.authorization import AuthorizationQueryService
from hunterx.domain.authorization.analyzer import AuthorizationAnalyzer
from hunterx.domain.authorization.confidence import AuthorizationConfidenceEngine
from hunterx.domain.authorization.correlator import AuthorizationCorrelator
from hunterx.domain.authorization.models import (
    AuthorizationInput,
    AuthzAdminSurfaceObservation,
    AuthzResourceObservation,
    AuthzRoleObservation,
)
from hunterx.infrastructure.db.sql.memory import InMemoryTidbRepositoryFactory
from hunterx.tools.authorization.registry import register_authorization_adapters
from hunterx.tools.sdk.engine import ExecutionEngine

_SCRIPT = (
    "const roles=['admin','viewer','editor']; window.permissions=['users.read','users.write',"
    "'projects.manage']; if(isAdmin){can('projects.manage')}; if(hasRole('admin')){};"
    "const User = class { role; permissions; owner_id; is_admin; };"
)


def _bundle() -> AuthorizationInput:
    return AuthorizationInput(
        target="https://example.com",
        url="https://example.com/admin/users/42",
        status_code=200,
        headers=(("X-Tenant-Id", "tenant1"),),
        html="<input name='owner_id'><input name='is_admin'>",
        scripts=(("https://example.com/a.js", _SCRIPT),),
        api_operations=(
            {"method": "GET", "path": "/api/v1/users/{id}", "roles": ["admin"], "scopes": ["users:read"]},
        ),
        observed_urls=("https://example.com/admin", "https://example.com/billing"),
    )


def test_analyze_snapshot_benchmark(benchmark) -> None:
    bundle = _bundle()
    analyzer = AuthorizationAnalyzer()
    count = benchmark(analyzer.analyze, bundle)
    assert len(count.all_observations()) >= 1


def test_correlate_1k_observations_benchmark(benchmark) -> None:
    observations = []
    for index in range(250):
        resource = AuthzResourceObservation(
            origin="https://example.com",
            name=f"resource-{index}",
            confidence=0.6,
            indicators=("test",),
        )
        role = AuthzRoleObservation(
            origin="https://example.com",
            name=f"role-{index}",
            confidence=0.5,
            indicators=("test",),
        )
        surface = AuthzAdminSurfaceObservation(
            url=f"https://example.com/admin/{index}",
            origin="https://example.com",
            confidence=0.5,
            indicators=("test",),
        )
        observations.extend((resource, role, surface))
    assert len(observations) == 750
    correlator = AuthorizationCorrelator()
    result = benchmark(correlator.correlate, observations)
    assert len(result.records) >= 750


def test_inventory_query_benchmark(benchmark) -> None:
    stores = InMemoryTidbRepositoryFactory()
    engine = ExecutionEngine()
    adapters = register_authorization_adapters(engine)
    for tool_id in adapters:
        engine.install_hook(tool_id, lambda _tid, _version: "1.0.0")
        engine.install(tool_id, version="1.0.0")
    from hunterx.application.authorization import AuthorizationService

    service = AuthorizationService(engine=engine, stores=stores)
    service.run(
        mission_id="perf",
        target="https://example.com/admin",
        mode="passive",
        parameters={"authorization_input": _bundle()},
    )
    query = AuthorizationQueryService(stores=stores)

    def _run() -> list:
        return query.resources(mission_id="perf")

    result = benchmark(_run)
    assert isinstance(result, list)


def test_batch_observations_with_corroboration_merged(benchmark) -> None:
    engine = AuthorizationConfidenceEngine()
    record = AuthzRoleObservation(origin="https://example.com", name="admin", confidence=0.3)
    group = [replace(record, source=f"source-{index}") for index in range(10)]
    score = benchmark(engine.merged_confidence, group)
    assert 0.0 <= score <= 1.0
