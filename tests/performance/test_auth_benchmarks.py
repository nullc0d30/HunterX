# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Performance benchmarks for the authentication intelligence capability.

Establishes deterministic baselines for the analytical core: analyzing an HTTP
snapshot bundle, correlating 1k observations and running inventory queries.
"""

from __future__ import annotations

from dataclasses import replace

from hunterx.application.auth import AuthQueryService
from hunterx.domain.auth.analyzer import AuthAnalyzer
from hunterx.domain.auth.correlator import AuthCorrelator
from hunterx.domain.auth.models import (
    AuthCookieObservation,
    AuthEndpointObservation,
    AuthInput,
    AuthSurfaceObservation,
)
from hunterx.infrastructure.db.sql.memory import InMemoryTidbRepositoryFactory
from hunterx.tools.auth.registry import register_auth_adapters
from hunterx.tools.sdk.engine import ExecutionEngine

_LOGIN_HTML = (
    "<html><form action='/login' method='post'><input type='password' name='password'>"
    "<input name='_token'></form><p>Sign in with Google</p><p>Two-factor authentication</p></html>"
)


def _bundle() -> AuthInput:
    return AuthInput(
        target="https://example.com",
        url="https://example.com/login",
        status_code=200,
        headers=(
            ("Set-Cookie", "session=abc; Path=/; HttpOnly; Secure; SameSite=Lax"),
            ("Access-Control-Allow-Origin", "https://example.com"),
            ("WWW-Authenticate", 'Bearer realm="api"'),
        ),
        html=_LOGIN_HTML,
        scripts=(("https://example.com/a.js", "localStorage.setItem('access_token', t); navigator.credentials.create({});"),),
    )


def test_analyze_snapshot_benchmark(benchmark) -> None:
    bundle = _bundle()
    analyzer = AuthAnalyzer()
    count = benchmark(analyzer.analyze, bundle)
    assert len(count.all_observations()) >= 1


def test_correlate_1k_observations_benchmark(benchmark) -> None:
    observations = []
    for index in range(250):
        surface = AuthSurfaceObservation(
            url=f"https://example.com/page/{index}",
            origin="https://example.com",
            confidence=0.7,
            indicators=("test",),
        )
        endpoint = AuthEndpointObservation(
            url=f"https://example.com/page/{index}",
            origin="https://example.com",
            confidence=0.6,
            indicators=("test",),
        )
        cookie = AuthCookieObservation(name=f"c{index}", origin="https://example.com", confidence=0.5)
        observations.extend((surface, endpoint, cookie))
    assert len(observations) == 750
    correlator = AuthCorrelator()
    result = benchmark(correlator.correlate, observations)
    assert len(result.records) >= 750


def test_inventory_query_benchmark(benchmark) -> None:
    stores = InMemoryTidbRepositoryFactory()
    engine = ExecutionEngine()
    adapters = register_auth_adapters(engine)
    for tool_id in adapters:
        engine.install_hook(tool_id, lambda _tid, _version: "1.0.0")
        engine.install(tool_id, version="1.0.0")
    from hunterx.application.auth import AuthService

    service = AuthService(engine=engine, stores=stores)
    service.run(
        mission_id="perf",
        target="https://example.com/login",
        mode="passive",
        parameters={"auth_input": {"url": "https://example.com/login", "status_code": 200, "html": _LOGIN_HTML}},
    )
    query = AuthQueryService(stores=stores)

    def _run() -> list:
        return query.surfaces(mission_id="perf")

    result = benchmark(_run)
    assert isinstance(result, list)


def test_batch_observations_with_corroboration_merged(benchmark) -> None:
    from hunterx.domain.auth.confidence import AuthConfidenceEngine

    engine = AuthConfidenceEngine()
    record = AuthSurfaceObservation(url="https://example.com/login", origin="https://example.com", confidence=0.7)
    group = [replace(record, source=f"source-{index}") for index in range(10)]
    score = benchmark(engine.merged_confidence, group)
    assert 0.0 <= score <= 1.0
