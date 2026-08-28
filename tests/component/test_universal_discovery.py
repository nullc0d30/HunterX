# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Universal discovery — application service tests.

Hermetic service coverage with a scripted engine: honest provider states
(available/unavailable/failed/partial/not-applicable/completed), stage
aggregation, continuous-discovery feedback between stages, the attack-surface
intake bridge, deduplication, and the guarantee that one failed tool never
kills the mission.
"""

from __future__ import annotations

from typing import Any

from hunterx.application.discovery import UniversalDiscoveryService, build_stage_plan
from hunterx.domain.discovery.enums import DiscoveryStage
from hunterx.domain.execution import ExecutionContext, ExecutionOutput, ExecutionResult, ExecutionStatus, FailureKind
from hunterx.tools.sdk.pipeline import PipelineResult

_TARGET = "http://fixture.test/"


class ScriptedEngine:
    """Engine whose adapters return scripted payloads or failures."""

    def __init__(
        self,
        payloads: dict[str, dict[str, Any]] | None = None,
        *,
        failures: set[str] | None = None,
        unhealthy: set[str] | None = None,
    ) -> None:
        self._payloads = payloads or {}
        self._failures = failures or set()
        self._unhealthy = unhealthy or set()
        self.executed: list[ExecutionContext] = []

    def adapter_for(self, tool_id: str):
        if tool_id in self._payloads or tool_id in self._failures:
            return object()
        return None

    def health_check(self, tool_id: str, *, requirement: str | None = None) -> bool:
        return tool_id not in self._unhealthy

    def execute(self, context: ExecutionContext) -> PipelineResult:
        self.executed.append(context)
        tool_id = context.tool_id
        if tool_id in self._failures:
            result = ExecutionResult(
                tool_id=tool_id,
                status=ExecutionStatus.FAILED,
                failure_kind=FailureKind.NOT_RETRYABLE,
                error=f"simulated failure for {tool_id}",
            )
            return PipelineResult(result=result, session=None, attempts=1)
        payload = self._payloads.get(tool_id)
        if payload is None:
            payload = {}
        output = ExecutionOutput(json=payload)
        result = ExecutionResult(tool_id=tool_id, status=ExecutionStatus.COMPLETED, output=output)
        return PipelineResult(result=result, session=None, attempts=1)


def _base_payloads() -> dict[str, dict[str, Any]]:
    """A minimal payload set exercising every converter family."""
    return {
        "dnspython": {
            "dns_records": [
                {"name": "fixture.test", "record_type": "A", "value": "127.0.0.1", "ttl": 300, "tool_id": "dnspython"},
                {"name": "api.fixture.test", "record_type": "A", "value": "127.0.0.1", "ttl": 300, "tool_id": "dnspython"},
            ]
        },
        "subfinder": {
            "discoveries": [
                {"kind": "subdomain", "name": "www.fixture.test", "tool_id": "subfinder", "source": "crt", "confidence": 0.9, "details": {}},
            ]
        },
        "tcp-connect": {
            "observations": [
                {"type": "host", "address": "127.0.0.1", "state": "up", "ip_version": 4, "tool_id": "tcp-connect", "source": "probe", "confidence": 1.0},
                {"type": "port", "address": "127.0.0.1", "port": 8080, "protocol": "tcp", "state": "open", "tool_id": "tcp-connect", "source": "probe", "confidence": 1.0},
            ]
        },
        "signature": {
            "technologies": [
                {"asset": "fixture.test", "raw_name": "nginx", "canonical_name": "Nginx", "version": "1.24.0", "category": "web-server", "family": "nginx", "confidence": 0.95, "source": "signature", "tool_id": "signature"}
            ]
        },
        "crawler": {
            "crawl": {
                "urls": [
                    {"url": "http://fixture.test/", "status_code": 200, "content_type": "text/html"},
                    {"url": "http://fixture.test/app.js", "status_code": 200, "content_type": "application/javascript"},
                ],
                "endpoints": [
                    {"url": "http://fixture.test/api/rest/products", "method": "GET"},
                    {"url": "http://fixture.test/graphql", "method": "POST"},
                ],
                "websockets": [{"url": "ws://fixture.test/ws/stream", "method": "GET"}],
                "graphqls": [{"url": "http://fixture.test/graphql", "method": "POST"}],
                "auth_boundaries": [{"url": "http://fixture.test/login", "method": "POST"}],
            }
        },
        "javascript": {
            "javascript": {
                "analyses": [
                    {
                        "asset": {"url": "http://fixture.test/app.js", "kind": "script"},
                        "endpoints": [{"url": "http://fixture.test/api/rest/products/search", "method": "GET"}],
                        "routes": [{"route": "/product/:id"}],
                    }
                ]
            }
        },
        "api-hints": {"apis": []},
        "api-graphql": {"apis": []},
        "api-openapi": {
            "apis": [
                {"type": "api-host", "origin_key": "http://fixture.test", "scheme": "http", "host": "fixture.test", "documented": True, "confidence": 1.0, "tool_id": "api-openapi"},
                {"type": "api-operation", "origin_key": "http://fixture.test", "method": "GET", "path": "/api/rest/products", "api_kind": "rest", "parameters": [], "confidence": 0.9, "tool_id": "api-openapi"},
            ]
        },
        "api-websocket": {"apis": []},
        "api-soap": {"apis": []},
        "api-swagger": {"apis": []},
        "arjun": {
            "parameters": {
                "findings": [
                    {"url": "http://fixture.test/api/rest/products", "parameters": ["q", "page"]}
                ]
            }
        },
        "auth-analysis": {
            "auth": [
                {"type": "auth-surface", "url": "http://fixture.test/login", "origin": "http://fixture.test", "surface_kind": "login", "access_state": "public", "confidence": 0.8, "tool_id": "auth-analysis"},
            ]
        },
    }


def _run(engine: ScriptedEngine, **kwargs: Any):
    service = UniversalDiscoveryService(engine=engine, mission_id="component", target_key="fixture.test")
    return service.run(target=_TARGET, timeout_seconds=5.0, **kwargs), service


class TestProviderStates:
    def test_unregistered_adapter_is_unavailable(self) -> None:
        engine = ScriptedEngine({"dnspython": {"dns_records": []}})
        run, _ = _run(engine)
        states = run.provider_states()
        assert states["dnspython"] == "completed"
        assert states["nmap"] == "unavailable"
        assert states["subfinder"] == "unavailable"

    def test_unhealthy_adapter_is_unavailable_not_failed(self) -> None:
        engine = ScriptedEngine({"tcp-connect": {"observations": []}}, unhealthy={"tcp-connect"})
        run, _ = _run(engine)
        assert run.provider_states()["tcp-connect"] == "unavailable"

    def test_failed_execution_is_failed_and_does_not_kill_mission(self) -> None:
        engine = ScriptedEngine(_base_payloads(), failures={"crawler"})
        run, _ = _run(engine)
        states = run.provider_states()
        assert states["crawler"] == "failed"
        # Every other provider still ran to completion.
        assert states["dnspython"] == "completed"
        assert states["javascript"] == "completed"
        # The HTTP stage's only available provider failed → the stage failed.
        assert run.stage_state(DiscoveryStage.HTTP) == "failed"
        assert run.summary["assets_total"] > 0

    def test_partial_stage_when_one_provider_fails(self) -> None:
        engine = ScriptedEngine(_base_payloads(), failures={"api-openapi"})
        run, _ = _run(engine)
        assert run.stage_state(DiscoveryStage.API) == "partial"
        # The other API providers still completed.
        assert run.provider_states()["api-hints"] == "completed"

    def test_graphql_stage_is_not_applicable_without_surface(self) -> None:
        payloads = _base_payloads()
        payloads["crawler"]["crawl"]["graphqls"] = []
        engine = ScriptedEngine(payloads)
        run, _ = _run(engine)
        assert run.stage_state(DiscoveryStage.GRAPHQL) == "not_applicable"

    def test_parameter_provider_skipped_in_passive_mode(self) -> None:
        engine = ScriptedEngine(_base_payloads())
        run, _ = _run(engine, mode="passive")
        assert run.provider_states()["arjun"] == "not_applicable"

    def test_stage_states_are_honest(self) -> None:
        engine = ScriptedEngine(_base_payloads())
        run, _ = _run(engine)
        states = {stage.value: run.stage_state(stage) for stage in DiscoveryStage}
        assert states["dns"] == "completed"
        assert states["technology"] == "completed"
        assert states["workflow"] == "completed"
        assert states["auth"] == "completed"


class TestDiscoveryAndIntake:
    def test_assets_are_deduplicated_across_stages(self) -> None:
        engine = ScriptedEngine(_base_payloads())
        run, _ = _run(engine)
        assert run.dedup["raw"] > run.dedup["unique"]
        hosts = run.by_kind("host")
        assert hosts, "host assets must be discovered"
        assert len(hosts) == len({asset.name for asset in hosts})

    def test_observation_bridge_feeds_surface_graph(self) -> None:
        engine = ScriptedEngine(_base_payloads())
        run, service = _run(engine)
        snapshot = service.surface.snapshot()
        assert snapshot["surfaces"] > 0
        assert snapshot["queue_total"] > 0
        assert "api_endpoint" in snapshot["kinds"]
        assert "workflow" in snapshot["kinds"] or "auth_surface" in snapshot["kinds"]

    def test_discovered_assets_carry_provenance(self) -> None:
        engine = ScriptedEngine(_base_payloads())
        run, _ = _run(engine)
        for asset in run.assets:
            assert asset.evidence, asset
            assert asset.evidence[0].provider
            assert asset.confidence > 0

    def test_continuous_discovery_feedback_graphql(self) -> None:
        """The GraphQL endpoint discovered by the crawler feeds api-graphql."""
        engine = ScriptedEngine(_base_payloads())
        _run(engine)
        graphql_contexts = [c for c in engine.executed if c.tool_id == "api-graphql"]
        assert graphql_contexts
        graphql_endpoints = graphql_contexts[0].parameters.get("graphql_endpoints")
        assert graphql_endpoints, "crawler-discovered GraphQL endpoint must be passed through"
        assert any("graphql" in item.get("url", "") for item in graphql_endpoints)

    def test_continuous_discovery_feedback_scripts(self) -> None:
        """The app.js URL discovered by the crawler feeds the JS analyzer."""
        engine = ScriptedEngine(_base_payloads())
        _run(engine)
        js_contexts = [c for c in engine.executed if c.tool_id == "javascript"]
        assert js_contexts
        assert js_contexts[0].parameters.get("url", "").endswith("app.js")

    def test_auth_input_consumes_discovered_urls(self) -> None:
        engine = ScriptedEngine(_base_payloads())
        _run(engine)
        auth_contexts = [c for c in engine.executed if c.tool_id == "auth-analysis"]
        assert auth_contexts
        assert auth_contexts[0].parameters["auth_input"]["url"] == _TARGET

    def test_context_carries_mission_and_permissions(self) -> None:
        engine = ScriptedEngine(_base_payloads())
        _run(engine)
        for context in engine.executed:
            assert context.mission_id == "component"
            assert context.profile == "universal-discovery"
            assert "network" in context.permissions or context.permissions == ()

    def test_passive_mode_skips_active_only_providers_honestly(self) -> None:
        engine = ScriptedEngine(_base_payloads())
        run, _ = _run(engine, mode="passive")
        assert run.provider_states()["arjun"] == "not_applicable"
        assert run.summary["mode"] == "passive"


class TestStagePlan:
    def test_plan_has_all_stages_in_order(self) -> None:
        plan = build_stage_plan()
        stages = [definition.stage for definition in plan.stages]
        assert stages == [
            DiscoveryStage.DNS,
            DiscoveryStage.SUBDOMAIN,
            DiscoveryStage.HOST,
            DiscoveryStage.PORT,
            DiscoveryStage.SERVICE,
            DiscoveryStage.TECHNOLOGY,
            DiscoveryStage.HTTP,
            DiscoveryStage.API,
            DiscoveryStage.GRAPHQL,
            DiscoveryStage.JAVASCRIPT,
            DiscoveryStage.WORKFLOW,
            DiscoveryStage.AUTH,
        ]

    def test_plan_tool_ids_are_platform_registrations(self) -> None:
        plan = build_stage_plan()
        tool_ids = set(plan.tool_ids())
        assert "dnspython" in tool_ids
        assert "tcp-connect" in tool_ids
        assert "crawler" in tool_ids
        assert "api-hints" in tool_ids
        assert "auth-analysis" in tool_ids

    def test_plan_provider_kinds_map_to_converters(self) -> None:
        plan = build_stage_plan()
        kinds = {provider.kind for definition in plan.stages for provider in definition.providers}
        assert kinds <= {"recon", "dns", "livehost", "tech", "web", "content", "parameter", "javascript", "api", "auth"}


__all__: list[str] = []
