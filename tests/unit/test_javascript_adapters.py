# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tests for the JavaScript intelligence tool adapters.

The analyzer is in-process and content-free: source text is supplied through the
execution parameters (``content``/``url``), so every test stays hermetic. Tests
assert the pipeline's ``javascript`` payload, the canonical tool output produced
by ``normalize``, engine registration and TIP registration.
"""

from __future__ import annotations

from hunterx.domain.execution import ExecutionContext
from hunterx.tools.javascript import (
    JS_TOOL_IDS,
    JavaScriptAdapterFactory,
    JavaScriptAnalyzerAdapter,
    javascript_adapters,
    register_javascript_adapters,
)
from hunterx.tools.javascript.tip import (
    javascript_tool_specs,
    register_javascript_tools,
)
from hunterx.tools.sdk.context import ExecutionContextBuilder
from hunterx.tools.sdk.engine import ExecutionEngine
from hunterx.tools.sdk.output import OutputCollector

_SAMPLE = 'fetch("https://api.example.com/users"); localStorage.setItem("token","abc"); const k="AKIAABCDEFGHIJKLMNOP";'


def _context(
    *,
    target: str = "https://example.com",
    content: str = _SAMPLE,
    url: str = "https://example.com/app.js",
) -> ExecutionContext:
    return (
        ExecutionContextBuilder(tool_id="javascript", target=target)
        .with_target_type("url")
        .with_mission("m1")
        .with_correlation_id("c1")
        .with_profile("javascript-intelligence")
        .with_permissions(("none",))
        .with_parameters({"content": content, "url": url, "content_hash": "h1"})
        .build()
    )


def _analyses(collector: OutputCollector) -> list[dict[str, object]]:
    payload = collector.build().json or {}
    analyses = payload["javascript"]["analyses"]
    assert isinstance(analyses, list)
    return analyses


class TestAdapter:
    def test_descriptor(self) -> None:
        adapter = JavaScriptAnalyzerAdapter()
        assert adapter.descriptor.name == "javascript"
        assert adapter.descriptor.version == "1.0.0"
        assert adapter.descriptor.entrypoint == "hunterx.tools.javascript.analyzer:JavaScriptAnalyzerAdapter"
        assert adapter.descriptor.targets == ("host", "domain", "url", "script")
        assert "secret-scanning" in adapter.descriptor.capabilities

    def test_run_detects_endpoints_storage_and_secrets(self) -> None:
        adapter = JavaScriptAnalyzerAdapter()
        collector = OutputCollector()
        adapter.run(_context(), collector)
        result = collector.build()
        assert result.exit_code == 0
        analyses = _analyses(collector)
        assert len(analyses) == 1
        analysis = analyses[0]
        assert analysis["asset"]["url"] == "https://example.com/app.js"
        assert len(analysis["endpoints"]) >= 1
        assert len(analysis["storage"]) >= 1
        assert len(analysis["secrets"]) >= 1
        assert analysis["secrets"][0]["tier"] == "high"

    def test_secret_values_are_masked(self) -> None:
        adapter = JavaScriptAnalyzerAdapter()
        collector = OutputCollector()
        adapter.run(_context(), collector)
        secret = _analyses(collector)[0]["secrets"][0]
        assert secret["masked_value"] is not None
        assert "*" in secret["masked_value"]
        assert secret["masked_value"] != "AKIAABCDEFGHIJKLMNOP"

    def test_normalize_projects_findings(self) -> None:
        adapter = JavaScriptAnalyzerAdapter()
        collector = OutputCollector()
        adapter.run(_context(), collector)
        output = adapter.normalize(_context(), collector.build())
        assert len(output.assets) == 1
        assert len(output.findings) >= 1
        assert output.assets[0]["url"] == "https://example.com/app.js"

    def test_empty_content_fails(self) -> None:
        adapter = JavaScriptAnalyzerAdapter()
        collector = OutputCollector()
        adapter.run(_context(content="", url=""), collector)
        assert collector.build().exit_code != 0

    def test_endpoint_extraction_deduplicates_and_filters_junk(self) -> None:
        adapter = JavaScriptAnalyzerAdapter()
        collector = OutputCollector()
        source = (
            "const a = this.http.get(`/api/Feedbacks`);"
            "const b = this.http.get(`/api/Feedbacks`);"
            "const c = this.http.get(`${this.host}/rest/products/search?q=${e}`);"
            "const d = this.http.get(`/160`);"
        )
        adapter.run(_context(content=source, url="https://example.com/app.js"), collector)
        endpoints = [ep["url"] for ep in _analyses(collector)[0]["endpoints"]]
        assert len(endpoints) == len(set(endpoints)), "identical endpoints must be emitted once"
        assert endpoints.count("/api/Feedbacks") == 1
        assert "/rest/products/search?q=" in endpoints
        assert not any(ep.startswith("/160") for ep in endpoints), "pure-numeric validator args are not endpoints"


class TestRegistry:
    def test_factory_builds_one_adapter(self) -> None:
        adapters = JavaScriptAdapterFactory().build()
        assert set(adapters) == set(JS_TOOL_IDS)

    def test_register_on_engine(self) -> None:
        engine = ExecutionEngine()
        mapping = register_javascript_adapters(engine)
        for tool_id in JS_TOOL_IDS:
            assert engine.adapter_for(tool_id) is mapping[tool_id]

    def test_adapters_helper(self) -> None:
        assert set(javascript_adapters()) == set(JS_TOOL_IDS)


class TestTip:
    def test_specs_match_descriptors(self) -> None:
        specs = javascript_tool_specs()
        assert {spec.tool_id for spec in specs} == set(JS_TOOL_IDS)
        assert specs[0].tool_id == JavaScriptAnalyzerAdapter.descriptor.name
        assert specs[0].version == JavaScriptAnalyzerAdapter.descriptor.version

    def test_register_tools(self) -> None:
        from hunterx.tools.intelligence.api import ToolIntelligenceAPI

        tip = ToolIntelligenceAPI()
        register_javascript_tools(tip)
        assert tip.get_tool("javascript") is not None
        metadata = {tool.tool_id for tool in tip.registry.list_metadata()}
        assert set(metadata) == set(JS_TOOL_IDS)


class TestPipeline:
    def test_adapter_end_to_end_through_sdk(self) -> None:
        engine = ExecutionEngine()
        adapters = register_javascript_adapters(engine)
        engine.install_hook("javascript", lambda _tid, _version: "1.0.0")
        engine.install("javascript", version="1.0.0")
        assert adapters["javascript"] is not None

        outcome = engine.execute(_context())
        assert outcome.result.status.is_success
        assert outcome.result.output.json is not None
        assert len(outcome.result.output.json["javascript"]["analyses"]) == 1

    def test_health_check_gates_uninstalled_tool(self) -> None:
        engine = ExecutionEngine()
        register_javascript_adapters(engine)
        outcome = engine.execute(_context())
        assert not outcome.result.status.is_success
        assert "not installed" in outcome.result.error
