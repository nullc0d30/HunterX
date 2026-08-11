# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tests for the cloud tool adapter & TIP registration."""

from __future__ import annotations

from hunterx.tools.cloud import cloud_tool_specs, register_cloud_adapters, register_cloud_tools
from hunterx.tools.cloud.analyzer import CloudAnalyzerAdapter
from hunterx.tools.intelligence.api import ToolIntelligenceAPI
from hunterx.tools.sdk.engine import ExecutionEngine


class TestCloudTip:
    def test_register_cloud_tools(self) -> None:
        tip = ToolIntelligenceAPI()
        register_cloud_tools(tip)
        ids = [tool.tool_id for tool in tip.list_tools()]
        assert "cloud-analysis" in ids

    def test_specs_share_capabilities_with_adapter(self) -> None:
        adapter = CloudAnalyzerAdapter()
        caps = set(adapter.descriptor.capabilities)
        for spec in cloud_tool_specs():
            assert set(spec.capabilities) == caps

    def test_specs_passive_safe(self) -> None:
        for spec in cloud_tool_specs():
            assert any(mode.safe for mode in spec.modes)

    def test_tools_queryable_by_capability(self) -> None:
        tip = ToolIntelligenceAPI()
        register_cloud_tools(tip)
        assert "cloud-analysis" in tip.tools_by_capability("cloud-intelligence")
        assert "cloud-analysis" in tip.tools_by_capability("cloud-attack-surface-intelligence")

    def test_adapter_descriptor_version_matches_spec(self) -> None:
        adapter = CloudAnalyzerAdapter()
        spec = cloud_tool_specs()[0]
        assert adapter.descriptor.version == spec.version


class TestCloudAdapters:
    def test_register_cloud_adapters(self) -> None:
        engine = ExecutionEngine()
        adapters = register_cloud_adapters(engine)
        assert "cloud-analysis" in adapters
        assert engine.adapter_for("cloud-analysis") is not None

    def test_adapter_run_produces_observations(self) -> None:
        engine = ExecutionEngine()
        register_cloud_adapters(engine)
        engine.install_hook("cloud-analysis", lambda _tid, _version: "1.0.0")
        engine.install("cloud-analysis", version="1.0.0")
        from hunterx.tools.sdk.context import ExecutionContextBuilder

        context = (
            ExecutionContextBuilder(tool_id="cloud-analysis", target="acme.com")
            .with_parameters(
                {
                    "cloud_input": {
                        "target": "acme.com",
                        "domain": "acme.com",
                        "records": [
                            {"name": "www.acme.com", "type": "CNAME", "cname_target": "d3m1234.cloudfront.net"}
                        ],
                    }
                }
            )
            .build()
        )
        outcome = engine.execute(context)
        assert outcome.result.status.is_success
        payload = outcome.result.output.json or {}
        assert payload.get("cloud")
        assert payload["count"] >= 1
