# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tests for TIP registration of the recon capability.

Verifies that the six recon tools are registered into the Tool Intelligence
Platform with taxonomy capability IDs and that the TIP metadata stays in sync
with the Tool Integration SDK adapters (same tool set, same version pins).
"""

from __future__ import annotations

from hunterx.tools.intelligence.api import ToolIntelligenceAPI
from hunterx.tools.recon import RECON_TOOL_IDS, register_recon_adapters, register_recon_tools
from hunterx.tools.sdk.engine import ExecutionEngine


class TestReconTipRegistration:
    def test_registers_all_recon_tools(self) -> None:
        tip = ToolIntelligenceAPI()
        register_recon_tools(tip)
        metadata = {tool.tool_id: tool for tool in tip.registry.list_metadata()}
        assert set(metadata) == set(RECON_TOOL_IDS)
        subfinder = metadata["subfinder"]
        assert subfinder.category == "recon"
        assert subfinder.version == "2.14.0"
        assert "subdomain-discovery" in tip.get_knowledge("subfinder").capabilities

    def test_capability_providers_resolve(self) -> None:
        tip = ToolIntelligenceAPI()
        register_recon_tools(tip)
        for capability in (
            "subdomain-discovery",
            "host-discovery",
            "dns-records",
            "certificate-lookup",
            "whois-lookup",
        ):
            providers = tip.tools_by_capability(capability)
            assert providers, capability
            assert set(providers) <= set(RECON_TOOL_IDS)

    def test_recommendation_finds_subdomain_tools(self) -> None:
        tip = ToolIntelligenceAPI()
        register_recon_tools(tip)
        recommended = tip.recommend("subdomain-discovery")
        assert recommended
        assert {tool.tool_id for tool in recommended} <= set(RECON_TOOL_IDS)

    def test_tip_metadata_matches_adapters(self) -> None:
        tip = ToolIntelligenceAPI()
        register_recon_tools(tip)
        engine = ExecutionEngine()
        register_recon_adapters(engine)
        for tool_id in RECON_TOOL_IDS:
            metadata = tip.get_tool(tool_id)
            adapter = engine.adapter_for(tool_id)
            assert metadata is not None
            assert adapter is not None
            assert metadata.version == adapter.descriptor.version
