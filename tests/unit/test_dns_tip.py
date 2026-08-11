# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tests for TIP registration of the DNS capability.

Verifies that the DNS tools (dnsx, dnspython) are registered into the Tool
Intelligence Platform with taxonomy capability IDs and that the TIP metadata
stays in sync with the Tool Integration SDK adapters.
"""

from __future__ import annotations

from hunterx.tools.dns import DNS_TOOL_IDS, register_dns_adapters, register_dns_tools
from hunterx.tools.intelligence.api import ToolIntelligenceAPI
from hunterx.tools.sdk.engine import ExecutionEngine


class TestDnsTipRegistration:
    def test_registers_all_dns_tools(self) -> None:
        tip = ToolIntelligenceAPI()
        register_dns_tools(tip)
        metadata = {tool.tool_id: tool for tool in tip.registry.list_metadata()}
        assert set(metadata) == set(DNS_TOOL_IDS)
        dnsx = metadata["dnsx"]
        assert dnsx.category == "recon"
        assert dnsx.version == "1.1.9"
        assert "dns-records" in tip.get_knowledge("dnsx").capabilities

    def test_capability_providers_resolve(self) -> None:
        tip = ToolIntelligenceAPI()
        register_dns_tools(tip)
        for capability in ("dns-records", "dns-resolution", "dnssec"):
            providers = tip.tools_by_capability(capability)
            assert providers, capability
            assert set(providers) <= set(DNS_TOOL_IDS)

    def test_recommendation_finds_dns_tools(self) -> None:
        tip = ToolIntelligenceAPI()
        register_dns_tools(tip)
        recommended = tip.recommend("dns-records")
        assert recommended
        assert {tool.tool_id for tool in recommended} <= set(DNS_TOOL_IDS)

    def test_tip_metadata_matches_adapters(self) -> None:
        tip = ToolIntelligenceAPI()
        register_dns_tools(tip)
        engine = ExecutionEngine()
        register_dns_adapters(engine)
        for tool_id in DNS_TOOL_IDS:
            metadata = tip.get_tool(tool_id)
            adapter = engine.adapter_for(tool_id)
            assert metadata is not None
            assert adapter is not None
            assert metadata.version == adapter.descriptor.version
