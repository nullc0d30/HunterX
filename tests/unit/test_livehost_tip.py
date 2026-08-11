# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tests for TIP registration of the Live Host & Service Discovery capability.

Verifies that the live discovery tools (nmap, naabu, masscan, tcp-connect) are
registered into the Tool Intelligence Platform with taxonomy capability IDs and
that the TIP metadata stays in sync with the Tool Integration SDK adapters.
"""

from __future__ import annotations

from hunterx.tools.intelligence.api import ToolIntelligenceAPI
from hunterx.tools.livehost import (
    LIVE_TOOL_IDS,
    register_live_adapters,
    register_live_tools,
)
from hunterx.tools.sdk.engine import ExecutionEngine


class TestLiveTipRegistration:
    def test_registers_all_live_tools(self) -> None:
        tip = ToolIntelligenceAPI()
        register_live_tools(tip)
        metadata = {tool.tool_id: tool for tool in tip.registry.list_metadata()}
        assert set(metadata) == set(LIVE_TOOL_IDS)
        nmap = metadata["nmap"]
        assert nmap.category == "recon"
        assert nmap.version == "7.95"
        assert "host-discovery" in tip.get_knowledge("nmap").capabilities
        assert "service-fingerprint" in tip.get_knowledge("nmap").capabilities

    def test_capability_providers_resolve(self) -> None:
        tip = ToolIntelligenceAPI()
        register_live_tools(tip)
        for capability in ("host-discovery", "port-scanning", "service-fingerprint"):
            providers = tip.tools_by_capability(capability)
            assert providers, capability
            assert set(providers) <= set(LIVE_TOOL_IDS)

    def test_recommendation_finds_live_tools(self) -> None:
        tip = ToolIntelligenceAPI()
        register_live_tools(tip)
        recommended = tip.recommend("port-scanning")
        assert recommended
        assert {tool.tool_id for tool in recommended} <= set(LIVE_TOOL_IDS)

    def test_tip_metadata_matches_adapters(self) -> None:
        tip = ToolIntelligenceAPI()
        register_live_tools(tip)
        engine = ExecutionEngine()
        register_live_adapters(engine)
        for tool_id in LIVE_TOOL_IDS:
            metadata = tip.get_tool(tool_id)
            adapter = engine.adapter_for(tool_id)
            assert metadata is not None
            assert adapter is not None
            assert metadata.version == adapter.descriptor.version
