# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tests for the authorization intelligence TIP registration.

Verifies the Tool Intelligence Platform profile mirrors the Tool SDK adapter
descriptor: tool id, version, capabilities, passive-mode safety and the
mission profiles that exercise the capability.
"""

from __future__ import annotations

from hunterx.tools.authorization import authorization_tool_specs, register_authorization_tools
from hunterx.tools.authorization.analyzer import AuthorizationAnalyzerAdapter
from hunterx.tools.authorization.registry import AUTHORIZATION_TOOL_IDS
from hunterx.tools.intelligence.api import ToolIntelligenceAPI


class TestAuthorizationTip:
    def test_tool_registered(self) -> None:
        tip = ToolIntelligenceAPI()
        register_authorization_tools(tip)
        ids = [tool.tool_id for tool in tip.list_tools()]
        assert "authorization-analysis" in ids
        spec = tip.get_tool("authorization-analysis")
        assert spec is not None
        assert spec.tool_id == "authorization-analysis"
        assert spec.version == "1.0.0"

    def test_adapter_tip_capability_parity(self) -> None:
        adapter = AuthorizationAnalyzerAdapter()
        caps = set(adapter.descriptor.capabilities)
        assert adapter.descriptor.name in AUTHORIZATION_TOOL_IDS
        for spec in authorization_tool_specs():
            assert set(spec.capabilities) == caps

    def test_spec_modes_passive_safe(self) -> None:
        specs = authorization_tool_specs()
        assert specs
        assert any(mode.safe for mode in specs[0].modes)

    def test_tools_by_capability(self) -> None:
        tip = ToolIntelligenceAPI()
        register_authorization_tools(tip)
        assert "authorization-analysis" in tip.tools_by_capability("authorization-intelligence")
