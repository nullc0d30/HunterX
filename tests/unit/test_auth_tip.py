# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tests for the authentication intelligence TIP registration."""

from __future__ import annotations

from hunterx.tools.auth import auth_tool_specs, register_auth_tools
from hunterx.tools.intelligence.api import ToolIntelligenceAPI


class TestAuthTip:
    def test_register_auth_tools(self) -> None:
        tip = ToolIntelligenceAPI()
        register_auth_tools(tip)
        ids = [tool.tool_id for tool in tip.list_tools()]
        assert "auth-analysis" in ids

    def test_specs_share_capabilities_with_adapter(self) -> None:
        from hunterx.tools.auth.analyzer import AuthAnalyzerAdapter

        adapter = AuthAnalyzerAdapter()
        caps = set(adapter.descriptor.capabilities)
        for spec in auth_tool_specs():
            assert set(spec.capabilities) == caps

    def test_specs_passive_safe(self) -> None:
        for spec in auth_tool_specs():
            assert any(mode.safe for mode in spec.modes)

    def test_tools_queryable_by_capability(self) -> None:
        tip = ToolIntelligenceAPI()
        register_auth_tools(tip)
        assert "auth-analysis" in tip.tools_by_capability("authentication-intelligence")
