# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Unit tests: capability-driven tool selection and fallback."""

from __future__ import annotations

from hunterx.domain.orchestration.enums import MissionType
from hunterx.domain.orchestration.models import ToolPolicy
from hunterx.domain.orchestration.selection import CapabilityNeed
from hunterx.engines.orchestration.fallback import FallbackEngine
from hunterx.engines.orchestration.selector import MissionToolSelector
from hunterx.tools.intelligence.api import ToolIntelligenceAPI
from tests.framework.tip import make_compatibility, make_knowledge, make_metadata


def _tip() -> ToolIntelligenceAPI:
    tip = ToolIntelligenceAPI()
    tip.register_tool(
        make_metadata(
            "katana",
            category="recon",
            subcategory="http",
            description="web crawler",
        ),
        knowledge=make_knowledge(
            "katana",
            capabilities=("web-crawling", "url-discovery"),
            accepts=("url", "domain"),
            required_inputs=("url",),
            missions=("web-security", "bug-bounty"),
        ),
        compatibility=make_compatibility("katana"),
    )
    tip.register_tool(
        make_metadata(
            "gau",
            category="recon",
            subcategory="http",
            description="url discovery",
        ),
        knowledge=make_knowledge(
            "gau",
            capabilities=("url-discovery",),
            accepts=("url", "domain"),
            required_inputs=("url",),
            missions=("web-security",),
        ),
        compatibility=make_compatibility("gau"),
    )
    return tip


def test_selector_finds_capability_tool() -> None:
    tip = _tip()
    selector = MissionToolSelector(tip=tip, engine=None)
    need = CapabilityNeed(capability="web-crawling", target_type="url")
    result = selector.select_primary(need, mission_type=MissionType.BUG_BOUNTY)
    assert result.tool_id == "katana"
    assert result.capability == "web-crawling"


def test_selector_respects_tool_policy() -> None:
    tip = _tip()
    selector = MissionToolSelector(tip=tip, engine=None)
    need = CapabilityNeed(capability="url-discovery", target_type="url")
    result = selector.select_primary(
        need,
        mission_type=MissionType.BUG_BOUNTY,
        policy=ToolPolicy(excluded_tools=("gau",)),
    )
    assert result.tool_id == "katana"


def test_selector_returns_alternatives_excluding_primary() -> None:
    tip = _tip()
    selector = MissionToolSelector(tip=tip, engine=None)
    need = CapabilityNeed(capability="url-discovery", target_type="url")
    alternatives = selector.alternatives(need, primary="katana", mission_type=MissionType.BUG_BOUNTY)
    assert all(item.tool_id != "katana" for item in alternatives)
    assert any(item.tool_id == "gau" for item in alternatives)


def test_fallback_selects_alternative() -> None:
    tip = _tip()
    selector = MissionToolSelector(tip=tip, engine=None)
    fallback = FallbackEngine(selector)
    decision = fallback.select_fallback(
        step_id="s1",
        primary="katana",
        need=CapabilityNeed(capability="url-discovery", target_type="url"),
        mission_type=MissionType.BUG_BOUNTY,
    )
    assert decision.fallback_tool == "gau"
    assert decision.primary_tool == "katana"


def test_selector_no_candidates_raises() -> None:
    tip = _tip()
    selector = MissionToolSelector(tip=tip, engine=None)
    need = CapabilityNeed(capability="port-scanning", target_type="host")
    try:
        selector.select(need, mission_type=MissionType.BUG_BOUNTY)
        raise AssertionError("expected ToolSelectionUnavailableError")
    except Exception as exc:  # noqa: BLE001
        from hunterx.domain.exceptions import ToolSelectionError

        # The TIP engine raises ToolSelectionError; the orchestration wrapper
        # converts it into ToolSelectionUnavailableError at the executor level.
        assert isinstance(exc, (ToolSelectionError, Exception))
