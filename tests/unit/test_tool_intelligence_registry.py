# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tests for the tool intelligence registry."""

from __future__ import annotations

import pytest

from hunterx.domain.exceptions import ToolNotFoundError, ToolRegistrationError
from hunterx.domain.tool_intelligence import ToolRuntimeState, ToolState
from hunterx.tools.intelligence.registry import ToolIntelligenceRegistry
from tests.framework.tip import make_knowledge, make_metadata


def test_register_and_get_metadata() -> None:
    registry = ToolIntelligenceRegistry()
    registry.register_metadata(make_metadata("katana"))

    metadata = registry.get_metadata("katana")
    assert metadata is not None
    assert metadata.tool_id == "katana"
    assert registry.get_metadata("missing") is None


def test_register_creates_registered_state() -> None:
    registry = ToolIntelligenceRegistry()
    registry.register_metadata(make_metadata("katana"))

    state = registry.get_state("katana")
    assert state is not None
    assert state.state == ToolState.REGISTERED


def test_register_rejects_duplicate() -> None:
    registry = ToolIntelligenceRegistry()
    registry.register_metadata(make_metadata("katana"))
    with pytest.raises(ToolRegistrationError):
        registry.register_metadata(make_metadata("katana"))


def test_register_rejects_non_lowercase_id() -> None:
    registry = ToolIntelligenceRegistry()
    with pytest.raises(ToolRegistrationError):
        registry.register_metadata(make_metadata("Katana"))


def test_list_and_search() -> None:
    registry = ToolIntelligenceRegistry()
    registry.register_metadata(make_metadata("katana", tags=("crawler",)))
    registry.register_metadata(make_metadata("nmap", tags=("scanner",)))

    assert [m.tool_id for m in registry.list_metadata()] == ["katana", "nmap"]
    assert [m.tool_id for m in registry.search("crawl")] == ["katana"]
    assert [m.tool_id for m in registry.search("NMAP")] == ["nmap"]
    assert registry.search("nothing") == []


def test_knowledge_registers_providers() -> None:
    registry = ToolIntelligenceRegistry()
    registry.register_metadata(make_metadata("katana"))
    registry.register_knowledge(
        make_knowledge("katana", capabilities=("web-crawling", "http-enumeration"))
    )

    assert registry.providers_for("web-crawling") == ["katana"]
    assert registry.capabilities_for("katana") == ["web-crawling", "http-enumeration"]


def test_remove_tool_cleans_providers() -> None:
    registry = ToolIntelligenceRegistry()
    registry.register_metadata(make_metadata("katana"))
    registry.register_knowledge(
        make_knowledge("katana", capabilities=("web-crawling",))
    )
    assert registry.remove_tool("katana") is True
    assert registry.get_metadata("katana") is None
    assert registry.providers_for("web-crawling") == []
    assert registry.remove_tool("katana") is False


def test_capability_and_compatibility_stores() -> None:
    from hunterx.domain.tool_intelligence import ToolCapability, ToolCompatibility

    registry = ToolIntelligenceRegistry()
    registry.register_metadata(make_metadata("katana"))
    capability = ToolCapability(capability_id="web-crawling", name="Web Crawling")
    registry.register_capability(capability)
    assert registry.get_capability("web-crawling") == capability
    assert registry.list_capabilities() == [capability]

    compatibility = ToolCompatibility(tool_id="katana", os=("linux",))
    registry.register_compatibility(compatibility)
    assert registry.get_compatibility("katana") == compatibility


def test_runtime_state_roundtrip() -> None:
    registry = ToolIntelligenceRegistry()
    registry.register_metadata(make_metadata("katana"))
    state = ToolRuntimeState(tool_id="katana", state=ToolState.AVAILABLE)
    registry.set_state(state)
    assert registry.get_state("katana") == state


def test_to_dict_serializes_all_sections() -> None:
    registry = ToolIntelligenceRegistry()
    registry.register_metadata(make_metadata("katana"))
    registry.register_knowledge(
        make_knowledge("katana", capabilities=("web-crawling",))
    )

    payload = registry.to_dict()
    assert {section in payload for section in ("metadata", "knowledge", "capabilities", "state", "health", "performance")}
    assert payload["metadata"][0]["tool_id"] == "katana"


def test_duplicate_registration_raises_via_lifecycle_style() -> None:
    registry = ToolIntelligenceRegistry()
    registry.register_metadata(make_metadata("katana"))
    registry.register_metadata(make_metadata("nmap"))

    with pytest.raises(ToolRegistrationError):
        registry.register_metadata(make_metadata("nmap"))


def test_not_found_uses_tool_not_found() -> None:
    with pytest.raises(ToolNotFoundError):
        raise ToolNotFoundError("katana")
