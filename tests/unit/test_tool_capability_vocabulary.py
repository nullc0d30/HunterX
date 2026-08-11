# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for the canonical capability vocabulary (Sprint 031)."""

from __future__ import annotations

from hunterx.tools.intelligence.api import ToolIntelligenceAPI
from hunterx.tools.intelligence.vocabulary import CAPABILITY_ALIASES, CapabilityVocabulary


def test_canonicalization_of_arsenal_vocabulary() -> None:
    vocabulary = CapabilityVocabulary()
    assert vocabulary.canonical("subdomain-enumeration") == "subdomain-discovery"
    assert vocabulary.canonical("port-discovery") == "port-scanning"
    assert vocabulary.canonical("web-vulnerability-detection") == "vulnerability-scan"
    assert vocabulary.canonical("xss-discovery") == "xss-detection"
    assert vocabulary.canonical("sql-injection-detection") == "sqli-detection"


def test_unknown_capability_passes_through() -> None:
    vocabulary = CapabilityVocabulary()
    assert vocabulary.canonical("custom-capability") == "custom-capability"
    assert vocabulary.is_known("custom-capability") is False


def test_variants_roundtrip() -> None:
    vocabulary = CapabilityVocabulary()
    assert "subdomain-enumeration" in vocabulary.variants("subdomain-discovery")
    assert "port-discovery" in vocabulary.variants("port-scanning")


def test_alias_table_is_consistent() -> None:
    vocabulary = CapabilityVocabulary()
    for variant, canonical in CAPABILITY_ALIASES.items():
        assert vocabulary.canonical(variant) == canonical
        assert vocabulary.canonical(canonical) == canonical


def test_selection_matches_across_vocabularies() -> None:
    from hunterx.domain.tool_intelligence import ToolSelectionCriteria
    from tests.framework.tip import make_compatibility, make_knowledge, make_metadata

    tip = ToolIntelligenceAPI()
    # The tool advertises the arsenal vocabulary.
    tip.register_tool(
        make_metadata("subfinder", category="recon", description="Passive subdomain enumeration."),
        knowledge=make_knowledge("subfinder", capabilities=("subdomain-enumeration",)),
        compatibility=make_compatibility("subfinder"),
    )
    results = tip.select(
        ToolSelectionCriteria(required_capabilities=("subdomain-discovery",), require_installed=False)
    )
    assert results
    assert results[0].tool_id == "subfinder"
