# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tests for the tool taxonomy and capability engine."""

from __future__ import annotations

from hunterx.domain.tool_intelligence import ToolCapability, ToolTaxonomyNode
from hunterx.tools.intelligence.capability import CapabilityEngine
from hunterx.tools.intelligence.registry import ToolIntelligenceRegistry
from hunterx.tools.intelligence.taxonomy import ToolTaxonomy
from tests.framework.tip import make_knowledge, make_metadata


class TestToolTaxonomy:
    def test_categories(self) -> None:
        taxonomy = ToolTaxonomy()
        assert taxonomy.categories() == ["recon", "assessment", "cloud", "directory", "analysis", "reporting"]

    def test_capabilities_include_canonical_ids(self) -> None:
        taxonomy = ToolTaxonomy()
        capabilities = taxonomy.capabilities()
        assert "subdomain-discovery" in capabilities
        assert "port-scanning" in capabilities
        assert "vulnerability-scan" in capabilities

    def test_root_is_built_from_tree(self) -> None:
        taxonomy = ToolTaxonomy()
        root = taxonomy.root
        assert isinstance(root, ToolTaxonomyNode)
        assert root.id == "root"
        assert len(root.children) == 6

    def test_find_descendant(self) -> None:
        taxonomy = ToolTaxonomy()
        node = taxonomy.root.find("web-crawling")
        assert node is not None
        assert node.kind == "capability"
        assert taxonomy.root.find("nope") is None

    def test_subcategories(self) -> None:
        taxonomy = ToolTaxonomy()
        assert taxonomy.subcategories("recon") == ["dns", "network", "http", "osint"]
        assert taxonomy.subcategories("nope") == []

    def test_classify(self) -> None:
        taxonomy = ToolTaxonomy()
        assert taxonomy.classify("web-crawling") == ("recon", "http")
        assert taxonomy.classify("port-scanning") == ("recon", "network")
        assert taxonomy.classify("nope") == ("", "")

    def test_techniques_and_missions(self) -> None:
        taxonomy = ToolTaxonomy()
        assert taxonomy.techniques_for("subdomain-discovery") == ("T1596",)
        assert taxonomy.techniques_for("nope") == ()
        assert taxonomy.missions_for("active-directory") == ("internal-pentest", "ad-security")


class TestCapabilityEngine:
    def _engine(self) -> tuple[CapabilityEngine, ToolIntelligenceRegistry]:
        registry = ToolIntelligenceRegistry()
        taxonomy = ToolTaxonomy()
        engine = CapabilityEngine(registry, taxonomy)
        engine.sync_taxonomy()
        return engine, registry

    def test_sync_taxonomy_seeds_all_capabilities(self) -> None:
        engine, _ = self._engine()
        capabilities = engine.capabilities()
        assert "web-crawling" in capabilities
        assert "reporting" in capabilities
        assert len(capabilities) == 50

    def test_synced_capabilities_have_category_and_description(self) -> None:
        engine, _ = self._engine()
        capability = engine.get("web-crawling")
        assert capability is not None
        assert capability.category == "recon"
        assert capability.subcategory == "http"
        assert capability.description

    def test_search(self) -> None:
        engine, _ = self._engine()
        matches = engine.search("crawl")
        ids = {capability.capability_id for capability in matches}
        assert "web-crawling" in ids

    def test_by_category(self) -> None:
        engine, _ = self._engine()
        cloud = engine.by_category("cloud")
        assert {cap.capability_id for cap in cloud} == {
            "cloud-assessment",
            "cloud-permission-audit",
            "storage-audit",
            "container-assessment",
            "image-scan",
            "k8s-audit",
            "serverless-audit",
        }

    def test_register_custom_capability(self) -> None:
        engine, _ = self._engine()
        engine.register(ToolCapability(capability_id="custom-thing", name="Custom Thing", category="custom"))
        assert engine.get("custom-thing") is not None

    def test_providers_derived_from_knowledge(self) -> None:
        _, registry = self._engine()
        registry.register_metadata(make_metadata("katana"))
        registry.register_knowledge(
            make_knowledge("katana", capabilities=("web-crawling",))
        )
        engine = CapabilityEngine(registry, ToolTaxonomy())
        assert engine.providers("web-crawling") == ["katana"]
        assert engine.capabilities_for("katana") == ["web-crawling"]
