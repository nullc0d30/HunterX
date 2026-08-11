# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0
#
# Tests for Visual Attack Graph
import tempfile
import os
import pytest
from core.visual_graph import VisualAttackGraph, VisualGraphConfig
from core.knowledge_graph import KnowledgeGraph, NodeType, RelationshipType
from core.attack_chain import AttackPath, ChainTransition
from core.threat_model import ThreatModel, Asset, AssetType


@pytest.fixture
def sample_kg():
    kg = KnowledgeGraph(target_url="http://example.com")
    host = kg.add_node(NodeType.HOST, "example.com", {"ip": "1.2.3.4"})
    finding = kg.add_node(NodeType.FINDING, "XSS detected", {"category": "XSS", "score": 85})
    evidence = kg.add_node(NodeType.EVIDENCE, "Reflected in response")
    kg.add_edge(host.id, finding.id, RelationshipType.EXPOSES)
    kg.add_edge(finding.id, evidence.id, RelationshipType.INDICATES)
    return kg


class TestVisualAttackGraph:
    def test_create(self):
        vg = VisualAttackGraph()
        assert vg.config.show_legend is True

    def test_from_knowledge_graph(self, sample_kg):
        vg = VisualAttackGraph()
        html = vg.from_knowledge_graph(sample_kg)
        assert "<!DOCTYPE html" in html
        assert "vis-network" in html
        assert "example.com" in html

    def test_from_knowledge_graph_with_output(self, sample_kg):
        vg = VisualAttackGraph()
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "graph.html")
            vg.from_knowledge_graph(sample_kg, path)
            assert os.path.exists(path)

    def test_from_attack_paths(self):
        vg = VisualAttackGraph()
        t = ChainTransition(
            source_finding="LFI", target_finding="RCE",
            technique="Log poisoning", confidence=0.7,
        )
        path = AttackPath(id="p1", name="LFI->RCE", steps=[t], overall_confidence=0.7)
        html = vg.from_attack_paths([path])
        assert "vis-network" in html
        assert "LFI" in html or "RCE" in html or "step" in html

    def test_from_threat_model(self):
        vg = VisualAttackGraph()
        tm = ThreatModel(id="tm1", target="http://example.com")
        tm.add_asset(Asset(id="a1", name="Web App", asset_type=AssetType.WEB_APPLICATION))
        html = vg.from_threat_model(tm)
        assert "vis-network" in html

    def test_to_mermaid(self, sample_kg):
        vg = VisualAttackGraph()
        mermaid = vg.to_mermaid(sample_kg)
        assert "graph LR" in mermaid

    def test_to_dot(self, sample_kg):
        vg = VisualAttackGraph()
        dot = vg.to_dot(sample_kg)
        assert "digraph" in dot

    def test_config_max_nodes(self):
        config = VisualGraphConfig(max_nodes=5)
        vg = VisualAttackGraph(config=config)
        kg = KnowledgeGraph(target_url="http://test.com")
        for i in range(20):
            kg.add_node(NodeType.HOST, f"host{i}")
        html = vg.from_knowledge_graph(kg)
        assert "vis-network" in html

    def test_config_hide_legend(self):
        config = VisualGraphConfig(show_legend=False)
        vg = VisualAttackGraph(config=config)
        assert vg.config.show_legend is False
