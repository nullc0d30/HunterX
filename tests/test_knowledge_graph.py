# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0
#
# Tests for Knowledge Graph Engine
import json
from core.knowledge_graph import (
    KnowledgeGraph,
    GraphNode,
    GraphEdge,
    NodeType,
    RelationshipType,
)


class TestNodeType:
    def test_node_type_values(self):
        assert NodeType.HOST.value == "host"
        assert NodeType.FINDING.value == "finding"
        assert NodeType.PAYLOAD.value == "payload"
        assert NodeType.EVIDENCE.value == "evidence"


class TestRelationshipType:
    def test_relationship_values(self):
        assert RelationshipType.USES.value == "USES"
        assert RelationshipType.EXPLOITS.value == "EXPLOITS"
        assert RelationshipType.INDICATES.value == "INDICATES"


class TestGraphNode:
    def test_create_node(self):
        node = GraphNode(
            id="test-1",
            node_type=NodeType.HOST,
            label="http://example.com",
            properties={"url": "http://example.com"},
            confidence=0.95,
        )
        assert node.id == "test-1"
        assert node.node_type == NodeType.HOST
        assert node.label == "http://example.com"
        assert node.confidence == 0.95

    def test_to_dict(self):
        node = GraphNode(
            id="test-1",
            node_type=NodeType.FINDING,
            label="SQLI detected",
            properties={"category": "SQLI", "score": 85},
        )
        d = node.to_dict()
        assert d["id"] == "test-1"
        assert d["type"] == "finding"
        assert d["properties"]["category"] == "SQLI"


class TestGraphEdge:
    def test_create_edge(self):
        edge = GraphEdge(
            id="e-1",
            source_id="n1",
            target_id="n2",
            relationship=RelationshipType.EXPLOITS,
            weight=0.8,
        )
        assert edge.source_id == "n1"
        assert edge.target_id == "n2"
        assert edge.relationship == RelationshipType.EXPLOITS

    def test_to_dict(self):
        edge = GraphEdge(
            id="e-1",
            source_id="n1",
            target_id="n2",
            relationship=RelationshipType.USES,
            properties={"technique": "test"},
        )
        d = edge.to_dict()
        assert d["relationship"] == "USES"
        assert d["properties"]["technique"] == "test"


class TestKnowledgeGraph:
    def test_create_graph(self):
        kg = KnowledgeGraph(target_url="http://example.com")
        assert kg.target_url == "http://example.com"
        assert kg.node_count() == 0
        assert kg.edge_count() == 0

    def test_add_node(self):
        kg = KnowledgeGraph(target_url="http://example.com")
        node = kg.add_node(NodeType.HOST, "http://example.com", {"ip": "1.2.3.4"})
        assert node.id is not None
        assert node.node_type == NodeType.HOST
        assert kg.node_count() == 1

    def test_add_duplicate_node(self):
        kg = KnowledgeGraph(target_url="http://example.com")
        n1 = kg.add_node(NodeType.HOST, "test", node_id="same-id")
        n2 = kg.add_node(NodeType.HOST, "test", node_id="same-id")
        assert n1.id == n2.id
        assert kg.node_count() == 1

    def test_get_or_create_node(self):
        kg = KnowledgeGraph(target_url="http://example.com")
        n1 = kg.get_or_create_node(NodeType.OWASP, "OWASP-A7: XSS")
        n2 = kg.get_or_create_node(NodeType.OWASP, "OWASP-A7: XSS")
        assert n1.id == n2.id
        assert kg.node_count() == 1

    def test_add_edge(self):
        kg = KnowledgeGraph(target_url="http://example.com")
        host = kg.add_node(NodeType.HOST, "host1")
        finding = kg.add_node(NodeType.FINDING, "XSS found")
        edge = kg.add_edge(host.id, finding.id, RelationshipType.EXPOSES)
        assert edge.source_id == host.id
        assert edge.target_id == finding.id
        assert kg.edge_count() == 1

    def test_get_neighbors(self):
        kg = KnowledgeGraph(target_url="http://example.com")
        host = kg.add_node(NodeType.HOST, "host1")
        f1 = kg.add_node(NodeType.FINDING, "finding1")
        f2 = kg.add_node(NodeType.FINDING, "finding2")
        kg.add_edge(host.id, f1.id, RelationshipType.EXPOSES)
        kg.add_edge(host.id, f2.id, RelationshipType.EXPOSES)
        neighbors = kg.get_neighbors(host.id)
        assert len(neighbors) == 2

    def test_get_edges_for_node(self):
        kg = KnowledgeGraph(target_url="http://example.com")
        host = kg.add_node(NodeType.HOST, "host1")
        finding = kg.add_node(NodeType.FINDING, "finding1")
        kg.add_edge(host.id, finding.id, RelationshipType.EXPOSES)
        edges = kg.get_edges_for_node(host.id)
        assert len(edges) == 1

    def test_find_path(self):
        kg = KnowledgeGraph(target_url="http://example.com")
        a = kg.add_node(NodeType.HOST, "A", node_id="a")
        b = kg.add_node(NodeType.FINDING, "B", node_id="b")
        c = kg.add_node(NodeType.FINDING, "C", node_id="c")
        kg.add_edge(a.id, b.id, RelationshipType.EXPOSES)
        kg.add_edge(b.id, c.id, RelationshipType.RELATED_TO)
        path = kg.find_path("a", "c")
        assert path == ["a", "b", "c"]

    def test_find_path_no_path(self):
        kg = KnowledgeGraph(target_url="http://example.com")
        kg.add_node(NodeType.HOST, "A", node_id="a")
        kg.add_node(NodeType.FINDING, "C", node_id="c")
        path = kg.find_path("a", "c")
        assert path == []

    def test_find_paths_between(self):
        kg = KnowledgeGraph(target_url="http://example.com")
        a = kg.add_node(NodeType.HOST, "A", node_id="a")
        b = kg.add_node(NodeType.FINDING, "B", node_id="b")
        c = kg.add_node(NodeType.FINDING, "C", node_id="c")
        kg.add_edge(a.id, b.id, RelationshipType.EXPOSES)
        kg.add_edge(b.id, c.id, RelationshipType.RELATED_TO)
        paths = kg.find_paths_between("a", "c")
        assert len(paths) == 1
        assert paths[0] == ["a", "b", "c"]

    def test_get_nodes_by_type(self):
        kg = KnowledgeGraph(target_url="http://example.com")
        kg.add_node(NodeType.HOST, "h1")
        kg.add_node(NodeType.HOST, "h2")
        kg.add_node(NodeType.FINDING, "f1")
        hosts = kg.get_nodes_by_type(NodeType.HOST)
        assert len(hosts) == 2

    def test_get_edges_by_type(self):
        kg = KnowledgeGraph(target_url="http://example.com")
        h = kg.add_node(NodeType.HOST, "h")
        f = kg.add_node(NodeType.FINDING, "f")
        kg.add_edge(h.id, f.id, RelationshipType.EXPOSES)
        kg.add_edge(h.id, f.id, RelationshipType.USES)
        exposes = kg.get_edges_by_type(RelationshipType.EXPOSES)
        assert len(exposes) == 1

    def test_to_dict(self):
        kg = KnowledgeGraph(target_url="http://example.com")
        kg.add_node(NodeType.HOST, "h1")
        d = kg.to_dict()
        assert d["target_url"] == "http://example.com"
        assert len(d["nodes"]) == 1
        assert len(d["edges"]) == 0

    def test_to_json(self):
        kg = KnowledgeGraph(target_url="http://example.com")
        kg.add_node(NodeType.HOST, "h1")
        j = kg.to_json()
        parsed = json.loads(j)
        assert parsed["target_url"] == "http://example.com"

    def test_to_dot(self):
        kg = KnowledgeGraph(target_url="http://example.com")
        host = kg.add_node(NodeType.HOST, "h1")
        find = kg.add_node(NodeType.FINDING, "f1")
        kg.add_edge(host.id, find.id, RelationshipType.EXPOSES)
        dot = kg.to_dot()
        assert "digraph" in dot
        assert host.id in dot
        assert find.id in dot

    def test_to_graphml(self):
        kg = KnowledgeGraph(target_url="http://example.com")
        kg.add_node(NodeType.HOST, "h1")
        graphml = kg.to_graphml()
        assert "graphml" in graphml
        assert "h1" in graphml

    def test_merge(self):
        kg1 = KnowledgeGraph(target_url="http://example.com")
        kg2 = KnowledgeGraph(target_url="http://example.com")
        kg1.add_node(NodeType.HOST, "h1")
        kg2.add_node(NodeType.FINDING, "f1")
        kg1.merge(kg2)
        assert kg1.node_count() == 2

    def test_build_from_findings(self):
        kg = KnowledgeGraph(target_url="http://example.com")
        findings = [
            {"payload_category": "XSS", "payload": "<script>alert(1)</script>",
             "diff_score": 80, "stage": 2, "findings": ["Reflected XSS"]},
            {"payload_category": "LFI", "payload": "/etc/passwd",
             "diff_score": 65, "stage": 1, "findings": []},
        ]
        kg.build_from_findings(findings)
        assert kg.node_count() > 0
        assert kg.edge_count() > 0
        findings_nodes = kg.get_nodes_by_type(NodeType.FINDING)
        assert len(findings_nodes) == 2
        evidence_nodes = kg.get_nodes_by_type(NodeType.EVIDENCE)
        assert len(evidence_nodes) >= 1

    def test_build_from_findings_with_context(self):
        kg = KnowledgeGraph(target_url="http://example.com")
        findings = [
            {"payload_category": "XSS", "payload": "<script>", "diff_score": 50,
             "stage": 1, "findings": []},
        ]

        class MockContext:
            headers = {"Server": "nginx/1.20", "X-Powered-By": "PHP/8.0"}
            technologies = ["PHP", "nginx", "Linux"]

        kg.build_from_findings(findings, MockContext())
        headers = kg.get_nodes_by_type(NodeType.HEADER)
        assert len(headers) >= 1
        techs = kg.get_nodes_by_type(NodeType.TECHNOLOGY)
        assert len(techs) >= 1

    def test_repr(self):
        kg = KnowledgeGraph(target_url="http://example.com")
        kg.add_node(NodeType.HOST, "h1")
        r = repr(kg)
        assert "KnowledgeGraph" in r
        assert "example.com" in r
