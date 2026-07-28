import sys
import os
import tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from core.payload_graph import PayloadKnowledgeGraph
from core.payload_index import IndexedPayload


def test_graph_init():
    with tempfile.TemporaryDirectory() as tmp:
        db = os.path.join(tmp, "graph.db")
        graph = PayloadKnowledgeGraph(db_path=db)
        stats = graph.get_statistics()
        assert stats["total_nodes"] == 0
        assert stats["total_edges"] == 0
        graph.close()


def test_graph_ensure_node():
    with tempfile.TemporaryDirectory() as tmp:
        db = os.path.join(tmp, "graph.db")
        graph = PayloadKnowledgeGraph(db_path=db)
        nid = graph.ensure_node("TECHNOLOGY", "PHP", description="PHP language")
        assert nid > 0
        nid2 = graph.ensure_node("TECHNOLOGY", "PHP")
        assert nid2 == nid  # duplicate returns same id
        graph.close()


def test_graph_ensure_edge():
    with tempfile.TemporaryDirectory() as tmp:
        db = os.path.join(tmp, "graph.db")
        graph = PayloadKnowledgeGraph(db_path=db)
        n1 = graph.ensure_node("TECHNOLOGY", "PHP")
        n2 = graph.ensure_node("CATEGORY", "RCE")
        eid = graph.ensure_edge(n1, n2, "TARGETS")
        assert eid > 0
        stats = graph.get_statistics()
        assert stats["total_edges"] >= 1
        graph.close()


def test_graph_link_payload():
    with tempfile.TemporaryDirectory() as tmp:
        db = os.path.join(tmp, "graph.db")
        graph = PayloadKnowledgeGraph(db_path=db)
        payload = IndexedPayload(
            row_id=1,
            filename="test.txt",
            file_path="RCE/test.txt",
            category="RCE",
            payload_text="cat /etc/passwd",
            payload_hash="abc123",
            technology=["PHP"],
            framework=["Laravel"],
            language=["PHP"],
            os_targets=["Linux"],
            metadata_json='{"related_cwes":["CWE-78"],"mitre_techniques":["T1203"],"owasp_categories":["A03:2021-Injection"]}',
        )
        nid = graph.link_payload(payload)
        assert nid > 0
        stats = graph.get_statistics()
        assert stats["total_nodes"] >= 5  # payload + category + tech + fw + lang + os + cwe + mitre + owasp
        assert stats["total_edges"] >= 1
        graph.close()


def test_graph_search_nodes():
    with tempfile.TemporaryDirectory() as tmp:
        db = os.path.join(tmp, "graph.db")
        graph = PayloadKnowledgeGraph(db_path=db)
        graph.ensure_node("TECHNOLOGY", "Node.js")
        graph.ensure_node("TECHNOLOGY", "Express")
        results = graph.search_nodes("Node")
        assert len(results) >= 1
        assert any("Node.js" in r["label"] for r in results)
        graph.close()


def test_graph_get_related():
    with tempfile.TemporaryDirectory() as tmp:
        db = os.path.join(tmp, "graph.db")
        graph = PayloadKnowledgeGraph(db_path=db)
        n1 = graph.ensure_node("TECHNOLOGY", "Django")
        n2 = graph.ensure_node("CWE", "CWE-89")
        graph.ensure_edge(n1, n2, "RELATES_TO")
        related = graph.get_related_nodes("TECHNOLOGY", "Django")
        assert len(related) >= 1
        labels = [r["label"] for r in related]
        assert "CWE-89" in labels
        graph.close()
