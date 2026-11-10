"""Attack Path Visualizer verification."""

def test_graph_integrity():
    nodes = ["A", "B", "C"]
    edges = [("A", "B"), ("B", "C")]
    assert len(nodes) == 3
    assert len(edges) == 2
    # Check all edges reference valid nodes
    for src, dst in edges:
        assert src in nodes
        assert dst in nodes

def test_provenance_metadata():
    graph = {
        "nodes": [{"id": "A", "provenance": "recon"}],
        "edges": [{"src": "A", "dst": "B", "provenance": "tool:nmap"}]
    }
    assert graph["nodes"][0]["provenance"] == "recon"
    assert "provenance" in graph["edges"][0]
