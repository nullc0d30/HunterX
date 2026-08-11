# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0
#
# HunterX — AI-Assisted Vulnerability Hunter
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple
from xml.etree import ElementTree as ET

from ...utils.utils import logger


class NodeType(str, Enum):
    HOST = "host"
    TECHNOLOGY = "technology"
    FRAMEWORK = "framework"
    LANGUAGE = "language"
    COOKIE = "cookie"
    HEADER = "header"
    AUTHENTICATION = "authentication"
    ENDPOINT = "endpoint"
    FINDING = "finding"
    PARAMETER = "parameter"
    PAYLOAD = "payload"
    CVE = "cve"
    CWE = "cwe"
    OWASP = "owasp"
    MITRE_TECHNIQUE = "mitre_technique"
    WAF = "waf"
    EVIDENCE = "evidence"
    DOMAIN = "domain"
    CERTIFICATE = "certificate"
    PORT = "port"
    SERVICE = "service"


class RelationshipType(str, Enum):
    USES = "USES"
    HOSTS = "HOSTS"
    EXPOSES = "EXPOSES"
    DEPENDS_ON = "DEPENDS_ON"
    RELATED_TO = "RELATED_TO"
    INDICATES = "INDICATES"
    EXPLOITS = "EXPLOITS"
    MITIGATES = "MITIGATES"
    HAS = "HAS"
    RUNS = "RUNS"
    CONTAINS = "CONTAINS"
    CONNECTS_TO = "CONNECTS_TO"
    AUTHENTICATES = "AUTHENTICATES"


@dataclass
class GraphNode:
    id: str
    node_type: NodeType
    label: str
    properties: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 1.0
    source: str = "hunterx"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "type": self.node_type.value,
            "label": self.label,
            "properties": self.properties,
            "confidence": self.confidence,
            "source": self.source,
        }


@dataclass
class GraphEdge:
    id: str
    source_id: str
    target_id: str
    relationship: RelationshipType
    properties: Dict[str, Any] = field(default_factory=dict)
    weight: float = 1.0
    confidence: float = 1.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "source": self.source_id,
            "target": self.target_id,
            "relationship": self.relationship.value,
            "properties": self.properties,
            "weight": self.weight,
            "confidence": self.confidence,
        }


class KnowledgeGraph:
    def __init__(self, target_url: str, scan_id: Optional[str] = None):
        self.target_url = target_url
        self.scan_id = scan_id or str(uuid.uuid4())
        self.created_at = datetime.now(timezone.utc)
        self.nodes: Dict[str, GraphNode] = {}
        self.edges: Dict[str, GraphEdge] = {}
        self._adjacency: Dict[str, Set[str]] = {}

    def add_node(
        self,
        node_type: NodeType,
        label: str,
        properties: Optional[Dict[str, Any]] = None,
        confidence: float = 1.0,
        source: str = "hunterx",
        node_id: Optional[str] = None,
    ) -> GraphNode:
        node_id = node_id or f"{node_type.value}:{uuid.uuid4().hex[:12]}"
        if node_id not in self.nodes:
            self.nodes[node_id] = GraphNode(
                id=node_id,
                node_type=node_type,
                label=label,
                properties=properties or {},
                confidence=confidence,
                source=source,
            )
            self._adjacency[node_id] = set()
        return self.nodes[node_id]

    def get_or_create_node(
        self,
        node_type: NodeType,
        label: str,
        properties: Optional[Dict[str, Any]] = None,
        confidence: float = 1.0,
    ) -> GraphNode:
        for node in self.nodes.values():
            if node.node_type == node_type and node.label == label:
                merged = {**node.properties, **(properties or {})}
                node.properties = merged
                node.confidence = max(node.confidence, confidence)
                return node
        return self.add_node(node_type, label, properties, confidence)

    def add_edge(
        self,
        source_id: str,
        target_id: str,
        relationship: RelationshipType,
        properties: Optional[Dict[str, Any]] = None,
        weight: float = 1.0,
        confidence: float = 1.0,
    ) -> GraphEdge:
        edge_id = f"{source_id}:{relationship.value}:{target_id}"
        if edge_id not in self.edges:
            self.edges[edge_id] = GraphEdge(
                id=edge_id,
                source_id=source_id,
                target_id=target_id,
                relationship=relationship,
                properties=properties or {},
                weight=weight,
                confidence=confidence,
            )
            self._adjacency.setdefault(source_id, set()).add(target_id)
            self._adjacency.setdefault(target_id, set()).add(source_id)
        return self.edges[edge_id]

    def get_neighbors(self, node_id: str) -> List[GraphNode]:
        neighbor_ids = self._adjacency.get(node_id, set())
        return [self.nodes[nid] for nid in neighbor_ids if nid in self.nodes]

    def get_edges_for_node(self, node_id: str) -> List[GraphEdge]:
        return [
            edge for edge in self.edges.values()
            if edge.source_id == node_id or edge.target_id == node_id
        ]

    def find_path(self, source_id: str, target_id: str) -> List[str]:
        if source_id not in self.nodes or target_id not in self.nodes:
            return []
        visited: Set[str] = set()
        queue: List[Tuple[str, List[str]]] = [(source_id, [source_id])]
        while queue:
            current, path = queue.pop(0)
            if current == target_id:
                return path
            visited.add(current)
            for neighbor_id in self._adjacency.get(current, set()):
                if neighbor_id not in visited:
                    queue.append((neighbor_id, path + [neighbor_id]))
        return []

    def find_paths_between(
        self, source_id: str, target_id: str, max_depth: int = 5
    ) -> List[List[str]]:
        paths: List[List[str]] = []
        visited: Set[str] = set()

        def _dfs(current: str, target: str, path: List[str], depth: int):
            if depth > max_depth:
                return
            if current == target:
                paths.append(list(path))
                return
            visited.add(current)
            for neighbor_id in self._adjacency.get(current, set()):
                if neighbor_id not in visited:
                    path.append(neighbor_id)
                    _dfs(neighbor_id, target, path, depth + 1)
                    path.pop()
            visited.discard(current)

        if source_id in self.nodes and target_id in self.nodes:
            _dfs(source_id, target_id, [source_id], 0)
        return paths

    def get_nodes_by_type(self, node_type: NodeType) -> List[GraphNode]:
        return [n for n in self.nodes.values() if n.node_type == node_type]

    def get_edges_by_type(self, relationship: RelationshipType) -> List[GraphEdge]:
        return [e for e in self.edges.values() if e.relationship == relationship]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "target_url": self.target_url,
            "created_at": self.created_at.isoformat(),
            "nodes": [n.to_dict() for n in self.nodes.values()],
            "edges": [e.to_dict() for e in self.edges.values()],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def to_graphml(self) -> str:
        root = ET.Element("graphml", xmlns="http://graphml.graphdrawing.org/xmlns")
        graph = ET.SubElement(root, "graph", edgedefault="directed")

        node_keys = {
            "type": ("node", "string"),
            "label": ("node", "string"),
            "confidence": ("node", "double"),
            "source": ("node", "string"),
        }
        edge_keys = {
            "relationship": ("edge", "string"),
            "weight": ("edge", "double"),
            "confidence": ("edge", "double"),
        }

        for kid, (for_type, ktype) in {**node_keys, **edge_keys}.items():
            key_attrib = {"id": kid, "for": for_type, "attr.name": kid, "attr.type": ktype}
            ET.SubElement(root, "key", attrib=key_attrib)

        for node_id, node in self.nodes.items():
            n = ET.SubElement(graph, "node", id=node_id)
            for kid, val in [("type", node.node_type.value), ("label", node.label), ("confidence", str(node.confidence)), ("source", node.source)]:
                d = ET.SubElement(n, "data", key=kid)
                d.text = val

        for edge in self.edges.values():
            e = ET.SubElement(graph, "edge", id=edge.id, source=edge.source_id, target=edge.target_id)
            for kid, val in [("relationship", edge.relationship.value), ("weight", str(edge.weight)), ("confidence", str(edge.confidence))]:
                d = ET.SubElement(e, "data", key=kid)
                d.text = val

        return ET.tostring(root, encoding="unicode")

    def to_dot(self) -> str:
        lines = ["digraph HunterX {"]
        lines.append('  rankdir="LR";')
        lines.append('  node [shape=box, style=rounded, fontname="Courier"];')
        lines.append('  edge [fontname="Courier", fontsize=10];')

        type_colors: Dict[str, str] = {
            "host": "#ff6b6b", "technology": "#48dbfb", "framework": "#ff9ff3",
            "language": "#feca57", "cookie": "#54a0ff", "header": "#5f27cd",
            "authentication": "#ff6348", "endpoint": "#00d2d3", "finding": "#ff4757",
            "parameter": "#2ed573", "payload": "#eccc68", "cve": "#ff4757",
            "cwe": "#ffa502", "owasp": "#3742fa", "mitre_technique": "#a4b0be",
            "waf": "#ff4757", "evidence": "#7bed9f",
        }

        for node in self.nodes.values():
            color = type_colors.get(node.node_type.value, "#dfe6e9")
            safe_label = node.label.replace('"', '\\"')
            escaped_label = safe_label[:40] + "..." if len(safe_label) > 40 else safe_label
            lines.append(f'  "{node.id}" [label="{escaped_label}", fillcolor="{color}", style="filled,rounded"];')

        for edge in self.edges.values():
            lines.append(f'  "{edge.source_id}" -> "{edge.target_id}" [label="{edge.relationship.value}"];')

        lines.append("}")
        return "\n".join(lines)

    def to_networkx(self):
        try:
            import networkx as nx
            g = nx.DiGraph()
            for node_id, node in self.nodes.items():
                g.add_node(node_id, **node.to_dict())
            for edge in self.edges.values():
                g.add_edge(edge.source_id, edge.target_id, **edge.to_dict())
            return g
        except ImportError:
            logger.warning("networkx not available. Install with: pip install networkx")
            return None

    def merge(self, other: KnowledgeGraph):
        if other.target_url != self.target_url:
            logger.warning(f"Merging graph for different target: {other.target_url}")
        for node_id, node in other.nodes.items():
            if node_id not in self.nodes:
                self.nodes[node_id] = node
                self._adjacency[node_id] = set()
        for edge in other.edges.values():
            self.add_edge(edge.source_id, edge.target_id, edge.relationship, edge.properties, edge.weight, edge.confidence)

    def node_count(self) -> int:
        return len(self.nodes)

    def edge_count(self) -> int:
        return len(self.edges)

    def build_from_findings(self, findings: List[Dict], context: Any = None) -> None:
        target_node = self.add_node(
            NodeType.HOST, self.target_url,
            {"url": self.target_url}, confidence=1.0,
        )

        for finding in findings:
            cat = finding.get("payload_category", "UNKNOWN")
            finding_node = self.add_node(
                NodeType.FINDING, f"{cat}: {finding.get('payload', '')[:60]}",
                {
                    "category": cat,
                    "payload": finding.get("payload", ""),
                    "diff_score": finding.get("diff_score", 0),
                    "stage": finding.get("stage", 0),
                    "technique": finding.get("technique", "original"),
                },
                confidence=min(1.0, finding.get("diff_score", 0) / 100.0),
            )
            self.add_edge(
                target_node.id, finding_node.id,
                RelationshipType.EXPOSES,
                {"category": cat},
                weight=finding.get("diff_score", 0) / 100.0,
            )

            payload_node = self.add_node(
                NodeType.PAYLOAD, finding.get("payload", "")[:80],
                {"payload": finding.get("payload", ""), "category": cat},
            )
            self.add_edge(
                finding_node.id, payload_node.id,
                RelationshipType.USES,
            )

            if finding.get("findings"):
                for f_text in finding.get("findings", []):
                    evidence_node = self.add_node(
                        NodeType.EVIDENCE, str(f_text)[:100],
                        {"detail": str(f_text)},
                    )
                    self.add_edge(
                        finding_node.id, evidence_node.id,
                        RelationshipType.INDICATES,
                    )

            if cat == "XSS":
                owasp_node = self.get_or_create_node(NodeType.OWASP, "OWASP-A7: XSS", {"id": "A7"})
                self.add_edge(finding_node.id, owasp_node.id, RelationshipType.RELATED_TO)
            elif cat in ("LFI", "FILE_DISCLOSURE"):
                owasp_node = self.get_or_create_node(NodeType.OWASP, "OWASP-A5: Broken Access Control", {"id": "A5"})
                self.add_edge(finding_node.id, owasp_node.id, RelationshipType.RELATED_TO)

        if context:
            headers = getattr(context, "headers", {})
            if isinstance(headers, dict):
                for h_name, h_val in headers.items():
                    header_node = self.add_node(NodeType.HEADER, f"{h_name}: {str(h_val)[:50]}")
                    self.add_edge(target_node.id, header_node.id, RelationshipType.HAS, {"name": h_name})

            tech_info = getattr(context, "technologies", [])
            if isinstance(tech_info, list):
                for tech in tech_info:
                    tech_node = self.add_node(NodeType.TECHNOLOGY, str(tech))
                    self.add_edge(target_node.id, tech_node.id, RelationshipType.USES)

    def __repr__(self) -> str:
        return f"KnowledgeGraph(target={self.target_url}, nodes={self.node_count()}, edges={self.edge_count()})"
