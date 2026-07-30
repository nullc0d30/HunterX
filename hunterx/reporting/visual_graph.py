# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0
#
# HunterX — AI-Assisted Vulnerability Hunter
from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass
from typing import Dict, List, Optional

from ..modules.intelligence.knowledge_graph import KnowledgeGraph, NodeType, RelationshipType
from ..modules.intelligence.attack_chain import AttackPath
from ..modules.intelligence.threat_model import ThreatModel
from ..utils.utils import logger


@dataclass
class VisualGraphConfig:
    show_legend: bool = True
    show_confidence: bool = True
    show_evidence: bool = True
    max_nodes: int = 200
    color_scheme: str = "default"
    layout: str = "hierarchical"
    height: str = "800px"
    width: str = "100%"


class VisualAttackGraph:
    def __init__(self, config: Optional[VisualGraphConfig] = None):
        self.config = config or VisualGraphConfig()

    def from_knowledge_graph(
        self,
        kg: KnowledgeGraph,
        output_path: Optional[str] = None,
    ) -> str:
        return self._generate_html(kg, output_path)

    def from_attack_paths(
        self,
        paths: List[AttackPath],
        kg: Optional[KnowledgeGraph] = None,
        output_path: Optional[str] = None,
    ) -> str:
        merged_kg = KnowledgeGraph(target_url=paths[0].steps[0].source_finding if paths else "unknown")
        if kg:
            merged_kg = kg

        for path in paths:
            for step in path.steps:
                source_id = f"step:{step.source_finding}"
                merged_kg.add_node(NodeType.FINDING, step.source_finding, {"technique": step.technique}, confidence=step.confidence, node_id=source_id)
                target_id = f"step:{step.target_finding}"
                merged_kg.add_node(NodeType.FINDING, step.target_finding, {}, confidence=step.confidence * 0.8, node_id=target_id)
                merged_kg.add_edge(source_id, target_id, RelationshipType.EXPLOITS, {
                    "confidence": step.confidence,
                    "likelihood": step.estimated_likelihood,
                })

        return self._generate_html(merged_kg, output_path)

    def from_threat_model(
        self,
        tm: ThreatModel,
        output_path: Optional[str] = None,
    ) -> str:
        kg = KnowledgeGraph(target_url=tm.target)

        for asset in tm.assets.values():
            asset_id = f"asset:{asset.id}"
            kg.add_node(
                NodeType.HOST if "web" in asset.asset_type.value else NodeType.SERVICE,
                asset.name,
                {"asset_type": asset.asset_type.value, "criticality": asset.criticality},
                node_id=asset_id,
            )

        for flow in tm.data_flows.values():
            kg.add_node(NodeType.ENDPOINT, flow.name, {"protocol": flow.protocol}, node_id=f"flow:{flow.id}")
            if flow.source in kg.nodes and flow.destination in kg.nodes:
                kg.add_edge(flow.source, flow.destination, RelationshipType.CONNECTS_TO, {
                    "protocol": flow.protocol,
                    "encrypted": flow.is_encrypted,
                })

        return self._generate_html(kg, output_path)

    def _generate_html(
        self,
        kg: KnowledgeGraph,
        output_path: Optional[str] = None,
    ) -> str:
        nodes_json = []
        edges_json = []

        type_colors = {
            "host": {"background": "#ff6b6b", "border": "#c0392b"},
            "technology": {"background": "#48dbfb", "border": "#0abde3"},
            "framework": {"background": "#ff9ff3", "border": "#f368e0"},
            "language": {"background": "#feca57", "border": "#f39c12"},
            "cookie": {"background": "#54a0ff", "border": "#2e86de"},
            "header": {"background": "#5f27cd", "border": "#341f97"},
            "authentication": {"background": "#ff6348", "border": "#e84118"},
            "endpoint": {"background": "#00d2d3", "border": "#01a3a4"},
            "finding": {"background": "#ff4757", "border": "#c0392b"},
            "parameter": {"background": "#2ed573", "border": "#27ae60"},
            "payload": {"background": "#eccc68", "border": "#d6a800"},
            "cve": {"background": "#ff4757", "border": "#c0392b"},
            "cwe": {"background": "#ffa502", "border": "#e67e22"},
            "owasp": {"background": "#3742fa", "border": "#1e3799"},
            "mitre_technique": {"background": "#a4b0be", "border": "#747d8c"},
            "waf": {"background": "#ff4757", "border": "#c0392b"},
            "evidence": {"background": "#7bed9f", "border": "#2ed573"},
            "domain": {"background": "#70a1ff", "border": "#1e90ff"},
            "certificate": {"background": "#ffa502", "border": "#e67e22"},
            "port": {"background": "#dfe6e9", "border": "#b2bec3"},
            "service": {"background": "#00cec9", "border": "#00b894"},
        }

        limit = min(len(kg.nodes), self.config.max_nodes)
        nodes_list = list(kg.nodes.values())[:limit]
        node_ids_included = {n.id for n in nodes_list}

        for i, node in enumerate(nodes_list):
            colors = type_colors.get(node.node_type.value, {"background": "#dfe6e9", "border": "#b2bec3"})
            title_parts = [f"Type: {node.node_type.value}", f"Confidence: {node.confidence:.2f}"]
            if self.config.show_evidence and node.properties:
                for k, v in list(node.properties.items())[:5]:
                    title_parts.append(f"{k}: {v}")
            title = "<br>".join(title_parts)
            safe_label = node.label[:50].replace('"', "\\").replace("'", "\\'")
            nodes_json.append({
                "id": node.id,
                "label": safe_label,
                "title": title,
                "color": colors,
                "shape": "box" if node.node_type in (NodeType.HOST, NodeType.FINDING) else "ellipse",
                "size": min(50, 20 + int(node.confidence * 30)),
                "font": {"size": 12, "face": "Courier"},
                "group": node.node_type.value,
            })

        for edge in kg.edges.values():
            if edge.source_id in node_ids_included and edge.target_id in node_ids_included:
                title = f"Relationship: {edge.relationship.value}<br>Confidence: {edge.confidence:.2f}<br>Weight: {edge.weight:.2f}"
                edges_json.append({
                    "from": edge.source_id,
                    "to": edge.target_id,
                    "label": edge.relationship.value,
                    "title": title,
                    "arrows": "to",
                    "color": {"color": "#95a5a6", "highlight": "#e74c3c"},
                    "font": {"size": 10, "face": "Courier", "color": "#7f8c8d"},
                    "width": max(1, edge.weight * 3),
                })

        html = self._build_html_template(nodes_json, edges_json)
        html = self._inject_copyright(html)

        if output_path:
            os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
            with open(output_path, "w") as f:
                f.write(html)
            logger.info(f"VisualAttackGraph: saved to {output_path}")

        return html

    def _build_html_template(self, nodes_json: List[Dict], edges_json: List[Dict]) -> str:
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>HunterX Attack Graph</title>
<style>
  body {{ margin: 0; padding: 0; font-family: 'Courier New', monospace; background: #0d0d0d; color: #e0e0e0; }}
  #mynetwork {{ width: 100%; height: {self.config.height}; border: none; }}
  .controls {{ position: fixed; top: 10px; right: 10px; z-index: 1000; background: #1a1a1a; padding: 10px; border: 1px solid #333; border-radius: 4px; }}
  .controls button {{ background: #333; color: #fff; border: 1px solid #555; padding: 5px 10px; margin: 2px; cursor: pointer; font-family: 'Courier New', monospace; }}
  .controls button:hover {{ background: #555; }}
  .legend {{ position: fixed; bottom: 10px; left: 10px; z-index: 1000; background: #1a1a1a; padding: 10px; border: 1px solid #333; border-radius: 4px; font-size: 12px; }}
  .stats {{ position: fixed; bottom: 10px; right: 10px; z-index: 1000; background: #1a1a1a; padding: 10px; border: 1px solid #333; border-radius: 4px; font-size: 12px; }}
  h3 {{ margin: 0 0 5px 0; color: #00ff00; }}
</style>
<script type="text/javascript" src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
</head>
<body>
<div id="mynetwork"></div>
<div class="controls">
  <button onclick="network.setOptions({{physics:{{enabled:true}}}})">Physics ON</button>
  <button onclick="network.setOptions({{physics:{{enabled:false}}}})">Physics OFF</button>
  <button onclick="network.fit()">Fit</button>
</div>
<div class="legend">
  <h3>Legend</h3>
  <div style="color:#ff6b6b;">&#9632; Host</div>
  <div style="color:#48dbfb;">&#9632; Technology</div>
  <div style="color:#ff9ff3;">&#9632; Framework</div>
  <div style="color:#ff4757;">&#9632; Finding</div>
  <div style="color:#7bed9f;">&#9632; Evidence</div>
  <div style="color:#feca57;">&#9632; Language</div>
  <div style="color:#5f27cd;">&#9632; Header</div>
</div>
<div class="stats" id="stats">
  <h3>Stats</h3>
  <div id="nodeCount">Nodes: {len(nodes_json)}</div>
  <div id="edgeCount">Edges: {len(edges_json)}</div>
</div>
<script>
  var nodes = new vis.DataSet({json.dumps(nodes_json)});
  var edges = new vis.DataSet({json.dumps(edges_json)});
  var container = document.getElementById('mynetwork');
  var data = {{ nodes: nodes, edges: edges }};
  var options = {{
    nodes: {{ shape: 'dot', size: 16, font: {{ face: 'Courier New', size: 12, color: '#e0e0e0' }} }},
    edges: {{ font: {{ face: 'Courier New', size: 10, color: '#95a5a6' }}, smooth: {{ type: 'continuous' }} }},
    physics: {{ enabled: true, solver: 'forceAtlas2Based', forceAtlas2Based: {{ gravitationalConstant: -80, springLength: 200 }} }},
    interaction: {{ hover: true, tooltipDelay: 200, navigationButtons: true, keyboard: true }},
    groups: {{
      'host': {{ shape: 'box', color: {{ background: '#ff6b6b', border: '#c0392b' }} }},
      'finding': {{ shape: 'box', color: {{ background: '#ff4757', border: '#c0392b' }} }},
      'technology': {{ shape: 'ellipse', color: {{ background: '#48dbfb', border: '#0abde3' }} }},
      'evidence': {{ shape: 'ellipse', color: {{ background: '#7bed9f', border: '#2ed573' }} }}
    }}
  }};
  var network = new vis.Network(container, data, options);
  window.addEventListener('resize', function() {{ network.fit(); }});
</script>
</body>
</html>"""

    def to_mermaid(self, kg: KnowledgeGraph) -> str:
        lines = ["graph LR"]
        for node in list(kg.nodes.values())[:self.config.max_nodes]:
            safe = node.label.replace('"', "#quot;")[:30]
            lines.append(f'    {node.id}["{safe}"]')

        for edge in list(kg.edges.values())[:self.config.max_nodes * 2]:
            lines.append(f'    {edge.source_id} -- "{edge.relationship.value}" --> {edge.target_id}')

        return "\n".join(lines)

    def to_dot(self, kg: KnowledgeGraph) -> str:
        return kg.to_dot()

    def to_png(self, kg: KnowledgeGraph, output_path: str) -> bool:
        try:
            dot = self.to_dot(kg)
            with tempfile.NamedTemporaryFile(mode="w", suffix=".dot", delete=False) as f:
                f.write(dot)
                dot_path = f.name
            import subprocess
            result = subprocess.run(
                ["dot", "-Tpng", dot_path, "-o", output_path],
                capture_output=True, text=True, timeout=30,
            )
            os.unlink(dot_path)
            if result.returncode == 0:
                logger.info(f"VisualAttackGraph: PNG saved to {output_path}")
                return True
            logger.warning(f"VisualAttackGraph: Graphviz failed: {result.stderr}")
            return False
        except FileNotFoundError:
            logger.warning("VisualAttackGraph: Graphviz not installed. Install with: apt-get install graphviz")
            return False
        except Exception as e:
            logger.warning(f"VisualAttackGraph: PNG generation failed: {e}")
            return False

    def to_svg(self, kg: KnowledgeGraph, output_path: str) -> bool:
        try:
            dot = self.to_dot(kg)
            with tempfile.NamedTemporaryFile(mode="w", suffix=".dot", delete=False) as f:
                f.write(dot)
                dot_path = f.name
            import subprocess
            result = subprocess.run(
                ["dot", "-Tsvg", dot_path, "-o", output_path],
                capture_output=True, text=True, timeout=30,
            )
            os.unlink(dot_path)
            if result.returncode == 0:
                logger.info(f"VisualAttackGraph: SVG saved to {output_path}")
                return True
            logger.warning(f"VisualAttackGraph: Graphviz failed: {result.stderr}")
            return False
        except FileNotFoundError:
            logger.warning("VisualAttackGraph: Graphviz not installed.")
            return False
        except Exception as e:
            logger.warning(f"VisualAttackGraph: SVG generation failed: {e}")
            return False

    @staticmethod
    def _inject_copyright(html: str) -> str:
        footer = '<div style="position:fixed;top:10px;left:10px;z-index:999;color:#555;font-size:11px;font-family:Courier New;">HunterX Attack Graph &copy; NullC0d3</div>'
        return html.replace("</body>", f"{footer}</body>")
