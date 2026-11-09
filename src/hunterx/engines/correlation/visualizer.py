# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Attack path visualization integration."""

from __future__ import annotations
import json

class AttackPathVisualizer:
    """Exports the knowledge graph to a visualizable format."""

    def __init__(self, knowledge_graph):
        self.knowledge_graph = knowledge_graph

    def export(self) -> dict:
        """Export the knowledge graph to a JSON format for visualization."""
        # Placeholder for exporting logic
        data = self.knowledge_graph.to_dict() if hasattr(self.knowledge_graph, 'to_dict') else {}
        return data

    def to_json(self) -> str:
        """Return the exported data as a JSON string."""
        return json.dumps(self.export())
