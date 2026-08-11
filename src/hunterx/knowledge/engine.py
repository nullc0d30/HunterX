# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Knowledge engine.

Answers questions like "what does CWE-79 mean?" and "which records relate to
this finding?" by combining the knowledge registry with the knowledge graph.
"""

from __future__ import annotations

from hunterx.domain.entities import Finding
from hunterx.knowledge.graph import KnowledgeGraph
from hunterx.knowledge.registry import KnowledgeRecord, KnowledgeRegistry
from hunterx.shared.result import Failure, Result, Success


class KnowledgeEngine:
    """Facade over the knowledge registry and graph.

    The engine validates that a graph backend is available before graph
    operations; registry lookups always work.
    """

    def __init__(self, registry: KnowledgeRegistry, graph: KnowledgeGraph | None = None) -> None:
        self._registry = registry
        self._graph = graph

    @property
    def registry(self) -> KnowledgeRegistry:
        """Return the underlying knowledge registry."""
        return self._registry

    @property
    def graph(self) -> KnowledgeGraph | None:
        """Return the underlying knowledge graph (may be ``None``)."""
        return self._graph

    def lookup(self, record_id: str) -> KnowledgeRecord | None:
        """Return a knowledge record by identifier."""
        return self._registry.get(record_id)

    def explain(self, finding: Finding) -> Result[list[KnowledgeRecord], Exception]:
        """Return knowledge records matching a finding's title/tags."""
        records = self._registry.query(finding.title, limit=10)
        return Success(records)

    def link_finding(self, finding: Finding, record: KnowledgeRecord) -> Result[bool, Exception]:
        """Link a finding to a knowledge record in the graph.

        Returns ``Failure`` when no graph backend is configured.
        """
        if self._graph is None:
            return Failure(Exception("Knowledge graph is not configured."))
        self._graph.add_relationship("references", finding.finding_id, record.record_id)
        return Success(True)
