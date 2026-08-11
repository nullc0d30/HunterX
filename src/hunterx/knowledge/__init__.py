# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Knowledge engine and knowledge graph.

Manages structured knowledge records (CWE/CVE categories, TTPs, remediation
guidance) and the knowledge graph linking findings, assets and vulnerabilities
for correlation and AI reasoning.
"""

from __future__ import annotations

from hunterx.knowledge.engine import KnowledgeEngine
from hunterx.knowledge.graph import KnowledgeGraph
from hunterx.knowledge.registry import KnowledgeRegistry

__all__ = ["KnowledgeEngine", "KnowledgeGraph", "KnowledgeRegistry"]
