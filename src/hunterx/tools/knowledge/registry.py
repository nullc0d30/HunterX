# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Knowledge dataset adapter registry."""

from __future__ import annotations

from collections.abc import Mapping

from hunterx.tools.knowledge.adapters import (
    FuzzdbAdapter,
    KnowledgeDatasetAdapter,
    PayloadsAllTheThingsAdapter,
    SeclistsAdapter,
)
from hunterx.tools.sdk.engine import ExecutionEngine

#: Canonical order and set of the integrated knowledge datasets.
KNOWLEDGE_TOOL_IDS: tuple[str, ...] = ("payloadsallthethings", "seclists", "fuzzdb")


class KnowledgeAdapterFactory:
    """Instantiate the knowledge dataset adapters."""

    def build(self) -> dict[str, KnowledgeDatasetAdapter]:
        """Return a fresh set of knowledge adapters keyed by tool id."""
        return {
            "payloadsallthethings": PayloadsAllTheThingsAdapter(),
            "seclists": SeclistsAdapter(),
            "fuzzdb": FuzzdbAdapter(),
        }

    def create(self, tool_id: str) -> KnowledgeDatasetAdapter:
        """Return a single adapter instance for ``tool_id``."""
        adapters = self.build()
        if tool_id not in adapters:
            raise KeyError(f"unknown knowledge tool '{tool_id}'")
        return adapters[tool_id]


def knowledge_adapters() -> dict[str, KnowledgeDatasetAdapter]:
    """Return a fresh mapping of knowledge tool id to adapter instance."""
    return KnowledgeAdapterFactory().build()


def register_knowledge_adapters(engine: ExecutionEngine) -> Mapping[str, KnowledgeDatasetAdapter]:
    """Register every knowledge adapter on ``engine`` and return the mapping."""
    adapters = knowledge_adapters()
    for tool_id, adapter in adapters.items():
        engine.register_adapter(tool_id, adapter)
    return adapters
