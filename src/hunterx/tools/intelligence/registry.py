# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tool intelligence registry.

The central, thread-safe store of everything the platform knows about tools:
metadata, knowledge profiles, capabilities, compatibility, runtime state,
health and performance. Engines read from this registry; the facade composes
them.
"""

from __future__ import annotations

from dataclasses import asdict
from threading import RLock
from typing import Any

from hunterx.domain.exceptions import ToolRegistrationError
from hunterx.domain.tool_intelligence import (
    ToolAvailabilityReport,
    ToolCapability,
    ToolCompatibility,
    ToolConfidenceCeiling,
    ToolEvidenceMapping,
    ToolHealthStats,
    ToolKnowledge,
    ToolMetadata,
    ToolPerformanceStats,
    ToolProofCapability,
    ToolReliabilityStats,
    ToolRuntimeState,
    ToolState,
)


class ToolIntelligenceRegistry:
    """Thread-safe catalog of tool intelligence records.

    Every record type is keyed by ``tool_id``. Capabilities are indexed both
    by their own id and by provider tool so capability queries are cheap.
    """

    def __init__(self) -> None:
        self._lock = RLock()
        self._metadata: dict[str, ToolMetadata] = {}
        self._knowledge: dict[str, ToolKnowledge] = {}
        self._capabilities: dict[str, ToolCapability] = {}
        self._capability_providers: dict[str, set[str]] = {}
        self._compatibility: dict[str, ToolCompatibility] = {}
        self._state: dict[str, ToolRuntimeState] = {}
        self._health: dict[str, ToolHealthStats] = {}
        self._performance: dict[str, ToolPerformanceStats] = {}
        self._evidence_mappings: dict[str, list[ToolEvidenceMapping]] = {}
        self._proof_capabilities: dict[str, list[ToolProofCapability]] = {}
        self._confidence_ceilings: dict[str, ToolConfidenceCeiling] = {}
        self._reliability: dict[str, ToolReliabilityStats] = {}
        self._availability: dict[str, ToolAvailabilityReport] = {}

    # -- metadata ----------------------------------------------------------

    def register_metadata(self, metadata: ToolMetadata) -> None:
        """Register ``metadata``, rejecting duplicate tool ids."""
        with self._lock:
            if metadata.tool_id in self._metadata:
                raise ToolRegistrationError(metadata.tool_id, "already registered")
            if not metadata.tool_id or not metadata.tool_id.islower():
                raise ToolRegistrationError(
                    metadata.tool_id, "tool id must be lowercase"
                )
            self._metadata[metadata.tool_id] = metadata
            self._state.setdefault(
                metadata.tool_id,
                ToolRuntimeState(tool_id=metadata.tool_id, state=ToolState.REGISTERED),
            )

    def get_metadata(self, tool_id: str) -> ToolMetadata | None:
        """Return metadata for ``tool_id`` or ``None``."""
        with self._lock:
            return self._metadata.get(tool_id)

    def list_metadata(self) -> list[ToolMetadata]:
        """Return metadata for every registered tool."""
        with self._lock:
            return list(self._metadata.values())

    def update_metadata(self, metadata: ToolMetadata) -> None:
        """Replace metadata for an already-registered tool."""
        with self._lock:
            if metadata.tool_id not in self._metadata:
                raise ToolRegistrationError(metadata.tool_id, "not registered")
            self._metadata[metadata.tool_id] = metadata

    def remove_tool(self, tool_id: str) -> bool:
        """Remove all records for ``tool_id``; return ``True`` if it existed.

        Removes metadata, knowledge (and its capability providers), state,
        health and performance records.
        """
        with self._lock:
            knowledge = self._knowledge.pop(tool_id, None)
            if knowledge is not None:
                for capability_id in knowledge.capabilities:
                    providers = self._capability_providers.get(capability_id)
                    if providers is not None:
                        providers.discard(tool_id)
                        if not providers:
                            self._capability_providers.pop(capability_id, None)
            existed = self._metadata.pop(tool_id, None) is not None
            self._state.pop(tool_id, None)
            self._health.pop(tool_id, None)
            self._performance.pop(tool_id, None)
            self._compatibility.pop(tool_id, None)
            self._evidence_mappings.pop(tool_id, None)
            self._proof_capabilities.pop(tool_id, None)
            self._confidence_ceilings.pop(tool_id, None)
            self._reliability.pop(tool_id, None)
            self._availability.pop(tool_id, None)
            return existed

    def search(self, term: str) -> list[ToolMetadata]:
        """Return tools whose id/name/tags match ``term`` (case-insensitive)."""
        needle = term.lower()
        with self._lock:
            return [
                meta
                for meta in self._metadata.values()
                if needle in meta.tool_id
                or needle in meta.display_name.lower()
                or needle in meta.description.lower()
                or any(needle in tag.lower() for tag in meta.tags)
            ]

    # -- knowledge ---------------------------------------------------------

    def register_knowledge(self, knowledge: ToolKnowledge) -> None:
        """Register or replace a knowledge profile."""
        with self._lock:
            self._knowledge[knowledge.tool_id] = knowledge
            for capability_id in knowledge.capabilities:
                self._capability_providers.setdefault(capability_id, set()).add(
                    knowledge.tool_id
                )

    def get_knowledge(self, tool_id: str) -> ToolKnowledge | None:
        """Return the knowledge profile for ``tool_id`` or ``None``."""
        with self._lock:
            return self._knowledge.get(tool_id)

    def list_knowledge(self) -> list[ToolKnowledge]:
        """Return every registered knowledge profile."""
        with self._lock:
            return list(self._knowledge.values())

    # -- capabilities ------------------------------------------------------

    def register_capability(self, capability: ToolCapability) -> None:
        """Register or replace a capability definition."""
        with self._lock:
            self._capabilities[capability.capability_id] = capability

    def get_capability(self, capability_id: str) -> ToolCapability | None:
        """Return a capability definition or ``None``."""
        with self._lock:
            return self._capabilities.get(capability_id)

    def list_capabilities(self) -> list[ToolCapability]:
        """Return every registered capability definition."""
        with self._lock:
            return list(self._capabilities.values())

    def providers_for(self, capability_id: str) -> list[str]:
        """Return tool ids that provide ``capability_id``."""
        with self._lock:
            return sorted(self._capability_providers.get(capability_id, set()))

    def capabilities_for(self, tool_id: str) -> list[str]:
        """Return capability ids provided by ``tool_id``."""
        with self._lock:
            knowledge = self._knowledge.get(tool_id)
            if knowledge is not None:
                return list(knowledge.capabilities)
            metadata = self._metadata.get(tool_id)
            if metadata is not None and metadata.tags:
                return [tag for tag in metadata.tags if tag in self._capabilities]
            return []

    # -- compatibility -----------------------------------------------------

    def register_compatibility(self, compatibility: ToolCompatibility) -> None:
        """Register or replace a tool compatibility profile."""
        with self._lock:
            self._compatibility[compatibility.tool_id] = compatibility

    def get_compatibility(self, tool_id: str) -> ToolCompatibility | None:
        """Return the compatibility profile for ``tool_id`` or ``None``."""
        with self._lock:
            return self._compatibility.get(tool_id)

    # -- runtime state -----------------------------------------------------

    def set_state(self, state: ToolRuntimeState) -> None:
        """Set the runtime state for a tool."""
        with self._lock:
            self._state[state.tool_id] = state

    def get_state(self, tool_id: str) -> ToolRuntimeState | None:
        """Return the runtime state for ``tool_id`` or ``None``."""
        with self._lock:
            return self._state.get(tool_id)

    # -- health & performance ----------------------------------------------

    def set_health(self, stats: ToolHealthStats) -> None:
        """Store health stats for a tool."""
        with self._lock:
            self._health[stats.tool_id] = stats

    def get_health(self, tool_id: str) -> ToolHealthStats | None:
        """Return health stats for ``tool_id`` or ``None``."""
        with self._lock:
            return self._health.get(tool_id)

    def set_performance(self, stats: ToolPerformanceStats) -> None:
        """Store performance stats for a tool."""
        with self._lock:
            self._performance[stats.tool_id] = stats

    def get_performance(self, tool_id: str) -> ToolPerformanceStats | None:
        """Return performance stats for ``tool_id`` or ``None``."""
        with self._lock:
            return self._performance.get(tool_id)

    # -- Sprint 023: evidence & proof mappings -----------------------------

    def register_evidence_mapping(self, mapping: ToolEvidenceMapping) -> None:
        """Register an evidence mapping for a tool (append or replace)."""
        with self._lock:
            mappings = self._evidence_mappings.setdefault(mapping.tool_id, [])
            for index, existing in enumerate(mappings):
                if (
                    existing.observation_kind == mapping.observation_kind
                    and existing.evidence_type == mapping.evidence_type
                ):
                    mappings[index] = mapping
                    return
            mappings.append(mapping)

    def evidence_mappings_for(self, tool_id: str) -> tuple[ToolEvidenceMapping, ...]:
        """Return evidence mappings registered for ``tool_id``."""
        with self._lock:
            return tuple(self._evidence_mappings.get(tool_id, ()))

    def list_evidence_mappings(self) -> list[ToolEvidenceMapping]:
        """Return every registered evidence mapping."""
        with self._lock:
            return [
                mapping
                for mappings in self._evidence_mappings.values()
                for mapping in mappings
            ]

    def register_proof_capability(self, capability: ToolProofCapability) -> None:
        """Register a proof capability for a tool (append or replace)."""
        with self._lock:
            capabilities = self._proof_capabilities.setdefault(capability.tool_id, [])
            for index, existing in enumerate(capabilities):
                if (
                    existing.vulnerability_class == capability.vulnerability_class
                    and existing.proof_strategy_id == capability.proof_strategy_id
                ):
                    capabilities[index] = capability
                    return
            capabilities.append(capability)

    def proof_capabilities_for(self, tool_id: str) -> tuple[ToolProofCapability, ...]:
        """Return proof capabilities registered for ``tool_id``."""
        with self._lock:
            return tuple(self._proof_capabilities.get(tool_id, ()))

    def list_proof_capabilities(self) -> list[ToolProofCapability]:
        """Return every registered proof capability."""
        with self._lock:
            return [
                capability
                for capabilities in self._proof_capabilities.values()
                for capability in capabilities
            ]

    def register_confidence_ceiling(self, ceiling: ToolConfidenceCeiling) -> None:
        """Register or replace a tool's confidence contribution ceiling."""
        with self._lock:
            self._confidence_ceilings[ceiling.tool_id] = ceiling

    def get_confidence_ceiling(self, tool_id: str) -> ToolConfidenceCeiling | None:
        """Return the confidence ceiling for ``tool_id`` or ``None``."""
        with self._lock:
            return self._confidence_ceilings.get(tool_id)

    # -- Sprint 023: reliability & availability ----------------------------

    def set_reliability(self, stats: ToolReliabilityStats) -> None:
        """Store reliability stats for a tool."""
        with self._lock:
            self._reliability[stats.tool_id] = stats

    def get_reliability(self, tool_id: str) -> ToolReliabilityStats | None:
        """Return reliability stats for ``tool_id`` or ``None``."""
        with self._lock:
            return self._reliability.get(tool_id)

    def set_availability_report(self, report: ToolAvailabilityReport) -> None:
        """Store the latest availability report for a tool."""
        with self._lock:
            self._availability[report.tool_id] = report

    def get_availability_report(self, tool_id: str) -> ToolAvailabilityReport | None:
        """Return the availability report for ``tool_id`` or ``None``."""
        with self._lock:
            return self._availability.get(tool_id)

    def to_dict(self) -> dict[str, Any]:
        """Serialize the full registry to a JSON-safe mapping."""
        return {
            "metadata": [asdict(m) for m in self.list_metadata()],
            "knowledge": [asdict(k) for k in self._knowledge.values()],
            "capabilities": [asdict(c) for c in self.list_capabilities()],
            "state": [asdict(s) for s in self._state.values()],
            "health": [asdict(h) for h in self._health.values()],
            "performance": [asdict(p) for p in self._performance.values()],
            "evidence_mappings": [asdict(m) for m in self.list_evidence_mappings()],
            "proof_capabilities": [asdict(c) for c in self.list_proof_capabilities()],
            "confidence_ceilings": [
                asdict(c) for c in self._confidence_ceilings.values()
            ],
            "reliability": [asdict(r) for r in self._reliability.values()],
            "availability": [asdict(r) for r in self._availability.values()],
        }
