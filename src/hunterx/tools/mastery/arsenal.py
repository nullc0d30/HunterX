# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Universal Security Arsenal — machine-readable arsenal manifest.

Serializes the complete arsenal (tools, capabilities, versions, adapters,
parsers, normalizers, evidence mappings, proof mappings, datasets,
relationships, playbooks, mission modes, security profiles) into the
``capabilities/universal-security-arsenal.json`` manifest and reads it back.
"""

from __future__ import annotations

import json
from typing import Any

from hunterx.tools.mastery.datasets import ToolDatasetRegistry
from hunterx.tools.mastery.playbooks import ToolPlaybookEngine
from hunterx.tools.mastery.registry import ToolMasteryRegistry
from hunterx.tools.mastery.relationships import ToolRelationshipGraph


class UniversalSecurityArsenal:
    """Build and consume the universal security arsenal manifest."""

    #: Manifest schema version.
    MANIFEST_VERSION = "1.0.0"

    def __init__(
        self,
        registry: ToolMasteryRegistry,
        relationships: ToolRelationshipGraph | None = None,
        playbooks: ToolPlaybookEngine | None = None,
        datasets: ToolDatasetRegistry | None = None,
    ) -> None:
        self.registry = registry
        self.relationships = relationships or ToolRelationshipGraph()
        self.playbooks = playbooks or ToolPlaybookEngine()
        self.datasets = datasets or ToolDatasetRegistry()

    # -- export -----------------------------------------------------------

    def to_manifest(self) -> dict[str, Any]:
        """Build the complete arsenal manifest as a plain dictionary."""
        profiles = self.registry.list()
        tools: dict[str, dict[str, Any]] = {}
        capability_map: dict[str, list[str]] = {}
        for profile in profiles:
            entry = {
                "display_name": profile.metadata.display_name,
                "vendor": profile.metadata.vendor,
                "project_url": profile.metadata.project_url,
                "license": profile.metadata.license,
                "version": profile.metadata.version,
                "support_level": profile.support_level.value,
                "capabilities": list(profile.capability_ids or profile.knowledge.capabilities),
                "supported_targets": list(profile.supported_targets),
                "supported_protocols": list(profile.supported_protocols),
                "output_formats": list(profile.output_formats),
                "structured_output_formats": list(profile.structured_output_formats),
                "parser_id": profile.parser_id,
                "normalizer_id": profile.normalizer_id,
                "adapter_id": profile.adapter_id,
                "version_constraints": list(profile.version_constraints),
                "alternative_tools": list(profile.alternative_tools),
                "complementary_tools": list(profile.complementary_tools),
                "recommended_predecessors": list(profile.recommended_predecessors),
                "recommended_successors": list(profile.recommended_successors),
                "safety_class": profile.safety_class,
                "destructive": profile.destructive,
                "provenance": profile.provenance,
            }
            tools[profile.tool_id] = entry
            for capability in entry["capabilities"]:
                capability_map.setdefault(capability, []).append(profile.tool_id)

        return {
            "manifest_version": self.MANIFEST_VERSION,
            "schema": "universal-security-arsenal",
            "tools": tools,
            "capabilities": {
                capability: {"tools": sorted(tool_ids)}
                for capability, tool_ids in sorted(capability_map.items())
            },
            "relationships": [_relationship_to_dict(e) for e in self.relationships.edges],
            "playbooks": [_playbook_to_dict(p) for p in self.playbooks.list()],
            "datasets": [_dataset_to_dict(d) for d in self.datasets.list()],
        }

    def export(self, path: str) -> None:
        """Write the arsenal manifest to ``path`` as formatted JSON."""
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(self.to_manifest(), handle, indent=2, ensure_ascii=False)

    # -- import -----------------------------------------------------------

    @classmethod
    def load_manifest(cls, path: str) -> dict[str, Any]:
        """Load a manifest JSON file from disk."""
        with open(path, encoding="utf-8") as handle:
            return json.load(handle)


def _relationship_to_dict(edge: Any) -> dict[str, Any]:
    return {
        "source": edge.source,
        "target": edge.target,
        "kind": edge.kind.value,
        "capability": edge.capability,
        "rationale": edge.rationale,
        "strength": edge.strength,
    }


def _playbook_to_dict(playbook: Any) -> dict[str, Any]:
    return {
        "playbook_id": playbook.playbook_id,
        "name": playbook.name,
        "category": playbook.category.value,
        "objective": playbook.objective,
        "mission_types": list(playbook.mission_types),
        "steps": [
            {
                "step_id": step.step_id,
                "objective": step.objective,
                "required_capabilities": list(step.required_capabilities),
                "preferred_tools": list(step.preferred_tools),
                "fallback_tools": list(step.fallback_tools),
                "preconditions": list(step.preconditions),
                "stop_conditions": list(step.stop_conditions),
                "evidence_requirements": list(step.evidence_requirements),
                "proof_requirements": list(step.proof_requirements),
                "safety_class": step.safety_class,
            }
            for step in playbook.steps
        ],
        "stop_conditions": list(playbook.stop_conditions),
        "version": playbook.version,
        "description": playbook.description,
    }


def _dataset_to_dict(dataset: Any) -> dict[str, Any]:
    return {
        "dataset_id": dataset.dataset_id,
        "name": dataset.name,
        "version": dataset.version,
        "source": dataset.source,
        "license": dataset.license,
        "category": dataset.category,
        "purpose": dataset.purpose,
        "encoding": dataset.encoding,
        "size_bytes": dataset.size_bytes,
        "checksum": dataset.checksum,
        "update_timestamp": dataset.update_timestamp,
        "compatibility": list(dataset.compatibility),
        "safety_classification": dataset.safety_classification,
    }
