# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tool documentation generator.

Generates Markdown documentation from tool knowledge and metadata. Used to
produce per-tool reference pages without hand-writing docs, mirroring the
knowledge file contract (``docs/bible/07``).
"""

from __future__ import annotations

from hunterx.domain.tool_intelligence import ToolKnowledge, ToolMetadata
from hunterx.tools.intelligence.registry import ToolIntelligenceRegistry


class ToolDocumentationGenerator:
    """Render tool documentation from structured intelligence records."""

    def __init__(self, registry: ToolIntelligenceRegistry) -> None:
        self._registry = registry

    def generate(self, tool_id: str) -> str:
        """Generate a Markdown reference page for ``tool_id``.

        Returns an empty string when the tool is not registered.
        """
        metadata = self._registry.get_metadata(tool_id)
        if metadata is None:
            return ""
        knowledge = self._registry.get_knowledge(tool_id)
        lines: list[str] = [f"# {metadata.display_name or metadata.tool_id}", ""]
        if metadata.description:
            lines.append(metadata.description)
            lines.append("")
        lines.extend(self._render_metadata(metadata))
        if knowledge is not None:
            lines.extend(self._render_knowledge(knowledge))
        lines.extend(self._render_capabilities(tool_id))
        return "\n".join(lines).rstrip() + "\n"

    def generate_all(self) -> dict[str, str]:
        """Return ``{tool_id: markdown}`` for every registered tool."""
        return {
            metadata.tool_id: self.generate(metadata.tool_id)
            for metadata in self._registry.list_metadata()
        }

    def _render_metadata(self, metadata: ToolMetadata) -> list[str]:
        lines = ["## Metadata", "", "| Field | Value |", "|-------|-------|"]
        lines.append(f"| id | {metadata.tool_id} |")
        lines.append(f"| vendor | {metadata.vendor or '-'} |")
        lines.append(f"| version | {metadata.version or '-'} |")
        lines.append(f"| license | {metadata.license or '-'} |")
        lines.append(f"| category | {metadata.category or '-'} |")
        lines.append(f"| subcategory | {metadata.subcategory or '-'} |")
        lines.append(f"| platforms | {', '.join(metadata.platforms) or '-'} |")
        lines.append(f"| architectures | {', '.join(metadata.architectures) or '-'} |")
        lines.append(f"| execution type | {metadata.execution_type.value} |")
        lines.append(f"| maintenance | {metadata.maintenance_status.value} |")
        lines.append(f"| community score | {metadata.community_score} |")
        lines.append("")
        return lines

    def _render_knowledge(self, knowledge: ToolKnowledge) -> list[str]:
        lines = ["## Knowledge", ""]
        if knowledge.purpose:
            lines.append(f"**Purpose:** {knowledge.purpose}")
            lines.append("")
        if knowledge.supported_assessments:
            lines.append(f"**Assessments:** {', '.join(knowledge.supported_assessments)}")
            lines.append("")
        if knowledge.supported_mission_profiles:
            lines.append(
                f"**Mission profiles:** {', '.join(knowledge.supported_mission_profiles)}"
            )
            lines.append("")
        if knowledge.inputs.accepts:
            lines.append(f"**Inputs:** {', '.join(knowledge.inputs.accepts)}")
            lines.append("")
        if knowledge.outputs.formats:
            lines.append(f"**Output formats:** {', '.join(knowledge.outputs.formats)}")
            lines.append("")
        if knowledge.cli_binary:
            lines.append(f"**CLI binary:** `{knowledge.cli_binary}`")
            lines.append("")
        if knowledge.modes:
            lines.append("**Execution modes:**")
            lines.append("")
            for mode in knowledge.modes:
                posture = "safe" if mode.safe else "aggressive"
                lines.append(f"- `{mode.id}` ({posture}) — {mode.description}")
            lines.append("")
        if knowledge.installation_requirements:
            lines.append("**Installation requirements:**")
            lines.append("")
            for requirement in knowledge.installation_requirements:
                lines.append(f"- {requirement}")
            lines.append("")
        if knowledge.known_issues:
            lines.append("**Known issues:**")
            lines.append("")
            for issue in knowledge.known_issues:
                lines.append(f"- {issue}")
            lines.append("")
        if knowledge.recommended_usage:
            lines.append("**Recommended usage:**")
            lines.append("")
            for usage in knowledge.recommended_usage:
                lines.append(f"- {usage}")
            lines.append("")
        if knowledge.references:
            lines.append("**References:**")
            lines.append("")
            for reference in knowledge.references:
                lines.append(f"- {reference}")
            lines.append("")
        return lines

    def _render_capabilities(self, tool_id: str) -> list[str]:
        capabilities = self._registry.capabilities_for(tool_id)
        if not capabilities:
            return []
        lines = ["## Capabilities", ""]
        for capability_id in capabilities:
            definition = self._registry.get_capability(capability_id)
            if definition is None:
                lines.append(f"- `{capability_id}`")
            else:
                lines.append(f"- `{capability_id}` — {definition.description}")
        lines.append("")
        return lines
