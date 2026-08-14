# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tool integration audit.

Machine-checkable integration maturity for every claimed tool integration.

A tool is NEVER considered fully integrated merely because its name appears in
a registry. The audit measures, per tool, the actual presence of machine-
actionable knowledge for every required dimension:

    Identity, Capability, Discovery, Installation, Verification, Version,
    Commands, Arguments, Invocation, Output, Parser, Platform, Safety

and derives a maturity level:

    KNOWN → DISCOVERABLE → INSTALLABLE → VERIFIED → INVOKABLE → PARSABLE →
    FULLY_INTEGRATED

``Tool Knowledge`` (what the tool is and how to operate it) is kept separate
from ``Tool Runtime State`` (whether the exact tool is installed and healthy
right now). A tool is an executable capability only when both are valid.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from hunterx.tools.intelligence.api import ToolIntelligenceAPI
from hunterx.tools.readiness.definitions import ToolDefinitionBuilder
from hunterx.tools.readiness.models import ToolDefinition


class IntegrationLevel(Enum):
    """Integration maturity ladder for a tool integration."""

    UNKNOWN = "unknown"
    KNOWN = "known"
    DISCOVERABLE = "discoverable"
    INSTALLABLE = "installable"
    VERIFIED = "verified"
    INVOKABLE = "invokable"
    PARSABLE = "parsable"
    FULLY_INTEGRATED = "fully_integrated"


#: Progressive maturity ladder (order matters).
_LEVEL_ORDER: tuple[IntegrationLevel, ...] = (
    IntegrationLevel.KNOWN,
    IntegrationLevel.DISCOVERABLE,
    IntegrationLevel.INSTALLABLE,
    IntegrationLevel.VERIFIED,
    IntegrationLevel.INVOKABLE,
    IntegrationLevel.PARSABLE,
    IntegrationLevel.FULLY_INTEGRATED,
)


@dataclass(slots=True)
class ToolAudit:
    """Integration audit for one tool.

    Attributes:
        tool_id: the audited tool.
        dimensions: dimension → ``True`` when the knowledge is present.
        missing: dimensions absent from the knowledge.
        level: derived maturity level.
        runtime: ``True`` when an execution adapter is registered (runtime
            state, independent of knowledge).
        available: ``True`` when the tool was discovered as available in the
            current environment (runtime state).
        reasons: human reasons for the classification.

    """

    tool_id: str
    dimensions: dict[str, bool] = field(default_factory=dict)
    missing: tuple[str, ...] = ()
    level: IntegrationLevel = IntegrationLevel.UNKNOWN
    runtime: bool = False
    available: bool = False
    reasons: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe mapping of the audit."""
        return {
            "tool_id": self.tool_id,
            "level": self.level.value,
            "dimensions": dict(self.dimensions),
            "missing": list(self.missing),
            "runtime": self.runtime,
            "available": self.available,
            "reasons": list(self.reasons),
        }


@dataclass(slots=True)
class IntegrationAuditReport:
    """Full integration audit across the claimed toolchain.

    Attributes:
        audits: per-tool audits.
        summary: counts per maturity level.

    """

    audits: list[ToolAudit] = field(default_factory=list)
    summary: dict[str, int] = field(default_factory=dict)

    def by_level(self) -> dict[IntegrationLevel, list[ToolAudit]]:
        """Return audits grouped by maturity level."""
        grouped: dict[IntegrationLevel, list[ToolAudit]] = {}
        for audit in self.audits:
            grouped.setdefault(audit.level, []).append(audit)
        return grouped

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe mapping of the report."""
        return {
            "audits": [audit.to_dict() for audit in self.audits],
            "summary": dict(self.summary),
        }


class ToolIntegrationAuditor:
    """Compute integration maturity for the claimed external toolchain.

    Args:
        tip: the Tool Intelligence API (canonical knowledge).
        definitions: readiness definition builder (discovery/installation facts).
        engine: optional Tool Integration SDK engine (runtime adapter state).
        availability: optional mapping of tool_id → readiness available state.

    """

    def __init__(
        self,
        tip: ToolIntelligenceAPI,
        definitions: ToolDefinitionBuilder | None = None,
        engine: Any | None = None,
        availability: dict[str, bool] | None = None,
    ) -> None:
        self._tip = tip
        # The audit measures DECLARED knowledge, so definitions are always
        # built WITHOUT a platform: installation/discovery facts are assessed
        # as declared in the manifest, not filtered by the current environment.
        self._definitions = definitions or ToolDefinitionBuilder(tip)
        self._definitions_plain = ToolDefinitionBuilder(tip)
        self._engine = engine
        self._availability = availability or {}

    def audit(self, tool_ids: list[str] | None = None) -> IntegrationAuditReport:
        """Audit every claimed tool (or the requested subset)."""
        targets = tool_ids or self._claimed_tool_ids()
        audits = [self._audit_tool(tool_id) for tool_id in targets]
        summary = {level.value: 0 for level in _LEVEL_ORDER}
        summary[IntegrationLevel.UNKNOWN.value] = 0
        for audit in audits:
            summary[audit.level.value] = summary.get(audit.level.value, 0) + 1
        return IntegrationAuditReport(audits=audits, summary=summary)

    def audit_tool(self, tool_id: str) -> ToolAudit:
        """Audit a single tool."""
        return self._audit_tool(tool_id)

    # -- internals ---------------------------------------------------------

    def _claimed_tool_ids(self) -> list[str]:
        """Return the union of tools HunterX claims to integrate."""
        return [metadata.tool_id for metadata in self._tip.list_tools()]

    def _audit_tool(self, tool_id: str) -> ToolAudit:
        metadata = self._tip.get_tool(tool_id)
        knowledge = self._tip.get_knowledge(tool_id)
        definition = self._definitions_plain.build(tool_id)
        if definition is None:
            definition = _fallback_definition(tool_id)
        engine = self._engine
        inprocess = definition.kind == "inprocess"
        runtime = False
        if engine is not None:
            try:
                runtime = engine.adapter_for(tool_id) is not None
            except Exception:  # noqa: BLE001 - runtime probe is best-effort
                runtime = False

        # In-process adapters ARE the invocation: there is no external CLI, so
        # the command/argument/output/parser dimensions are satisfied by the
        # registered adapter itself.
        has_commands = knowledge is not None and bool(knowledge.cli_binary)
        has_arguments = knowledge is not None and bool(knowledge.arguments)
        has_invocation = knowledge is not None and bool(knowledge.inputs.accepts)
        has_output = knowledge is not None and bool(knowledge.outputs.formats)
        has_parser = knowledge is not None and bool(knowledge.outputs.parser)
        if inprocess and runtime:
            has_commands = has_arguments = has_invocation = has_output = has_parser = True

        dimensions: dict[str, bool] = {
            "identity": metadata is not None,
            "capability": bool(knowledge is not None and knowledge.capabilities)
            or bool(definition.capabilities),
            "discovery": inprocess or bool(definition.executable),
            "installation": inprocess or bool(definition.installation_methods),
            "verification": inprocess
            or (bool(definition.version_command) and bool(definition.version_regex)),
            "version": (metadata is not None and bool(metadata.version)) or bool(definition.min_version),
            "commands": has_commands
            and (has_arguments or (knowledge is not None and knowledge.invocation_contract is not None)),
            "arguments": has_arguments,
            "invocation": has_invocation and (has_commands or inprocess),
            "output": has_output,
            "parser": has_parser,
            "platform": metadata is not None and bool(metadata.platforms),
            "safety": _has_safety(knowledge) or (inprocess and runtime),
        }
        missing = tuple(dimension for dimension, present in dimensions.items() if not present)
        level = _derive_level(dimensions)

        reasons: list[str] = []
        if missing:
            reasons.append(f"missing knowledge: {', '.join(missing)}")
        if not runtime:
            reasons.append("no execution adapter registered")

        return ToolAudit(
            tool_id=tool_id,
            dimensions=dimensions,
            missing=missing,
            level=level,
            runtime=runtime,
            available=bool(self._availability.get(tool_id, False)),
            reasons=tuple(reasons),
        )


def _derive_level(dimensions: dict[str, bool]) -> IntegrationLevel:
    """Derive the maturity level from the dimension map."""
    base = dimensions.get("identity", False) and dimensions.get("capability", False)
    if not base:
        return IntegrationLevel.UNKNOWN
    level = IntegrationLevel.KNOWN
    if dimensions.get("discovery", False):
        level = IntegrationLevel.DISCOVERABLE
    if level is IntegrationLevel.DISCOVERABLE and dimensions.get("installation", False):
        level = IntegrationLevel.INSTALLABLE
    if (
        level is IntegrationLevel.INSTALLABLE
        and dimensions.get("verification", False)
        and dimensions.get("version", False)
    ):
        level = IntegrationLevel.VERIFIED
    if (
        level is IntegrationLevel.VERIFIED
        and dimensions.get("commands", False)
        and dimensions.get("arguments", False)
        and dimensions.get("invocation", False)
    ):
        level = IntegrationLevel.INVOKABLE
    if (
        level is IntegrationLevel.INVOKABLE
        and dimensions.get("output", False)
        and dimensions.get("parser", False)
    ):
        level = IntegrationLevel.PARSABLE
    if (
        level is IntegrationLevel.PARSABLE
        and dimensions.get("platform", False)
        and dimensions.get("safety", False)
    ):
        level = IntegrationLevel.FULLY_INTEGRATED
    return level


def _has_safety(knowledge: Any) -> bool:
    """Return ``True`` when safety constraints are machine-actionable."""
    if knowledge is None:
        return False
    if knowledge.safety_profile is not None:
        return True
    if knowledge.scope_profile is not None:
        return True
    return bool(getattr(knowledge, "safe_mode", "")) or bool(getattr(knowledge, "aggressive_mode", ""))


def _fallback_definition(tool_id: str) -> ToolDefinition:
    """Return a minimal definition for tools unknown to the readiness manifest."""
    return ToolDefinition(tool_id=tool_id, name=tool_id)


__all__ = ["IntegrationAuditReport", "IntegrationLevel", "ToolAudit", "ToolIntegrationAuditor"]
