# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Consolidated machine-readable tool contract (Sprint 034.5).

The tool contract is the single, authoritative, machine-readable capability
definition every integrated tool must expose. It aggregates the master profile,
knowledge profile, evidence/proof wiring, failure knowledge and downstream
chaining facts into one JSON-serializable envelope covering the minimum
contract dimensions:

identity, version, category, capabilities, requirements, input schema,
argument builder, scope model, execution profile, timeout, resource limits,
output formats, exit-code mapping, parser, normalizer, artifact handling,
error mapping, retry policy, evidence mapping and downstream capabilities.

Pure data. No I/O, no execution. The builder lives in the mastery layer
(``hunterx.tools.mastery.contract``) because it needs the arsenal registry and
the relationship graph.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class ToolContract:
    """Consolidated machine-readable contract for one tool.

    Every field is JSON-serializable via :meth:`to_dict`. A contract is only
    complete when every minimum dimension is populated; the certification gate
    rejects tools with empty contract dimensions (documented, not silently
    accepted).
    """

    # -- identity -----------------------------------------------------------
    tool_id: str
    identity: dict[str, Any] = field(default_factory=dict)
    version: str = ""
    category: str = ""
    subcategory: str = ""
    capabilities: tuple[str, ...] = ()
    support_level: str = "knowledge-only"

    # -- usage contract -----------------------------------------------------
    requirements: dict[str, Any] = field(default_factory=dict)
    input_schema: dict[str, Any] = field(default_factory=dict)
    argument_builder: dict[str, Any] = field(default_factory=dict)
    scope_model: dict[str, Any] = field(default_factory=dict)

    # -- execution contract -------------------------------------------------
    execution_profile: dict[str, Any] = field(default_factory=dict)
    timeout: float = 0.0
    resource_limits: dict[str, Any] = field(default_factory=dict)
    output_formats: tuple[str, ...] = ()

    # -- interpretation contract ---------------------------------------------
    exit_code_mapping: tuple[str, ...] = ()
    parser: dict[str, Any] = field(default_factory=dict)
    normalizer: dict[str, Any] = field(default_factory=dict)
    artifact_handling: dict[str, Any] = field(default_factory=dict)
    error_mapping: dict[str, Any] = field(default_factory=dict)
    retry_policy: dict[str, Any] = field(default_factory=dict)

    # -- intelligence contract -----------------------------------------------
    evidence_mapping: tuple[dict[str, Any], ...] = ()
    downstream_capabilities: dict[str, Any] = field(default_factory=dict)
    false_positive_risks: tuple[str, ...] = ()
    false_negative_risks: tuple[str, ...] = ()

    # -- audit ----------------------------------------------------------------
    provenance: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize the contract to a JSON-safe mapping."""
        return {
            "tool_id": self.tool_id,
            "identity": dict(self.identity),
            "version": self.version,
            "category": self.category,
            "subcategory": self.subcategory,
            "capabilities": list(self.capabilities),
            "support_level": self.support_level,
            "requirements": dict(self.requirements),
            "input_schema": dict(self.input_schema),
            "argument_builder": dict(self.argument_builder),
            "scope_model": dict(self.scope_model),
            "execution_profile": dict(self.execution_profile),
            "timeout": self.timeout,
            "resource_limits": dict(self.resource_limits),
            "output_formats": list(self.output_formats),
            "exit_code_mapping": list(self.exit_code_mapping),
            "parser": dict(self.parser),
            "normalizer": dict(self.normalizer),
            "artifact_handling": dict(self.artifact_handling),
            "error_mapping": dict(self.error_mapping),
            "retry_policy": dict(self.retry_policy),
            "evidence_mapping": [dict(item) for item in self.evidence_mapping],
            "downstream_capabilities": dict(self.downstream_capabilities),
            "false_positive_risks": list(self.false_positive_risks),
            "false_negative_risks": list(self.false_negative_risks),
            "provenance": dict(self.provenance),
        }

    def missing_dimensions(self) -> tuple[str, ...]:
        """Return the contract dimensions that are not populated.

        Used by the certification gate to prove "every registered tool has a
        defined contract". Knowledge-only tools may legitimately have empty
        execution dimensions; those are classified, never silently accepted.
        """
        missing: list[str] = []
        if not self.identity:
            missing.append("identity")
        if not self.version:
            missing.append("version")
        if not self.category:
            missing.append("category")
        if not self.capabilities:
            missing.append("capabilities")
        if not self.input_schema:
            missing.append("input_schema")
        if not self.argument_builder:
            missing.append("argument_builder")
        if not self.scope_model:
            missing.append("scope_model")
        if not self.output_formats:
            missing.append("output_formats")
        if not self.parser:
            missing.append("parser")
        if not self.normalizer:
            missing.append("normalizer")
        if not self.error_mapping:
            missing.append("error_mapping")
        if not self.retry_policy:
            missing.append("retry_policy")
        if not self.evidence_mapping:
            missing.append("evidence_mapping")
        if not self.downstream_capabilities:
            missing.append("downstream_capabilities")
        if self.support_level in {"fully-supported", "execution-only", "partial-support"} and not self.timeout:
            missing.append("timeout")
        return tuple(missing)


__all__ = ["ToolContract"]
