# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tool contract builder (Sprint 034.5).

Synthesizes the consolidated :class:`~hunterx.domain.tool_contract.ToolContract`
for every registered arsenal tool from the authoritative master profile, the
relationship graph and the knowledge fixtures. The contract never claims more
than the profile supports: knowledge-only tools receive a complete contract
with ``execution_profile`` marked ``unavailable`` rather than fabricated
execution semantics.
"""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

from hunterx.domain.tool_contract import ToolContract
from hunterx.domain.tool_mastery import ToolMasterProfile, ToolSupportLevel
from hunterx.tools.mastery.knowledge_fixtures import _evidence_mappings
from hunterx.tools.mastery.relationships import ToolRelationshipGraph

#: Support levels that imply executable semantics.
_EXECUTABLE_LEVELS = {
    ToolSupportLevel.FULLY_SUPPORTED,
    ToolSupportLevel.EXECUTION_ONLY,
    ToolSupportLevel.PARTIAL_SUPPORT,
    ToolSupportLevel.PARSER_ONLY,
}


def build_contract(
    profile: ToolMasterProfile,
    relationships: ToolRelationshipGraph,
) -> ToolContract:
    """Build the consolidated contract for ``profile``."""
    tool_id = profile.tool_id
    metadata = profile.metadata
    knowledge = profile.knowledge
    resources = knowledge.resource_requirements
    invocation = knowledge.invocation_contract
    input_schema = knowledge.input_schema
    support = profile.support_level

    timeout = 0.0
    for candidate in (resources, input_schema, invocation):
        value = getattr(candidate, "timeout", 0.0) or 0.0
        timeout = max(timeout, value)

    declared_timeout = timeout
    if timeout == 0.0 and support in _EXECUTABLE_LEVELS:
        # Executable tools without a declared timeout run under the platform
        # default execution budget. Transparent: declared vs effective is kept.
        timeout = 300.0

    return ToolContract(
        tool_id=tool_id,
        identity={
            "tool_id": tool_id,
            "display_name": metadata.display_name,
            "vendor": metadata.vendor,
            "project_url": metadata.project_url,
            "license": metadata.license,
            "description": metadata.description,
            "language": metadata.language,
            "tags": list(metadata.tags),
            "platforms": list(metadata.platforms),
            "execution_type": _enum_value(metadata.execution_type),
            "package_manager": metadata.package_manager,
            "maintenance_status": _enum_value(metadata.maintenance_status),
            "project_activity": _enum_value(metadata.project_activity),
            "community_score": metadata.community_score,
        },
        version=metadata.version or "unknown",
        category=metadata.category,
        subcategory=metadata.subcategory,
        capabilities=tuple(profile.capability_ids or knowledge.capabilities),
        support_level=support.value,
        requirements=_requirements(profile),
        input_schema=_input_schema(profile),
        argument_builder=_argument_builder(profile),
        scope_model=_scope_model(profile),
        execution_profile=_execution_profile(profile),
        timeout=timeout,
        resource_limits={**_resource_limits(profile), "timeout_declared": declared_timeout > 0.0},
        output_formats=tuple(dict.fromkeys([*profile.output_formats, *profile.structured_output_formats])),        exit_code_mapping=tuple(profile.exit_codes or _default_exit_codes()),
        parser=_parser(profile),
        normalizer=_normalizer(profile),
        artifact_handling=_artifact_handling(profile),
        error_mapping=_error_mapping(profile),
        retry_policy=_retry_policy(profile, support),
        evidence_mapping=tuple(
            {key: value for key, value in mapping.items() if value is not None}
            for mapping in _evidence_mappings(profile)
        ),
        downstream_capabilities=_downstream(profile, relationships),
        false_positive_risks=tuple(profile.false_positive_risks or knowledge.known_false_positives),
        false_negative_risks=tuple(profile.false_negative_risks or knowledge.known_false_negatives),
        provenance=dict(profile.provenance),
    )


def _requirements(profile: ToolMasterProfile) -> dict[str, Any]:
    knowledge = profile.knowledge
    metadata = profile.metadata
    return {
        "authentication": knowledge.authentication_requirements,
        "privileges": knowledge.privileges_required,
        "installation": list(knowledge.installation_requirements),
        "dependencies": [asdict(dep) for dep in knowledge.dependencies],
        "version_constraints": list(profile.version_constraints),
        "known_version_issues": list(profile.known_version_issues),
        "network": profile.scope_requirements or "outbound to target within scope",
        "os": list(metadata.platforms),
        "compatibility": asdict(profile.compatibility) if profile.compatibility is not None else {},
    }


def _input_schema(profile: ToolMasterProfile) -> dict[str, Any]:
    knowledge = profile.knowledge
    contract = knowledge.inputs
    schema = knowledge.input_schema
    fields = tuple(asdict(field) for field in schema.fields) if schema is not None else ()
    return {
        "accepts": list(contract.accepts or profile.supported_targets),
        "required": list(contract.required or schema.required if schema is not None else contract.required),
        "optional": list(contract.optional or schema.optional if schema is not None else contract.optional),
        "transforms": list(contract.transforms),
        "max_targets_per_invocation": contract.max_targets_per_invocation,
        "target_type": schema.target_type if schema is not None else "",
        "fields": fields,
        "protocols": list(profile.supported_protocols),
    }


def _argument_builder(profile: ToolMasterProfile) -> dict[str, Any]:
    knowledge = profile.knowledge
    return {
        "cli_binary": knowledge.cli_binary or profile.tool_id,
        "cli_structure": knowledge.cli_structure or "flags",
        "arguments": [asdict(argument) for argument in knowledge.arguments],
        "modes": [asdict(mode) for mode in knowledge.modes],
        "safe_mode": knowledge.safe_mode,
        "aggressive_mode": knowledge.aggressive_mode,
        "global_options": list(profile.global_options),
        "command_tree": list(profile.command_tree),
        "input_formats": list(profile.input_formats),
    }


def _scope_model(profile: ToolMasterProfile) -> dict[str, Any]:
    scope = profile.knowledge.scope_profile
    return {
        "scope_requirements": profile.scope_requirements,
        "follows_redirects": scope.follows_redirects if scope is not None else False,
        "redirect_scope": scope.redirect_scope if scope is not None else "inherit",
        "expands_scope": scope.expands_scope if scope is not None else False,
        "network_boundary": scope.network_boundary if scope is not None else "inherit",
        "safety_class": profile.safety_class,
        "destructive": profile.destructive,
        "requires_authorization": profile.knowledge.safety_profile.requires_authorization
        if profile.knowledge.safety_profile is not None
        else False,
    }


def _execution_profile(profile: ToolMasterProfile) -> dict[str, Any]:
    metadata = profile.metadata
    executable = profile.support_level in _EXECUTABLE_LEVELS
    return {
        "execution_type": _enum_value(metadata.execution_type),
        "binary_available": metadata.binary_available,
        "container_available": metadata.container_available,
        "adapter_id": profile.adapter_id or "none",
        "executable": executable,
        "availability": "executable" if executable else "knowledge-only",
        "concurrency_class": profile.knowledge.resource_requirements.concurrency_class
        if profile.knowledge.resource_requirements is not None
        else "light",
    }


def _resource_limits(profile: ToolMasterProfile) -> dict[str, Any]:
    resources = profile.knowledge.resource_requirements
    rate = resources.rate_limit if resources is not None else None
    return {
        "cpu_estimate": resources.cpu_estimate if resources is not None else 0.0,
        "memory_estimate_mb": resources.memory_estimate_mb if resources is not None else 0.0,
        "network_estimate": resources.network_estimate if resources is not None else "low",
        "disk_estimate_mb": resources.disk_estimate_mb if resources is not None else 0.0,
        "rate_limits": asdict(rate) if rate is not None else {},
        "declared_rate_limits": profile.rate_limits,
    }


def _parser(profile: ToolMasterProfile) -> dict[str, Any]:
    knowledge = profile.knowledge
    return {
        "parser_id": profile.parser_id or knowledge.parser_id or knowledge.outputs.parser,
        "output_mappings": {},
        "input_format": profile.structured_output_formats[0] if profile.structured_output_formats else "text",
        "backward_compatible": True,
    }


def _normalizer(profile: ToolMasterProfile) -> dict[str, Any]:
    knowledge = profile.knowledge
    return {
        "normalizer_id": profile.normalizer_id or knowledge.normalizer_id or knowledge.outputs.normalizer,
        "schema": "canonical-observation",
        "backward_compatible": True,
    }


def _artifact_handling(profile: ToolMasterProfile) -> dict[str, Any]:
    knowledge = profile.knowledge
    invocation = knowledge.invocation_contract
    return {
        "evidence_capture": list(knowledge.outputs.evidence_capture),
        "output_files": list(invocation.output_files) if invocation is not None else [],
        "input_files": list(invocation.input_files) if invocation is not None else [],
        "output_formats": list(knowledge.outputs.formats),
        "raw_artifact_preserved": True,
    }


def _error_mapping(profile: ToolMasterProfile) -> dict[str, Any]:
    return {
        "error_indicators": list(profile.error_indicators),
        "warning_indicators": list(profile.warning_indicators),
        "partial_result_indicators": list(profile.partial_result_indicators),
        "classification": {
            "errors": "failure",
            "warnings": "degraded",
            "partial": "partial-result",
        },
    }


def _retry_policy(profile: ToolMasterProfile, support: ToolSupportLevel) -> dict[str, Any]:
    executable = support in _EXECUTABLE_LEVELS
    return {
        "max_attempts": 2 if executable else 1,
        "retryable_kinds": ["retryable", "timeout", "resource-exhausted"],
        "strategy": "exponential-backoff",
        "base_delay_s": 1.0,
        "max_delay_s": 60.0,
        "fallback": list(profile.alternative_tools or profile.knowledge.alternative_tools)[:3],
    }


def _downstream(profile: ToolMasterProfile, relationships: ToolRelationshipGraph) -> dict[str, Any]:
    tool_id = profile.tool_id
    return {
        "successors": relationships.successors(tool_id),
        "next_tools": relationships.next_tools(tool_id),
        "validates": relationships.validates(tool_id),
        "predecessors": relationships.predecessors(tool_id),
        "alternatives": relationships.alternatives(tool_id),
        "recommended_successors": list(profile.recommended_successors),
        "complementary": list(profile.complementary_tools),
    }


def _default_exit_codes() -> tuple[str, ...]:
    return (
        "0: completed",
        "1: completed with warnings or no findings",
        "2: error",
    )


def _enum_value(value: Any) -> str:
    """Return the enum value, tolerating strings stored by the arsenal data."""
    if hasattr(value, "value"):
        return str(value.value)
    return str(value)


__all__ = ["build_contract"]
