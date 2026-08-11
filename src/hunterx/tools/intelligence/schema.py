# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tool metadata schema.

The permanent schema for storing and exchanging tool metadata and knowledge.
Provides bidirectional mapping between the domain dataclasses and plain
JSON/YAML-safe mappings, plus a loader for Tool Knowledge Files
(``docs/bible/07 - Tool Knowledge Base Specification.md``).
"""

from __future__ import annotations

from typing import Any

import yaml

from hunterx.domain.exceptions import ConfigurationError
from hunterx.domain.tool_intelligence import (
    EvidenceStrength,
    MaintenanceStatus,
    ProjectActivity,
    ToolArgument,
    ToolCompatibility,
    ToolConfidenceCeiling,
    ToolDependency,
    ToolEvidenceMapping,
    ToolExecutionMode,
    ToolExecutionType,
    ToolInputContract,
    ToolInputField,
    ToolInputSchema,
    ToolInvocationContract,
    ToolKnowledge,
    ToolMetadata,
    ToolOutputContract,
    ToolOutputField,
    ToolOutputSchema,
    ToolProofCapability,
    ToolRateLimitProfile,
    ToolResourceRequirements,
    ToolSafetyClass,
    ToolSafetyProfile,
    ToolScopeProfile,
)


def metadata_to_dict(metadata: ToolMetadata) -> dict[str, Any]:
    """Serialize :class:`ToolMetadata` to a JSON-safe mapping."""
    return {
        "tool_id": metadata.tool_id,
        "display_name": metadata.display_name,
        "vendor": metadata.vendor,
        "project_url": metadata.project_url,
        "license": metadata.license,
        "category": metadata.category,
        "subcategory": metadata.subcategory,
        "version": metadata.version,
        "platforms": list(metadata.platforms),
        "architectures": list(metadata.architectures),
        "language": metadata.language,
        "execution_type": metadata.execution_type.value,
        "package_manager": metadata.package_manager,
        "container_available": metadata.container_available,
        "binary_available": metadata.binary_available,
        "maintenance_status": metadata.maintenance_status.value,
        "project_activity": metadata.project_activity.value,
        "community_score": metadata.community_score,
        "description": metadata.description,
        "tags": list(metadata.tags),
    }


def metadata_from_dict(raw: dict[str, Any]) -> ToolMetadata:
    """Build :class:`ToolMetadata` from a mapping (raises on missing id)."""
    tool_id = str(raw.get("tool_id", ""))
    if not tool_id:
        raise ConfigurationError("Tool metadata requires a 'tool_id'.")
    return ToolMetadata(
        tool_id=tool_id,
        display_name=str(raw.get("display_name", "")),
        vendor=str(raw.get("vendor", "")),
        project_url=str(raw.get("project_url", "")),
        license=str(raw.get("license", "")),
        category=str(raw.get("category", "")),
        subcategory=str(raw.get("subcategory", "")),
        version=str(raw.get("version", "")),
        platforms=tuple(str(p) for p in raw.get("platforms", ())),
        architectures=tuple(str(a) for a in raw.get("architectures", ())),
        language=str(raw.get("language", "")),
        execution_type=_execution_type(raw.get("execution_type", "binary")),
        package_manager=str(raw.get("package_manager", "")),
        container_available=bool(raw.get("container_available", False)),
        binary_available=bool(raw.get("binary_available", False)),
        maintenance_status=_maintenance_status(raw.get("maintenance_status", "active")),
        project_activity=_project_activity(raw.get("project_activity", "medium")),
        community_score=float(raw.get("community_score", 0.0)),
        description=str(raw.get("description", "")),
        tags=tuple(str(t) for t in raw.get("tags", ())),
    )


def knowledge_to_dict(knowledge: ToolKnowledge) -> dict[str, Any]:
    """Serialize :class:`ToolKnowledge` to a JSON-safe mapping."""
    payload: dict[str, Any] = {
        "tool_id": knowledge.tool_id,
        "canonical_name": knowledge.canonical_name,
        "purpose": knowledge.purpose,
        "capabilities": list(knowledge.capabilities),
        "supported_assessments": list(knowledge.supported_assessments),
        "supported_mission_profiles": list(knowledge.supported_mission_profiles),
        "inputs": {
            "accepts": list(knowledge.inputs.accepts),
            "required": list(knowledge.inputs.required),
            "optional": list(knowledge.inputs.optional),
            "transforms": list(knowledge.inputs.transforms),
            "max_targets_per_invocation": knowledge.inputs.max_targets_per_invocation,
        },
        "outputs": {
            "formats": list(knowledge.outputs.formats),
            "parser": knowledge.outputs.parser,
            "normalizer": knowledge.outputs.normalizer,
            "event_types": list(knowledge.outputs.event_types),
            "evidence_capture": list(knowledge.outputs.evidence_capture),
            "dedup_key_spec": list(knowledge.outputs.dedup_key_spec),
        },
        "cli_binary": knowledge.cli_binary,
        "cli_structure": knowledge.cli_structure,
        "arguments": [_argument_to_dict(a) for a in knowledge.arguments],
        "modes": [_mode_to_dict(m) for m in knowledge.modes],
        "safe_mode": knowledge.safe_mode,
        "aggressive_mode": knowledge.aggressive_mode,
        "authentication_requirements": knowledge.authentication_requirements,
        "privileges_required": knowledge.privileges_required,
        "limitations": list(knowledge.limitations),
        "known_issues": list(knowledge.known_issues),
        "performance_notes": knowledge.performance_notes,
        "installation_requirements": list(knowledge.installation_requirements),
        "dependencies": [_dependency_to_dict(d) for d in knowledge.dependencies],
        "alternative_tools": list(knowledge.alternative_tools),
        "recommended_usage": list(knowledge.recommended_usage),
        "common_mistakes": list(knowledge.common_mistakes),
        "examples": list(knowledge.examples),
        "references": list(knowledge.references),
        "supported_targets": list(knowledge.supported_targets),
        "supported_protocols": list(knowledge.supported_protocols),
        "supported_vulnerabilities": list(knowledge.supported_vulnerabilities),
        "supported_evidence_types": list(knowledge.supported_evidence_types),
        "supported_proof_strategies": list(knowledge.supported_proof_strategies),
        "parser_id": knowledge.parser_id,
        "normalizer_id": knowledge.normalizer_id,
        "adapter_id": knowledge.adapter_id,
        "version_constraints": list(knowledge.version_constraints),
        "known_false_positives": list(knowledge.known_false_positives),
        "known_false_negatives": list(knowledge.known_false_negatives),
        "provenance": dict(knowledge.provenance),
        "knowledge_version": knowledge.knowledge_version,
        "configuration_contract": knowledge.configuration_contract,
    }
    if knowledge.input_schema is not None:
        payload["input_schema"] = _input_schema_to_dict(knowledge.input_schema)
    if knowledge.output_schema is not None:
        payload["output_schema"] = _output_schema_to_dict(knowledge.output_schema)
    if knowledge.invocation_contract is not None:
        payload["invocation_contract"] = _invocation_to_dict(knowledge.invocation_contract)
    if knowledge.resource_requirements is not None:
        payload["resource_requirements"] = _resources_to_dict(knowledge.resource_requirements)
    if knowledge.safety_profile is not None:
        payload["safety_profile"] = _safety_to_dict(knowledge.safety_profile)
    if knowledge.scope_profile is not None:
        payload["scope_profile"] = _scope_to_dict(knowledge.scope_profile)
    return payload


def knowledge_from_dict(raw: dict[str, Any]) -> ToolKnowledge:
    """Build :class:`ToolKnowledge` from a mapping (raises on missing id)."""
    tool_id = str(raw.get("tool_id", ""))
    if not tool_id:
        raise ConfigurationError("Tool knowledge requires a 'tool_id'.")
    inputs_raw = raw.get("inputs", {}) or {}
    outputs_raw = raw.get("outputs", {}) or {}
    return ToolKnowledge(
        tool_id=tool_id,
        canonical_name=str(raw.get("canonical_name", "")),
        purpose=str(raw.get("purpose", "")),
        capabilities=tuple(str(c) for c in raw.get("capabilities", ())),
        supported_assessments=tuple(str(a) for a in raw.get("supported_assessments", ())),
        supported_mission_profiles=tuple(
            str(m) for m in raw.get("supported_mission_profiles", ())
        ),
        inputs=ToolInputContract(
            accepts=tuple(str(i) for i in inputs_raw.get("accepts", ())),
            required=tuple(str(i) for i in inputs_raw.get("required", ())),
            optional=tuple(str(i) for i in inputs_raw.get("optional", ())),
            transforms=tuple(str(i) for i in inputs_raw.get("transforms", ())),
            max_targets_per_invocation=int(inputs_raw.get("max_targets_per_invocation", 0)),
        ),
        outputs=ToolOutputContract(
            formats=tuple(str(f) for f in outputs_raw.get("formats", ())),
            parser=str(outputs_raw.get("parser", "")),
            normalizer=str(outputs_raw.get("normalizer", "")),
            event_types=tuple(str(e) for e in outputs_raw.get("event_types", ())),
            evidence_capture=tuple(str(e) for e in outputs_raw.get("evidence_capture", ())),
            dedup_key_spec=tuple(str(f) for f in outputs_raw.get("dedup_key_spec", ())),
        ),
        cli_binary=str(raw.get("cli_binary", "")),
        cli_structure=str(raw.get("cli_structure", "")),
        arguments=tuple(_argument_from_dict(a) for a in raw.get("arguments", ())),
        modes=tuple(_mode_from_dict(m) for m in raw.get("modes", ())),
        safe_mode=str(raw.get("safe_mode", "")),
        aggressive_mode=str(raw.get("aggressive_mode", "")),
        authentication_requirements=str(raw.get("authentication_requirements", "")),
        privileges_required=str(raw.get("privileges_required", "")),
        limitations=tuple(str(lim) for lim in raw.get("limitations", ())),
        known_issues=tuple(str(i) for i in raw.get("known_issues", ())),
        performance_notes=str(raw.get("performance_notes", "")),
        installation_requirements=tuple(
            str(i) for i in raw.get("installation_requirements", ())
        ),
        dependencies=tuple(_dependency_from_dict(d) for d in raw.get("dependencies", ())),
        alternative_tools=tuple(str(a) for a in raw.get("alternative_tools", ())),
        recommended_usage=tuple(str(u) for u in raw.get("recommended_usage", ())),
        common_mistakes=tuple(str(m) for m in raw.get("common_mistakes", ())),
        examples=tuple(str(e) for e in raw.get("examples", ())),
        references=tuple(str(r) for r in raw.get("references", ())),
        supported_targets=tuple(str(t) for t in raw.get("supported_targets", ())),
        supported_protocols=tuple(str(p) for p in raw.get("supported_protocols", ())),
        supported_vulnerabilities=tuple(str(v) for v in raw.get("supported_vulnerabilities", ())),
        supported_evidence_types=tuple(str(e) for e in raw.get("supported_evidence_types", ())),
        supported_proof_strategies=tuple(
            str(s) for s in raw.get("supported_proof_strategies", ())
        ),
        input_schema=(
            _input_schema_from_dict(raw["input_schema"]) if raw.get("input_schema") else None
        ),
        output_schema=(
            _output_schema_from_dict(raw["output_schema"]) if raw.get("output_schema") else None
        ),
        invocation_contract=(
            _invocation_from_dict(raw["invocation_contract"])
            if raw.get("invocation_contract")
            else None
        ),
        configuration_contract=str(raw.get("configuration_contract", "")),
        resource_requirements=(
            _resources_from_dict(raw["resource_requirements"])
            if raw.get("resource_requirements")
            else None
        ),
        safety_profile=(
            _safety_from_dict(raw["safety_profile"]) if raw.get("safety_profile") else None
        ),
        scope_profile=(
            _scope_from_dict(raw["scope_profile"]) if raw.get("scope_profile") else None
        ),
        parser_id=str(raw.get("parser_id", "")),
        normalizer_id=str(raw.get("normalizer_id", "")),
        adapter_id=str(raw.get("adapter_id", "")),
        version_constraints=tuple(str(v) for v in raw.get("version_constraints", ())),
        known_false_positives=tuple(str(v) for v in raw.get("known_false_positives", ())),
        known_false_negatives=tuple(str(v) for v in raw.get("known_false_negatives", ())),
        provenance={str(k): str(v) for k, v in (raw.get("provenance") or {}).items()},
        knowledge_version=str(raw.get("knowledge_version", "1.0.0")),
    )


def compatibility_from_dict(raw: dict[str, Any]) -> ToolCompatibility:
    """Build :class:`ToolCompatibility` from a mapping."""
    return ToolCompatibility(
        tool_id=str(raw.get("tool_id", "")),
        os=tuple(str(o) for o in raw.get("os", ())),
        architectures=tuple(str(a) for a in raw.get("architectures", ())),
        python_versions=tuple(str(p) for p in raw.get("python_versions", ())),
        docker=bool(raw.get("docker", False)),
        containerized=bool(raw.get("containerized", False)),
        native=bool(raw.get("native", True)),
        cloud=bool(raw.get("cloud", False)),
        air_gapped=bool(raw.get("air_gapped", True)),
    )


def load_knowledge_file(path: str) -> ToolKnowledge:
    """Load a Tool Knowledge File (YAML) from ``path``."""
    try:
        with open(path, encoding="utf-8") as handle:
            raw = yaml.safe_load(handle)
    except OSError as exc:
        raise ConfigurationError(f"Cannot read knowledge file '{path}': {exc}") from exc
    except yaml.YAMLError as exc:
        raise ConfigurationError(f"Invalid YAML in '{path}': {exc}") from exc
    if not isinstance(raw, dict):
        raise ConfigurationError(f"Knowledge file '{path}' must be a mapping.")
    return knowledge_from_dict(raw)


def _argument_to_dict(argument: ToolArgument) -> dict[str, Any]:
    return {
        "name": argument.name,
        "flag": argument.flag,
        "kind": argument.kind,
        "required": argument.required,
        "default": argument.default,
        "description": argument.description,
        "choices": list(argument.choices),
    }


def _argument_from_dict(raw: dict[str, Any]) -> ToolArgument:
    return ToolArgument(
        name=str(raw.get("name", "")),
        flag=str(raw.get("flag", "")),
        kind=str(raw.get("kind", "string")),
        required=bool(raw.get("required", False)),
        default=raw.get("default"),
        description=str(raw.get("description", "")),
        choices=tuple(str(c) for c in raw.get("choices", ())),
    )


def _mode_to_dict(mode: ToolExecutionMode) -> dict[str, Any]:
    return {
        "id": mode.id,
        "description": mode.description,
        "safe": mode.safe,
        "aggressive": mode.aggressive,
        "args": list(mode.args),
    }


def _mode_from_dict(raw: dict[str, Any]) -> ToolExecutionMode:
    return ToolExecutionMode(
        id=str(raw.get("id", "")),
        description=str(raw.get("description", "")),
        safe=bool(raw.get("safe", True)),
        aggressive=bool(raw.get("aggressive", False)),
        args=tuple(str(a) for a in raw.get("args", ())),
    )


def _dependency_to_dict(dependency: ToolDependency) -> dict[str, Any]:
    return {
        "capability": dependency.capability,
        "provided_by": dependency.provided_by,
        "optional": dependency.optional,
        "description": dependency.description,
    }


def _dependency_from_dict(raw: dict[str, Any]) -> ToolDependency:
    return ToolDependency(
        capability=str(raw.get("capability", "")),
        provided_by=str(raw.get("provided_by", "")),
        optional=bool(raw.get("optional", False)),
        description=str(raw.get("description", "")),
    )


def input_field_to_dict(field_: ToolInputField) -> dict[str, Any]:
    """Serialize a :class:`ToolInputField` to a JSON-safe mapping."""
    return {
        "name": field_.name,
        "kind": field_.kind,
        "required": field_.required,
        "default": field_.default,
        "choices": list(field_.choices),
        "pattern": field_.pattern,
        "description": field_.description,
        "sensitive": field_.sensitive,
        "scope_linked": field_.scope_linked,
    }


def input_field_from_dict(raw: dict[str, Any]) -> ToolInputField:
    """Build a :class:`ToolInputField` from a mapping."""
    return ToolInputField(
        name=str(raw.get("name", "")),
        kind=str(raw.get("kind", "string")),
        required=bool(raw.get("required", False)),
        default=raw.get("default"),
        choices=tuple(str(c) for c in raw.get("choices", ())),
        pattern=str(raw.get("pattern", "")),
        description=str(raw.get("description", "")),
        sensitive=bool(raw.get("sensitive", False)),
        scope_linked=bool(raw.get("scope_linked", False)),
    )


def _input_schema_to_dict(schema: ToolInputSchema) -> dict[str, Any]:
    return {
        "fields": [input_field_to_dict(f) for f in schema.fields],
        "required": list(schema.required),
        "optional": list(schema.optional),
        "target_type": schema.target_type,
        "scope": schema.scope,
        "authentication": schema.authentication,
        "headers": list(schema.headers),
        "cookies": list(schema.cookies),
        "rate_limits": list(schema.rate_limits),
        "timeout": schema.timeout,
        "output_format": schema.output_format,
        "execution_mode": schema.execution_mode,
    }


def _input_schema_from_dict(raw: dict[str, Any]) -> ToolInputSchema:
    return ToolInputSchema(
        fields=tuple(input_field_from_dict(f) for f in raw.get("fields", ())),
        required=tuple(str(r) for r in raw.get("required", ())),
        optional=tuple(str(o) for o in raw.get("optional", ())),
        target_type=str(raw.get("target_type", "")),
        scope=str(raw.get("scope", "")),
        authentication=str(raw.get("authentication", "")),
        headers=tuple(str(h) for h in raw.get("headers", ())),
        cookies=tuple(str(c) for c in raw.get("cookies", ())),
        rate_limits=tuple(str(r) for r in raw.get("rate_limits", ())),
        timeout=float(raw.get("timeout", 0.0)),
        output_format=str(raw.get("output_format", "")),
        execution_mode=str(raw.get("execution_mode", "")),
    )


def output_field_to_dict(field_: ToolOutputField) -> dict[str, Any]:
    """Serialize a :class:`ToolOutputField` to a JSON-safe mapping."""
    return {
        "name": field_.name,
        "kind": field_.kind,
        "description": field_.description,
        "required": field_.required,
    }


def output_field_from_dict(raw: dict[str, Any]) -> ToolOutputField:
    """Build a :class:`ToolOutputField` from a mapping."""
    return ToolOutputField(
        name=str(raw.get("name", "")),
        kind=str(raw.get("kind", "string")),
        description=str(raw.get("description", "")),
        required=bool(raw.get("required", False)),
    )


def _output_schema_to_dict(schema: ToolOutputSchema) -> dict[str, Any]:
    return {
        "fields": [output_field_to_dict(f) for f in schema.fields],
        "required_fields": list(schema.required_fields),
        "formats": list(schema.formats),
    }


def _output_schema_from_dict(raw: dict[str, Any]) -> ToolOutputSchema:
    return ToolOutputSchema(
        fields=tuple(output_field_from_dict(f) for f in raw.get("fields", ())),
        required_fields=tuple(str(r) for r in raw.get("required_fields", ())),
        formats=tuple(str(f) for f in raw.get("formats", ())),
    )


def _invocation_to_dict(contract: ToolInvocationContract) -> dict[str, Any]:
    return {
        "command": contract.command,
        "arguments": [input_field_to_dict(a) for a in contract.arguments],
        "environment": list(contract.environment),
        "working_directory": contract.working_directory,
        "input_files": list(contract.input_files),
        "output_files": list(contract.output_files),
        "stdin": contract.stdin,
        "timeout": contract.timeout,
        "resource_limits": list(contract.resource_limits),
        "network_policy": contract.network_policy,
        "filesystem_policy": contract.filesystem_policy,
        "scope_policy": contract.scope_policy,
        "safety_policy": contract.safety_policy,
        "expected_exit_codes": list(contract.expected_exit_codes),
        "expected_output_formats": list(contract.expected_output_formats),
    }


def _invocation_from_dict(raw: dict[str, Any]) -> ToolInvocationContract:
    return ToolInvocationContract(
        command=str(raw.get("command", "")),
        arguments=tuple(input_field_from_dict(a) for a in raw.get("arguments", ())),
        environment=tuple(str(e) for e in raw.get("environment", ())),
        working_directory=str(raw.get("working_directory", "")),
        input_files=tuple(str(f) for f in raw.get("input_files", ())),
        output_files=tuple(str(f) for f in raw.get("output_files", ())),
        stdin=bool(raw.get("stdin", False)),
        timeout=float(raw.get("timeout", 0.0)),
        resource_limits=tuple(str(r) for r in raw.get("resource_limits", ())),
        network_policy=str(raw.get("network_policy", "allowed")),
        filesystem_policy=str(raw.get("filesystem_policy", "scoped")),
        scope_policy=str(raw.get("scope_policy", "inherit")),
        safety_policy=str(raw.get("safety_policy", "inherit")),
        expected_exit_codes=tuple(int(c) for c in raw.get("expected_exit_codes", (0,))),
        expected_output_formats=tuple(str(f) for f in raw.get("expected_output_formats", ())),
    )


def _resources_to_dict(resources: ToolResourceRequirements) -> dict[str, Any]:
    rate_limit = resources.rate_limit
    return {
        "cpu_estimate": resources.cpu_estimate,
        "memory_estimate_mb": resources.memory_estimate_mb,
        "network_estimate": resources.network_estimate,
        "disk_estimate_mb": resources.disk_estimate_mb,
        "timeout": resources.timeout,
        "concurrency_class": resources.concurrency_class,
        "rate_limit": {
            "requests_per_second": rate_limit.requests_per_second,
            "concurrency": rate_limit.concurrency,
            "burst": rate_limit.burst,
            "cooldown_seconds": rate_limit.cooldown_seconds,
            "target_limits": dict(rate_limit.target_limits),
        }
        if rate_limit is not None
        else None,
    }


def _resources_from_dict(raw: dict[str, Any]) -> ToolResourceRequirements:
    rate_limit_raw = raw.get("rate_limit") or {}
    rate_limit = ToolRateLimitProfile(
        requests_per_second=float(rate_limit_raw.get("requests_per_second", 0.0)),
        concurrency=int(rate_limit_raw.get("concurrency", 0)),
        burst=int(rate_limit_raw.get("burst", 0)),
        cooldown_seconds=float(rate_limit_raw.get("cooldown_seconds", 0.0)),
        target_limits={str(k): float(v) for k, v in (rate_limit_raw.get("target_limits") or {}).items()},
    )
    return ToolResourceRequirements(
        cpu_estimate=float(raw.get("cpu_estimate", 0.0)),
        memory_estimate_mb=float(raw.get("memory_estimate_mb", 0.0)),
        network_estimate=str(raw.get("network_estimate", "low")),
        disk_estimate_mb=float(raw.get("disk_estimate_mb", 0.0)),
        timeout=float(raw.get("timeout", 0.0)),
        concurrency_class=str(raw.get("concurrency_class", "light")),
        rate_limit=rate_limit,
    )


def _safety_to_dict(profile: ToolSafetyProfile) -> dict[str, Any]:
    return {
        "safety_class": profile.safety_class.value,
        "destructive": profile.destructive,
        "requires_authorization": profile.requires_authorization,
        "approval_level": profile.approval_level,
        "allowed_for": list(profile.allowed_for),
    }


def _safety_from_dict(raw: dict[str, Any]) -> ToolSafetyProfile:

    return ToolSafetyProfile(
        safety_class=_safety_class(raw.get("safety_class", "passive")),
        destructive=bool(raw.get("destructive", False)),
        requires_authorization=bool(raw.get("requires_authorization", False)),
        approval_level=str(raw.get("approval_level", "")),
        allowed_for=tuple(str(a) for a in raw.get("allowed_for", ())),
    )


def _scope_to_dict(profile: ToolScopeProfile) -> dict[str, Any]:
    return {
        "follows_redirects": profile.follows_redirects,
        "redirect_scope": profile.redirect_scope,
        "expands_scope": profile.expands_scope,
        "network_boundary": profile.network_boundary,
    }


def _scope_from_dict(raw: dict[str, Any]) -> ToolScopeProfile:
    return ToolScopeProfile(
        follows_redirects=bool(raw.get("follows_redirects", False)),
        redirect_scope=str(raw.get("redirect_scope", "inherit")),
        expands_scope=bool(raw.get("expands_scope", False)),
        network_boundary=str(raw.get("network_boundary", "inherit")),
    )


def evidence_mapping_to_dict(mapping: ToolEvidenceMapping) -> dict[str, Any]:
    """Serialize a :class:`ToolEvidenceMapping` to a JSON-safe mapping."""
    return {
        "tool_id": mapping.tool_id,
        "observation_kind": mapping.observation_kind,
        "evidence_type": mapping.evidence_type,
        "strength": mapping.strength.value,
        "vulnerability_classes": list(mapping.vulnerability_classes),
        "proof_strategies": list(mapping.proof_strategies),
        "requires_validation": mapping.requires_validation,
        "confidence_contribution": mapping.confidence_contribution,
        "notes": mapping.notes,
    }


def evidence_mapping_from_dict(raw: dict[str, Any]) -> ToolEvidenceMapping:
    """Build a :class:`ToolEvidenceMapping` from a mapping."""
    return ToolEvidenceMapping(
        tool_id=str(raw.get("tool_id", "")),
        observation_kind=str(raw.get("observation_kind", "")),
        evidence_type=str(raw.get("evidence_type", "")),
        strength=_evidence_strength(raw.get("strength", "detection")),
        vulnerability_classes=tuple(str(v) for v in raw.get("vulnerability_classes", ())),
        proof_strategies=tuple(str(s) for s in raw.get("proof_strategies", ())),
        requires_validation=bool(raw.get("requires_validation", True)),
        confidence_contribution=float(raw.get("confidence_contribution", 0.0)),
        notes=str(raw.get("notes", "")),
    )


def proof_capability_to_dict(capability: ToolProofCapability) -> dict[str, Any]:
    """Serialize a :class:`ToolProofCapability` to a JSON-safe mapping."""
    return {
        "tool_id": capability.tool_id,
        "vulnerability_class": capability.vulnerability_class,
        "proof_strategy_id": capability.proof_strategy_id,
        "supported_proof_types": list(capability.supported_proof_types),
        "required_inputs": list(capability.required_inputs),
        "produced_evidence": list(capability.produced_evidence),
        "limitations": list(capability.limitations),
        "safety_class": capability.safety_class.value,
        "scope_requirements": capability.scope_requirements,
        "replay_support": capability.replay_support,
        "confidence_ceiling": capability.confidence_ceiling,
    }


def proof_capability_from_dict(raw: dict[str, Any]) -> ToolProofCapability:
    """Build a :class:`ToolProofCapability` from a mapping."""
    return ToolProofCapability(
        tool_id=str(raw.get("tool_id", "")),
        vulnerability_class=str(raw.get("vulnerability_class", "")),
        proof_strategy_id=str(raw.get("proof_strategy_id", "")),
        supported_proof_types=tuple(str(p) for p in raw.get("supported_proof_types", ())),
        required_inputs=tuple(str(i) for i in raw.get("required_inputs", ())),
        produced_evidence=tuple(str(e) for e in raw.get("produced_evidence", ())),
        limitations=tuple(str(item) for item in raw.get("limitations", ())),
        safety_class=_safety_class(raw.get("safety_class", "active")),
        scope_requirements=str(raw.get("scope_requirements", "")),
        replay_support=bool(raw.get("replay_support", False)),
        confidence_ceiling=float(raw.get("confidence_ceiling", 0.9)),
    )


def confidence_ceiling_to_dict(ceiling: ToolConfidenceCeiling) -> dict[str, Any]:
    """Serialize a :class:`ToolConfidenceCeiling` to a JSON-safe mapping."""
    return {
        "tool_id": ceiling.tool_id,
        "detection_ceiling": ceiling.detection_ceiling,
        "behavioral_ceiling": ceiling.behavioral_ceiling,
        "proof_ceiling": ceiling.proof_ceiling,
    }


def confidence_ceiling_from_dict(raw: dict[str, Any]) -> ToolConfidenceCeiling:
    """Build a :class:`ToolConfidenceCeiling` from a mapping."""
    return ToolConfidenceCeiling(
        tool_id=str(raw.get("tool_id", "")),
        detection_ceiling=float(raw.get("detection_ceiling", 0.5)),
        behavioral_ceiling=float(raw.get("behavioral_ceiling", 0.8)),
        proof_ceiling=float(raw.get("proof_ceiling", 0.95)),
    )


def _safety_class(value: Any) -> ToolSafetyClass:
    try:
        return ToolSafetyClass(str(value))
    except ValueError:
        return ToolSafetyClass.PASSIVE


def _evidence_strength(value: Any) -> EvidenceStrength:
    try:
        return EvidenceStrength(str(value))
    except ValueError:
        return EvidenceStrength.DETECTION


def _execution_type(value: Any) -> ToolExecutionType:
    try:
        return ToolExecutionType(str(value))
    except ValueError:
        return ToolExecutionType.BINARY


def _maintenance_status(value: Any) -> MaintenanceStatus:
    try:
        return MaintenanceStatus(str(value))
    except ValueError:
        return MaintenanceStatus.ACTIVE


def _project_activity(value: Any) -> ProjectActivity:
    try:
        return ProjectActivity(str(value))
    except ValueError:
        return ProjectActivity.MEDIUM
