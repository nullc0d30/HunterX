# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tool Intelligence Platform registration for Secret Discovery.

Registers the secret discovery tools (gitleaks) into a
:class:`ToolIntelligenceAPI` with the full Sprint 023 contracts. The safety
profile is bounded to ``LOW_IMPACT_ACTIVE`` and the filesystem policy is
read-only. Secret output is always redacted by the adapter.
"""

from __future__ import annotations

from hunterx.domain.tool_intelligence import (
    MaintenanceStatus,
    ProjectActivity,
    ToolArgument,
    ToolCompatibility,
    ToolConfidenceCeiling,
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
    ToolResourceRequirements,
    ToolSafetyClass,
    ToolSafetyProfile,
    ToolScopeProfile,
)
from hunterx.tools.intelligence.api import ToolIntelligenceAPI

#: Mission profiles that exercise secret discovery.
_MISSIONS = ("code-review", "devsecops", "audit", "external-pentest")

#: Canonical capability identifiers advertised by the secrets tool set.
_CAPABILITIES = ("secrets-scan", "secrets-detection")

_SECRETS_TOOLS: tuple[ToolMetadata, ...] = (
    ToolMetadata(
        tool_id="gitleaks",
        display_name="gitleaks",
        vendor="Gitleaks",
        project_url="https://github.com/gitleaks/gitleaks",
        license="MIT",
        category="analysis",
        subcategory="code",
        version="8.18.0",
        platforms=("linux", "windows", "darwin"),
        architectures=("amd64", "arm64"),
        language="go",
        execution_type=ToolExecutionType.BINARY,
        package_manager="go",
        container_available=True,
        binary_available=True,
        maintenance_status=MaintenanceStatus.ACTIVE,
        project_activity=ProjectActivity.HIGH,
        community_score=96.0,
        description="Detect hardcoded secrets in filesystems, repositories and artifacts.",
        tags=("secrets", "sast", "credential", "leak"),
    ),
)


def register_secrets_tools(tip: ToolIntelligenceAPI) -> None:
    """Register every secret discovery tool into ``tip``."""
    for metadata in _SECRETS_TOOLS:
        tip.register_tool(
            metadata,
            knowledge=_knowledge(metadata),
            compatibility=_compatibility(metadata),
        )


def secrets_tool_ids() -> tuple[str, ...]:
    """Return the secret tool ids registered on the execution engine."""
    from hunterx.tools.secrets.registry import SECRETS_TOOL_IDS

    return SECRETS_TOOL_IDS


def _knowledge(metadata: ToolMetadata) -> ToolKnowledge:
    tool_id = metadata.tool_id
    return ToolKnowledge(
        tool_id=tool_id,
        canonical_name=tool_id,
        purpose=metadata.description,
        capabilities=_CAPABILITIES,
        supported_assessments=("code", "source", "artifact"),
        supported_mission_profiles=_MISSIONS,
        inputs=ToolInputContract(
            accepts=("path", "repository", "artifact"),
            required=("source",),
            optional=("report_path", "verbose", "redact"),
            transforms=(),
            max_targets_per_invocation=1,
        ),
        outputs=ToolOutputContract(
            formats=("json",),
            parser="gitleaks-json",
            normalizer="secret-normalizer",
            event_types=("arsenal.secret.discovered",),
            evidence_capture=("findings",),
            dedup_key_spec=("fingerprint", "secret_type", "location"),
        ),
        cli_binary="gitleaks",
        cli_structure="subcommand",
        arguments=(
            ToolArgument("source", "--source", "path", required=True, description="Input to scan."),
            ToolArgument("report_path", "--report-path", "path", description="Where gitleaks writes its report."),
            ToolArgument("redact", "--redact", "bool", description="Redact secrets from output."),
            ToolArgument("verbose", "-v", "bool", description="Verbose logging."),
        ),
        modes=(
            ToolExecutionMode("filesystem", description="Scan a filesystem tree.", safe=True),
            ToolExecutionMode("repository", description="Scan a git repository (requires git).", safe=True),
            ToolExecutionMode("artifact", description="Scan a build artifact or archive.", safe=True),
        ),
        safe_mode="filesystem",
        aggressive_mode="filesystem",
        authentication_requirements="none",
        privileges_required="user",
        limitations=(
            "Detected secrets are candidates; validate ownership before acting.",
            "Entropy-only rules produce false positives.",
        ),
        known_issues=(),
        installation_requirements=("go install github.com/gitleaks/gitleaks/v8@latest",),
        dependencies=(),
        alternative_tools=(),
        recommended_usage=(
            "Scan only in-scope repositories/artifacts and never persist raw matches.",
            "Treat every finding as sensitive material.",
        ),
        common_mistakes=("Scanning out-of-scope codebases or storing raw secrets.",),
        examples=("gitleaks detect --source /repo --report-format json",),
        references=(metadata.project_url,),
        supported_targets=("path", "repository", "artifact"),
        supported_protocols=(),
        supported_vulnerabilities=(),
        supported_evidence_types=("masked-secret", "secret-fingerprint"),
        supported_proof_strategies=(),
        input_schema=ToolInputSchema(
            fields=(
                ToolInputField("source", "path", required=True, scope_linked=True, description="Input to scan."),
                ToolInputField("report_path", "path", description="Report artifact path."),
                ToolInputField("redact", "bool", description="Redact secrets from output."),
                ToolInputField("verbose", "bool", description="Verbose logging."),
            ),
            required=("source",),
            optional=("report_path", "redact", "verbose"),
            target_type="path",
            scope="inherit",
            timeout=120.0,
            output_format="json",
            execution_mode="filesystem",
        ),
        output_schema=ToolOutputSchema(
            fields=(
                ToolOutputField("secret_type", "string", "Detected secret rule id."),
                ToolOutputField("location", "string", "File location."),
                ToolOutputField("fingerprint", "string", "SHA-256 fingerprint."),
                ToolOutputField("masked_value", "string", "Masked preview of the secret."),
                ToolOutputField("confidence", "float", "Detection confidence."),
            ),
            required_fields=("secret_type", "fingerprint"),
            formats=("json",),
        ),
        invocation_contract=ToolInvocationContract(
            command="gitleaks",
            arguments=(
                ToolInputField("source", "path", required=True, scope_linked=True),
                ToolInputField("report_path", "path"),
                ToolInputField("redact", "bool"),
                ToolInputField("verbose", "bool"),
            ),
            stdin=False,
            timeout=120.0,
            network_policy="denied",
            filesystem_policy="read-only",
            scope_policy="inherit",
            safety_policy="low-impact-active",
            expected_exit_codes=(0, 1),
            expected_output_formats=("json",),
        ),
        configuration_contract="no raw secrets may be persisted",
        resource_requirements=ToolResourceRequirements(
            cpu_estimate=20.0,
            memory_estimate_mb=256.0,
            network_estimate="low",
            disk_estimate_mb=64.0,
            timeout=120.0,
            concurrency_class="medium",
        ),
        safety_profile=ToolSafetyProfile(
            safety_class=ToolSafetyClass.LOW_IMPACT_ACTIVE,
            destructive=False,
            requires_authorization=False,
            allowed_for=("code-review", "devsecops", "audit", "external-pentest"),
        ),
        scope_profile=ToolScopeProfile(
            follows_redirects=False,
            redirect_scope="inherit",
            expands_scope=False,
            network_boundary="inherit",
        ),
        parser_id="gitleaks-json",
        normalizer_id="secret-normalizer",
        adapter_id="hunterx.tools.secrets.gitleaks:GitleaksAdapter",
        version_constraints=(">=8.0.0",),
        known_false_positives=("Entropy-only matches on non-secret strings.",),
        known_false_negatives=("Secrets split across lines or in binary files.",),
        provenance={"source": "sprint-024", "category": "secrets", "license": "MIT"},
        knowledge_version="1.0.0",
    )


def _compatibility(metadata: ToolMetadata) -> ToolCompatibility:
    return ToolCompatibility(
        tool_id=metadata.tool_id,
        os=("linux", "windows", "darwin"),
        architectures=("amd64", "arm64"),
        docker=True,
        containerized=False,
        native=True,
        cloud=True,
        air_gapped=False,
    )


#: Confidence ceiling: gitleaks findings are detection-grade candidates.
GITLEAKS_CONFIDENCE_CEILING = ToolConfidenceCeiling(
    tool_id="gitleaks",
    detection_ceiling=0.7,
    behavioral_ceiling=0.8,
    proof_ceiling=0.8,
)
