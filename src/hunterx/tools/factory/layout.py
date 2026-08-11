# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Standard Tool Integration Pack layout.

Every Tool Integration Pack follows exactly the same directory structure.
No custom layouts are allowed: the layout is the contract. Generators emit
files for every path below and the validator enforces that no required file
is missing.
"""

from __future__ import annotations

from hunterx.domain.tool_factory import PackArtifactKind

#: The canonical pack structure version. Bump on breaking layout changes.
PACK_STRUCTURE_VERSION = "1.0"

#: Ordered pack layout: relative path -> (artifact kind, purpose).
PACK_LAYOUT: dict[str, tuple[PackArtifactKind, str]] = {
    "pack.yaml": (PackArtifactKind.MANIFEST, "Pack manifest and generated metadata"),
    "README.md": (PackArtifactKind.PACKAGING, "Pack overview"),
    "pyproject.toml": (PackArtifactKind.PACKAGING, "Packaging definition"),
    "MANIFEST.in": (PackArtifactKind.PACKAGING, "Distribution file manifest"),
    "metadata/tool.yaml": (PackArtifactKind.METADATA, "Tool metadata"),
    "metadata/version.yaml": (PackArtifactKind.VERSION, "Semantic version definition"),
    "metadata/compatibility.yaml": (PackArtifactKind.COMPATIBILITY, "Compatibility matrix"),
    "metadata/migrations.yaml": (PackArtifactKind.MIGRATIONS, "Migration support"),
    "knowledge/knowledge_profile.yaml": (PackArtifactKind.KNOWLEDGE, "Knowledge profile"),
    "knowledge/capabilities.yaml": (PackArtifactKind.CAPABILITIES, "Capabilities"),
    "install/installation.yaml": (PackArtifactKind.INSTALLATION, "Installation definition"),
    "install/dependencies.yaml": (PackArtifactKind.DEPENDENCY, "Dependency definition"),
    "install/health_check.yaml": (PackArtifactKind.HEALTH, "Health check"),
    "rules/execution.yaml": (PackArtifactKind.EXECUTION_RULES, "Execution rules"),
    "rules/mission.yaml": (PackArtifactKind.MISSION_RULES, "Mission rules"),
    "rules/workflow.yaml": (PackArtifactKind.WORKFLOW_RULES, "Workflow rules"),
    "schemas/input.json": (PackArtifactKind.INPUT_SCHEMA, "Input schema"),
    "schemas/output.json": (PackArtifactKind.OUTPUT_SCHEMA, "Output schema"),
    "adapters/__init__.py": (PackArtifactKind.BOILERPLATE, "Adapter package marker"),
    "adapters/adapter.py": (PackArtifactKind.ADAPTER, "Tool adapter"),
    "parsing/__init__.py": (PackArtifactKind.BOILERPLATE, "Parsing package marker"),
    "parsing/parser.py": (PackArtifactKind.PARSER, "Output parser"),
    "parsing/normalizer.py": (PackArtifactKind.NORMALIZER, "Result normalizer"),
    "mapping/database.yaml": (PackArtifactKind.DATABASE_MAPPING, "Database mapping"),
    "mapping/evidence.yaml": (PackArtifactKind.EVIDENCE_MAPPING, "Evidence mapping"),
    "mapping/risk.yaml": (PackArtifactKind.RISK_MAPPING, "Risk mapping"),
    "runtime/__init__.py": (PackArtifactKind.BOILERPLATE, "Runtime package marker"),
    "runtime/errors.py": (PackArtifactKind.ERROR_HANDLING, "Error handling"),
    "runtime/logging.py": (PackArtifactKind.LOGGING, "Logging"),
    "runtime/telemetry.py": (PackArtifactKind.TELEMETRY, "Telemetry"),
    "validation/rules.yaml": (PackArtifactKind.VALIDATION, "Validation rules"),
    "tests/__init__.py": (PackArtifactKind.BOILERPLATE, "Tests package marker"),
    "tests/test_unit.py": (PackArtifactKind.UNIT_TESTS, "Unit tests"),
    "tests/test_integration.py": (PackArtifactKind.INTEGRATION_TESTS, "Integration tests"),
    "tests/test_performance.py": (PackArtifactKind.PERFORMANCE_TESTS, "Performance tests"),
    "docs/developer.md": (PackArtifactKind.DOCUMENTATION, "Developer guide"),
    "docs/integration.md": (PackArtifactKind.DOCUMENTATION, "Integration guide"),
    "docs/architecture.md": (PackArtifactKind.DOCUMENTATION, "Architecture guide"),
    "docs/lifecycle.md": (PackArtifactKind.DOCUMENTATION, "Lifecycle guide"),
    "docs/examples.md": (PackArtifactKind.EXAMPLES, "Examples"),
}

#: Artifacts that must exist for a pack to be accepted (quality gates).
QUALITY_GATES: list[str] = [
    "pack.yaml",
    "metadata/version.yaml",
    "knowledge/knowledge_profile.yaml",
    "knowledge/capabilities.yaml",
    "install/health_check.yaml",
    "rules/execution.yaml",
    "rules/mission.yaml",
    "schemas/input.json",
    "schemas/output.json",
    "adapters/adapter.py",
    "parsing/parser.py",
    "parsing/normalizer.py",
    "mapping/database.yaml",
    "validation/rules.yaml",
    "tests/test_unit.py",
    "tests/test_integration.py",
    "tests/test_performance.py",
    "docs/developer.md",
    "docs/integration.md",
]

#: Generator engine version embedded in every generated manifest.
GENERATOR_VERSION = "1.0.0"

#: HunterX platform version embedded in packaging and the compatibility matrix.
HUNTERX_VERSION = "7.0.0"

#: Tool Integration SDK version embedded in generated boilerplate.
SDK_VERSION = "1.0.0"


def required_files() -> list[str]:
    """Return every file a complete Tool Integration Pack must contain."""
    return list(PACK_LAYOUT)


def quality_gate_files() -> list[str]:
    """Return the minimum files a pack must contain to be accepted."""
    return list(QUALITY_GATES)
