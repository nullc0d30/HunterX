# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tool Integration Factory generators.

Every generator emits a slice of a Tool Integration Pack. The engine runs them
in a fixed order and assembles the resulting files.
"""

from __future__ import annotations

from hunterx.tools.factory.generators.base import PackContext, PackGenerator
from hunterx.tools.factory.generators.code import (
    AdapterGenerator,
    ErrorHandlingGenerator,
    LoggingGenerator,
    TelemetryGenerator,
)
from hunterx.tools.factory.generators.core import (
    InstallationGenerator,
    KnowledgeFileGenerator,
    MetadataGenerator,
    VersionMetadataGenerator,
)
from hunterx.tools.factory.generators.io import (
    DatabaseMappingGenerator,
    NormalizerGenerator,
    ParserGenerator,
    SchemaGenerator,
)
from hunterx.tools.factory.generators.quality import (
    BoilerplateGenerator,
    DocumentationGenerator,
    PackagingGenerator,
    TestGenerator,
    ValidationGenerator,
)
from hunterx.tools.factory.generators.rules import (
    ExecutionRulesGenerator,
    MissionRulesGenerator,
    WorkflowRulesGenerator,
)

__all__ = [
    "PackContext",
    "PackGenerator",
    "AdapterGenerator",
    "ErrorHandlingGenerator",
    "LoggingGenerator",
    "TelemetryGenerator",
    "InstallationGenerator",
    "KnowledgeFileGenerator",
    "MetadataGenerator",
    "VersionMetadataGenerator",
    "DatabaseMappingGenerator",
    "NormalizerGenerator",
    "ParserGenerator",
    "SchemaGenerator",
    "BoilerplateGenerator",
    "DocumentationGenerator",
    "PackagingGenerator",
    "TestGenerator",
    "ValidationGenerator",
    "ExecutionRulesGenerator",
    "MissionRulesGenerator",
    "WorkflowRulesGenerator",
]


def default_generators() -> list[PackGenerator]:
    """Return every built-in generator in engine execution order."""
    return [
        BoilerplateGenerator(),
        MetadataGenerator(),
        VersionMetadataGenerator(),
        KnowledgeFileGenerator(),
        InstallationGenerator(),
        ExecutionRulesGenerator(),
        MissionRulesGenerator(),
        WorkflowRulesGenerator(),
        SchemaGenerator(),
        ParserGenerator(),
        NormalizerGenerator(),
        DatabaseMappingGenerator(),
        AdapterGenerator(),
        ErrorHandlingGenerator(),
        LoggingGenerator(),
        TelemetryGenerator(),
        TestGenerator(),
        DocumentationGenerator(),
        ValidationGenerator(),
        PackagingGenerator(),
    ]
