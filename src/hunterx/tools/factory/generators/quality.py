# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Quality generators: tests, documentation, validation and packaging.

Emits the test skeletons, the five documentation guides, the generated
validation rules and the packaging definition (``pyproject.toml``,
``README.md``, ``MANIFEST.in``) of a Tool Integration Pack, plus the package
marker files.
"""

from __future__ import annotations

from hunterx.domain.tool_factory import PackArtifactKind, render_yaml
from hunterx.tools.factory.generators.base import PackContext, PackGenerator
from hunterx.tools.factory.layout import PACK_STRUCTURE_VERSION, QUALITY_GATES, required_files
from hunterx.tools.factory.templates import BUILTIN_FILES


class BoilerplateGenerator(PackGenerator):
    """Generates the package marker (``__init__.py``) files."""

    name = "boilerplate"
    description = "Generates the package marker files."

    def generate(self, ctx: PackContext):
        """Emit the package marker files."""
        files = []
        for path in ("adapters/__init__.py", "parsing/__init__.py", "runtime/__init__.py", "tests/__init__.py"):
            content = self.render(ctx, path, BUILTIN_FILES[path])
            files.append(self.file(path, content, PackArtifactKind.BOILERPLATE))
        return files


class TestGenerator(PackGenerator):
    """Generates the unit, integration and performance test skeletons."""

    name = "tests"
    description = "Generates the unit, integration and performance test skeletons."

    def generate(self, ctx: PackContext):
        """Emit the unit, integration and performance test skeletons."""
        return [
            self.file(
                "tests/test_unit.py",
                self.render(ctx, "tests/test_unit.py", BUILTIN_FILES["tests/test_unit.py"]),
                PackArtifactKind.UNIT_TESTS,
            ),
            self.file(
                "tests/test_integration.py",
                self.render(ctx, "tests/test_integration.py", BUILTIN_FILES["tests/test_integration.py"]),
                PackArtifactKind.INTEGRATION_TESTS,
            ),
            self.file(
                "tests/test_performance.py",
                self.render(ctx, "tests/test_performance.py", BUILTIN_FILES["tests/test_performance.py"]),
                PackArtifactKind.PERFORMANCE_TESTS,
            ),
        ]


class DocumentationGenerator(PackGenerator):
    """Generates the developer, integration, architecture, lifecycle guides and examples."""

    name = "documentation"
    description = "Generates the pack documentation guides and examples."

    def generate(self, ctx: PackContext):
        """Emit the documentation guides and examples."""
        return [
            self.file("docs/developer.md", self.render(ctx, "docs/developer.md", _DEVELOPER), PackArtifactKind.DOCUMENTATION),
            self.file("docs/integration.md", self.render(ctx, "docs/integration.md", _INTEGRATION), PackArtifactKind.DOCUMENTATION),
            self.file("docs/architecture.md", self.render(ctx, "docs/architecture.md", _ARCHITECTURE), PackArtifactKind.DOCUMENTATION),
            self.file("docs/lifecycle.md", self.render(ctx, "docs/lifecycle.md", _LIFECYCLE), PackArtifactKind.DOCUMENTATION),
            self.file("docs/examples.md", self.render(ctx, "docs/examples.md", _EXAMPLES), PackArtifactKind.EXAMPLES),
        ]


class ValidationGenerator(PackGenerator):
    """Generates the pack validation rules (``validation/rules.yaml``)."""

    name = "validation"
    description = "Generates the validation rules record."

    def generate(self, ctx: PackContext):
        """Emit the validation rules record."""
        spec = ctx.spec
        data = {
            "tool_id": spec.pack_id,
            "structure_version": PACK_STRUCTURE_VERSION,
            "naming": {
                "pack_id_pattern": "^[a-z0-9][a-z0-9-]*$",
                "vendor_pattern": "^[a-z0-9][a-z0-9-]*$",
                "file_path_pattern": "^[a-z0-9/._-]+$",
            },
            "required_files": required_files(),
            "quality_gates": list(QUALITY_GATES),
            "schema_compatibility": {
                "input": "schemas/input.json",
                "output": "schemas/output.json",
            },
            "mission_compatibility": {"profiles": list(spec.mission_profiles)},
        }
        return [self.file("validation/rules.yaml", render_yaml(data) + "\n", PackArtifactKind.VALIDATION)]


class PackagingGenerator(PackGenerator):
    """Generates the packaging definition and top-level readme."""

    name = "packaging"
    description = "Generates pyproject.toml, README.md and MANIFEST.in."

    def generate(self, ctx: PackContext):
        """Emit the packaging definition and top-level readme."""
        return [
            self.file(
                "pyproject.toml",
                self.render(ctx, "pyproject.toml", BUILTIN_FILES["pyproject.toml"]),
                PackArtifactKind.PACKAGING,
            ),
            self.file(
                "README.md",
                self.render(ctx, "README.md", BUILTIN_FILES["README.md"]),
                PackArtifactKind.PACKAGING,
            ),
            self.file(
                "MANIFEST.in",
                self.render(ctx, "MANIFEST.in", BUILTIN_FILES["MANIFEST.in"]),
                PackArtifactKind.PACKAGING,
            ),
        ]


_DEVELOPER = """# ${display_name} — Developer Guide

${description}

Generated by the HunterX Tool Integration Factory v${generator_version}.
Structure version: ${structure_version}.

## Layout

Every pack follows the standard Tool Integration Pack layout:

- ``adapters/adapter.py`` — the :class:`ToolAdapter` for ${tool_name}.
- ``parsing/parser.py`` — parses raw output into records.
- ``parsing/normalizer.py`` — normalizes records into findings.
- ``runtime/`` — typed errors, logging and telemetry.
- ``mapping/`` — database, evidence and risk mappings.
- ``rules/`` — execution, mission and workflow rules.
- ``schemas/`` — input and output JSON Schemas.

## Developing the adapter

Implement ``${adapter_class_name}.run`` to invoke the ``${cli_binary}``
binary, attach raw output to the ``OutputCollector`` and set a JSON payload
shaped like ``{"findings": [...]}``. Add strategy-specific parsing to
``${parser_class_name}`` and refine normalization in
``${normalizer_class_name}``.

## Testing

Run the generated skeletons:

```bash
python -m pytest tests -q
```
"""

_INTEGRATION = """# ${display_name} — Integration Guide

Wiring the pack into HunterX.

## Registration

```python
from hunterx.tools.sdk import ExecutionEngine
from hunterx_tool_packs import ${pack_id}

engine = ExecutionEngine()
engine.register_adapter("${pack_id}", "${entrypoint}")
```

## Execution

```python
from hunterx.tools.sdk import ExecutionContextBuilder

context = (
    ExecutionContextBuilder(tool_id="${pack_id}", target="example.com")
    .with_parameters({...})
    .build()
)
result = engine.execute(context)
```

## Capabilities

This pack registers the following capabilities:

${capabilities_joined}

## Mission profiles

The pack participates in the following mission profiles:

${mission_profiles_list}
"""

_ARCHITECTURE = """# ${display_name} — Architecture Guide

## Overview

${description}

The pack is a standard HunterX Tool Integration Pack: an SDK adapter that
executes ${tool_name}, a parser and normalizer that turn raw output into
findings, and rule/schema/mapping records that describe how HunterX should
run, validate and persist the tool.

## Data flow

```text
target/parameters → adapter.run → collector → parser → normalizer → findings
```

## Records

- ``metadata/`` — tool metadata, version, compatibility matrix, migrations.
- ``knowledge/`` — knowledge profile and capabilities.
- ``install/`` — installation, dependencies and health checks.
- ``rules/`` — execution, mission and workflow rules.
- ``schemas/`` — input and output JSON Schemas.
- ``mapping/`` — database, evidence and risk mappings.
"""

_LIFECYCLE = """# ${display_name} — Lifecycle Guide

## Versioning

The pack version ${version} follows Semantic Versioning
(``major.minor.patch``).

- Breaking integration changes require a major bump.
- New capabilities require a minor bump.
- Fixes that preserve behavior require a patch bump.

## Compatibility

See ``metadata/compatibility.yaml`` for the declared compatibility matrix
against HunterX ${hunterx_version}.

## Deprecation

A deprecated pack (``deprecated: ${deprecated}``) remains usable but is
removed on the next major release. See ``metadata/migrations.yaml`` for
migration notes.
"""

_EXAMPLES = """# ${display_name} — Examples

${description}

## Scan a single target

```python
from ${vendor}.${pack_id}.adapters.adapter import ${adapter_class_name}

adapter = ${adapter_class_name}()
```

## Parse output

```python
from ${vendor}.${pack_id}.parsing.parser import ${parser_class_name}

records = ${parser_class_name}().parse(raw_output)
```

## Normalize findings

```python
from ${vendor}.${pack_id}.parsing.normalizer import ${normalizer_class_name}

findings = ${normalizer_class_name}().normalize(records, target="example.com")
```
"""
