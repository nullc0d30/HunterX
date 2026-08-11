---
layout: default
title: HunterX v7 Tool Integration Factory - Architecture & Reference
description: >-
  Architecture and reference for the HunterX v7 Tool Integration Factory: the
  generation framework that produces standardized Tool Integration Packs for
  every future external security tool. The standard pack layout, integration
  templates, the 20-generator engine, the strict validator, semantic versioning
  with compatibility matrices and deprecation policy, and the ToolIntegrationFactory
  facade. Mermaid diagrams, data models and a developer integration guide.
permalink: /v7-tool-integration-factory/
---

# HunterX v7 Tool Integration Factory — Architecture & Reference

**Status:** Ratified (Sprint 006)
**Version:** 1.0.0
**Owner:** HunterX Architecture Council

---

## 1. Purpose / Scope

This document defines the **Tool Integration Factory** — the subsystem that
generates standardized, validated **Tool Integration Packs** for every future
external security tool (Nmap, Nuclei, Katana, SQLMap, and any tool yet to be
supported). It has one mandate:

**Generate — create the pack.** A `ToolPackSpec` (tool identity + capabilities
+ targets + permissions + mission profiles) is expanded into an identical,
production-ready Tool Integration Pack: metadata, knowledge profile,
capabilities, installation and dependency definitions, version metadata,
health check, execution/mission/workflow rules, input/output schemas, a parser,
a normalizer, database/evidence/risk mappings, error handling, logging,
telemetry, unit/integration/performance test skeletons, five documentation
guides, validation rules, and packaging.

Hard constraints:

- **No tool-specific code.** This sprint builds the factory and generation
  framework only. No external security tool is integrated; no real adapter is
  implemented; no scanner is generated.
- **One layout, no exceptions.** Every generated pack follows exactly the same
  directory structure (`PACK_LAYOUT`). No custom layouts are allowed; the
  layout is the contract.
- **Strict rendering.** Templates are rendered with `${name}` substitution and
  an unknown placeholder raises — no pack ships with a hole.
- **Quality gates.** A pack is accepted only when its knowledge profile, parser,
  normalizer, mission rules, tests, documentation exist and validation passes.

Scope: `src/hunterx/domain/tool_factory.py`,
`src/hunterx/domain/exceptions/factory.py`,
`src/hunterx/domain/ports/tool_factory.py` and
`src/hunterx/tools/factory/` (layout, render, templates, generators, validator,
versioning, compatibility, engine, api).

Out of scope: tool execution and the SDK runtime (Sprint 004
`docs/v7-tool-integration-sdk.md`), the tool intelligence platform (Sprint 003
`docs/v7-tool-intelligence-platform.md`), mission planning (Sprint 005
`docs/v7-mission-planning-engine.md`), and persistence adapters beyond the
repository ports and in-memory test doubles.

---

## 2. Design Goals

1. **Standardize by construction.** Every tool goes through the same factory,
   so integration quality is uniform and reviewable.
2. **Templates, not copy-paste.** Adapters, parsers, tests and docs are rendered
   from the built-in standard template; operators may register overrides by
   `template_id` while keeping the layout identical.
3. **Validate at the gate.** Naming, required files, metadata completeness,
   parser/normalizer contracts, docs, tests, mission and schema compatibility
   are all enforced by `ToolPackValidator`.
4. **Version everything.** Every pack carries semantic versioning, a declared
   compatibility matrix, migration notes and a deprecation policy.
5. **Extensible engine.** Generators are swappable and additive; the engine runs
   them in a fixed order and assembles the pack.

---

## 3. Package Overview

```
src/hunterx/
├── domain/
│   ├── tool_factory.py              # pack models, spec, manifest, semver, YAML
│   ├── exceptions/factory.py        # factory exceptions (code FACTORY)
│   └── ports/tool_factory.py        # PackTemplateRepository / ToolPackRepository
└── tools/
    └── factory/
        ├── layout.py                # PACK_LAYOUT, QUALITY_GATES, version pins
        ├── render.py                # TemplateRenderer, render_context
        ├── templates.py             # BUILTIN_TEMPLATE, PackTemplateStore
        ├── generators/              # 20 generators in engine order
        │   ├── base.py              # PackContext, PackGenerator
        │   ├── core.py              # metadata, version, knowledge, installation
        │   ├── rules.py             # execution, mission, workflow rules
        │   ├── io.py                # schemas, parser, normalizer, mappings
        │   ├── code.py              # adapter, errors, logging, telemetry
        │   └── quality.py           # boilerplate, tests, docs, validation, packaging
        ├── validator.py             # ToolPackValidator
        ├── versioning.py            # VersionResolver
        ├── compatibility.py         # CompatibilityValidator
        ├── engine.py                # ToolPackGeneratorEngine (composition root)
        └── api.py                   # ToolIntegrationFactory (facade)
```

```mermaid
flowchart TD
    API[ToolIntegrationFactory<br/>facade] --> ENG[ToolPackGeneratorEngine<br/>composition root]
    ENG --> STORE[PackTemplateStore<br/>templates]
    ENG --> RENDER[TemplateRenderer<br/>${name} substitution]
    ENG --> GEN[20 generators<br/>engine order]
    ENG --> VAL[ToolPackValidator<br/>naming/files/contracts/gates]
    ENG --> COMP[CompatibilityValidator<br/>matrix + deprecation]
    ENG --> REPO[ToolPackRepository]
    GEN --> PACK[ToolPack<br/>40+ GeneratedFile artifacts]
    VAL --> REPORT[PackValidationReport]
    API --> SERVICE[ToolFactoryService<br/>application use cases]
```

---

## 4. Domain Models

Defined in `src/hunterx/domain/tool_factory.py` (frozen, slotted dataclasses
unless noted).

### 4.1 PackArtifactKind

Classification of every generated file: `manifest`, `metadata`, `version`,
`compatibility`, `migrations`, `knowledge`, `capabilities`, `installation`,
`dependency`, `health`, `execution-rules`, `mission-rules`, `workflow-rules`,
`input-schema`, `output-schema`, `adapter`, `parser`, `normalizer`,
`database-mapping`, `evidence-mapping`, `risk-mapping`, `error-handling`,
`logging`, `telemetry`, `validation`, `unit-tests`, `integration-tests`,
`performance-tests`, `documentation`, `examples`, `packaging`, `boilerplate`.

### 4.2 SemanticVersion

A SemVer 2.0.0 value object. Supports parsing, ordering, bumping, constraint
satisfaction (`==`, `!=`, `>=`, `>`, `<=`, `<`, `~=`, `^`, bare exact) and the
compatibility rule (`0.x` shares within minor, `1.0+` within major).

### 4.3 ToolPackSpec

The declaration used to generate a pack. Validation is strict:
`pack_id`/`vendor` must match `[a-z0-9][a-z0-9-]*`, version must be valid
SemVer, permissions must be a known flag, `output_format` and
`parser_strategy` must be known, and a deprecated pack must declare a
`deprecation_reason`. Derived properties: `entrypoint`
(`hunterx_tool_packs.<vendor>.<pack_id>.adapters.adapter:<AdapterClass>`),
`adapter_class_name`, `root_path()`.

### 4.4 GeneratedFile

A single pack file: `path`, `content`, `kind`. Paths are normalized to forward
slashes; absolute or `..`-traversing paths are rejected.

### 4.5 ValidationIssue / PackValidationReport

A `ValidationIssue` is one finding (`severity`, `code`, `message`, `path`).
A `PackValidationReport` carries `issues`, `passed` (no error-level issue),
`errors`, `warnings` and a JSON-safe `to_dict()`.

### 4.6 CompatibilityEntry / CompatibilityMatrix

A `CompatibilityEntry` is one `(tool_version, hunterx_version, status, notes)`
record; a `CompatibilityMatrix` aggregates them and resolves
`status_for(tool_version, hunterx_version)` (falling back to `incompatible`).

### 4.7 ToolPackManifest

The generated `pack.yaml` manifest: `pack_id`, `vendor`, `name`, `version`,
`description`, `author`, `license`, `entrypoint`, `structure_version`,
`generator_version`, `generated_at`, `capabilities`, `targets`, `files`,
`quality_gates_passed`, `validation`. Rendered with `manifest_to_yaml`.

### 4.8 ToolPack

An immutable collection of `GeneratedFile` artifacts plus its manifest and
validation report. Rejects duplicate paths and mismatched manifest `pack_id`.
Helpers: `file(path)`, `has(path)`, `paths()`, `root_path()`, `count(kind)`,
`write_to(directory)` (writes under `directory/vendor/pack_id`).

### 4.9 IntegrationTemplate

A reusable template: `template_id`, `name`, `description`, `version`,
`structure_version`, `author`, `files`, `builtin`. The built-in `standard`
template ships with the factory; overrides merge per-path on top of it.

---

## 5. Standard Pack Layout

Defined in `src/hunterx/tools/factory/layout.py` (`PACK_LAYOUT`,
`PACK_STRUCTURE_VERSION = "1.0"`). Every pack, without exception:

```
pack.yaml                          # manifest + generated metadata
README.md                          # pack overview
pyproject.toml                     # packaging definition
MANIFEST.in                        # distribution file manifest
metadata/tool.yaml                 # tool metadata
metadata/version.yaml              # semantic version definition
metadata/compatibility.yaml        # compatibility matrix
metadata/migrations.yaml           # migration support
knowledge/knowledge_profile.yaml   # knowledge profile
knowledge/capabilities.yaml        # capabilities
install/installation.yaml          # installation definition
install/dependencies.yaml          # dependency definition
install/health_check.yaml          # health check
rules/execution.yaml               # execution rules
rules/mission.yaml                 # mission rules
rules/workflow.yaml                # workflow rules
schemas/input.json                 # input schema
schemas/output.json                # output schema
adapters/__init__.py               # adapter package marker
adapters/adapter.py                # SDK ToolAdapter
parsing/__init__.py                # parsing package marker
parsing/parser.py                  # output parser
parsing/normalizer.py              # result normalizer
mapping/database.yaml              # database mapping
mapping/evidence.yaml              # evidence mapping
mapping/risk.yaml                  # risk mapping
runtime/__init__.py                # runtime package marker
runtime/errors.py                  # typed error handling
runtime/logging.py                 # module logging
runtime/telemetry.py               # runtime telemetry
validation/rules.yaml              # validation rules
tests/__init__.py                  # tests package marker
tests/test_unit.py                 # unit tests
tests/test_integration.py          # integration tests
tests/test_performance.py          # performance tests
docs/developer.md                  # developer guide
docs/integration.md                # integration guide
docs/architecture.md               # architecture guide
docs/lifecycle.md                  # lifecycle guide
docs/examples.md                   # examples
```

### Quality gates

No pack is accepted unless all 19 `QUALITY_GATES` exist and validation passes:
`pack.yaml`, `metadata/version.yaml`, `knowledge/knowledge_profile.yaml`,
`knowledge/capabilities.yaml`, `install/health_check.yaml`,
`rules/execution.yaml`, `rules/mission.yaml`, `schemas/input.json`,
`schemas/output.json`, `adapters/adapter.py`, `parsing/parser.py`,
`parsing/normalizer.py`, `mapping/database.yaml`, `validation/rules.yaml`,
`tests/test_unit.py`, `tests/test_integration.py`, `tests/test_performance.py`,
`docs/developer.md`, `docs/integration.md`.

---

## 6. Generator Engine

`ToolPackGeneratorEngine` (composition root) runs 20 generators in a fixed
order and assembles the pack:

1. `boilerplate` — package markers (`__init__.py`).
2. `metadata` — `metadata/tool.yaml`.
3. `version-metadata` — version, compatibility matrix, migrations.
4. `knowledge` — knowledge profile and capabilities.
5. `installation` — installation, dependencies, health check.
6. `execution-rules` — permissions, sandbox, retry, resource limits.
7. `mission-rules` — mission profiles, targets, capabilities, approvals.
8. `workflow-rules` — stages, parallelism, fallbacks, approvals.
9. `schemas` — input/output JSON Schemas.
10. `parser` — parser skeleton.
11. `normalizer` — normalizer skeleton.
12. `database-mapping` — database, evidence, risk mappings.
13. `adapter` — SDK `ToolAdapter` skeleton.
14. `error-handling` — typed errors.
15. `logging` — pack logger.
16. `telemetry` — runtime telemetry.
17. `tests` — unit/integration/performance test skeletons.
18. `documentation` — developer/integration/architecture/lifecycle guides.
19. `validation` — validation rules record.
20. `packaging` — `pyproject.toml`, `README.md`, `MANIFEST.in`.

The engine renders template files through `TemplateRenderer`, sorts artifacts,
builds the `pack.yaml` manifest (including its own path), validates the pack,
and rebuilds the manifest with the final report before persisting through an
optional `ToolPackRepository`.

The generated `adapters/adapter.py` conforms to the Sprint 004 SDK contract:
a `ToolAdapter` subclass with a `descriptor` (`ToolDescriptor` from
`hunterx.domain.tools`) and an abstract `run(context, collector)`.

---

## 7. Validation

`ToolPackValidator` checks, in order:

| Check | Error codes |
| --- | --- |
| Naming (`pack_id`, `vendor`, file paths, entrypoint `module:Class`) | `NAMING_*` |
| Required files (every `PACK_LAYOUT` path) | `REQUIRED_FILE` |
| Metadata completeness (tool_id/vendor/version, semver, knowledge keys) | `METADATA_*`, `VERSION_INVALID`, `KNOWLEDGE_*` |
| Parser/normalizer contracts | `PARSER_*`, `NORMALIZER_*` |
| Documentation completeness | `DOCS_MISSING` |
| Test availability | `TESTS_MISSING` |
| Mission compatibility | `MISSION_RULES_*` |
| Schema compatibility (JSON Schema shape, `findings` property) | `SCHEMA_*` |
| Quality gates | `QUALITY_GATE` |

A pack with any error-level issue is rejected; `passed` is `True` only when no
error-level issue exists. `ToolIntegrationFactory.assert_acceptable` raises
`PackValidationError` when a pack fails the gates.

---

## 8. Versioning & Compatibility

- **`VersionResolver`** — semantic sort, `latest`, constraint satisfaction,
  stability, deprecation plan.
- **`CompatibilityValidator`** — builds the declared matrix from
  `spec.hunterx_versions` (defaulting to the supported set), checks a tool
  against a HunterX version under the SemVer rule, and reports
  `compatible` / `deprecated` / `incompatible`. A deprecated pack is never
  compatible.

Every pack's `metadata/version.yaml` carries `semver`, `major/minor/patch`,
`prerelease`, `build`, a `compatibility_rule` (`same-major` for `1.0+`,
`same-minor` for `0.x`) and a `deprecation` block; `metadata/migrations.yaml`
records the deprecation and migration policy.

---

## 9. Application Service

`src/hunterx/application/tool_factory.py` exposes `ToolFactoryService`, a
framework-agnostic use-case facade over `ToolIntegrationFactory`:
`generate`, `generate_and_validate`, `validate`, `accept`,
`require_acceptable`, `register_template`, `list_templates`, `pack_layout`,
`required_files`, `quality_gates`, `compatibility_matrix`, `list_packs`,
`get_pack`, `delete_pack`.

---

## 10. Developer Integration Guide

### Generating a pack

```python
from hunterx.domain.tool_factory import ToolPackSpec
from hunterx.tools import ToolIntegrationFactory

factory = ToolIntegrationFactory()
spec = ToolPackSpec(
    pack_id="nmap",
    vendor="acme",
    tool_name="nmap",
    display_name="Nmap",
    description="Network mapper",
    capabilities=("port-scanning", "service-fingerprint"),
    targets=("host", "range"),
    permissions=("network",),
    mission_profiles=("external-pentest", "internal-pentest"),
)
result = factory.generate_and_validate(spec)
if result.ok:
    pack = result.value
    pack.write_to("./generated")   # -> ./generated/acme/nmap/<40 files>
```

### Customizing boilerplate with a template override

```python
from hunterx.domain.tool_factory import IntegrationTemplate
factory.register_template(IntegrationTemplate(
    template_id="enterprise",
    name="Enterprise boilerplate",
    files={"README.md": "Proprietary ${display_name} pack — ${vendor}."},
))
spec = ToolPackSpec(..., template_id="enterprise")
```

### In-memory wiring for tests / development

```python
from tests.framework.tool_factory import make_factory

factory = make_factory()   # ToolIntegrationFactory over in-memory repos
```

---

## 11. Testing

- `tests/framework/tool_factory.py` — in-memory `PackTemplateRepository` /
  `ToolPackRepository` doubles and `make_factory()`.
- `tests/unit/test_tool_factory_models.py` — spec validation, semver, YAML.
- `tests/unit/test_tool_factory_render.py` — renderer, layout, template store.
- `tests/unit/test_tool_factory_versioning.py` — version resolver, compatibility.
- `tests/unit/test_tool_factory_generators.py` — every generator's output.
- `tests/unit/test_tool_factory_validator.py` — each validation check.
- `tests/unit/test_tool_factory_engine.py` — engine, facade, service, disk write.

---

## 12. References

- `docs/v7-foundation.md` — Sprint 001 module reference.
- `docs/v7-tool-intelligence-platform.md` — Sprint 003 (TIP knowledge plane).
- `docs/v7-tool-integration-sdk.md` — Sprint 004 (SDK contract packs conform to).
- `docs/v7-mission-planning-engine.md` — Sprint 005 (mission planning).
- `src/hunterx/tools/factory/` — implementation.
