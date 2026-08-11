---
layout: default
title: HunterX Architecture Enforcement Framework
description: >-
  Developer-facing documentation for the HunterX v7 Architecture Enforcement
  Framework (hunterx-arch): layer rules, dependency matrix, CI integration and
  the developer workflow.
permalink: /architecture/
---

# HunterX Architecture Enforcement Framework

**Status:** Ratified (Sprint 006.7)
**Version:** 1.0.0
**Owner:** HunterX Architecture Council

The Architecture Enforcement Framework encodes the ratified Clean Architecture
rules from the Development Bible (`docs/bible/02 - Architecture.md`,
`docs/bible/03 - Folder Structure.md`) as machine-checked, automatic validation.
It catches boundary violations, forbidden imports and new dependency cycles at
the earliest point in the workflow: the editor, the pre-commit hook, and CI.

This is **enforcement only**. It introduces no business logic and changes no
mission behavior. Violations are reported, never silently fixed.

## What it enforces

| Check | Code | Fails CI? | Description |
|---|---|---|---|
| Dependency matrix | ARCH-001 | Yes | A module imports a layer its layer is not allowed to reach |
| Forbidden imports | ARCH-002 | Yes | Matches a forbidden pattern (legacy `core.*`, `scripts.*`, ...) |
| Dependency cycles | ARCH-003 | Yes | A new module-level import cycle (Tarjan SCC) |
| Plugin boundary | ARCH-004 | Yes | A plugin imports something outside the public plugin SDK |
| Tool boundary | ARCH-005 | Yes | A tool adapter imports something outside the tool SDK |
| Package docstring | ARCH-007 | No | A package `__init__.py` lacks a docstring / recommended sections |
| Stability baseline | ARCH-009 | Yes | Public API changed vs `config/api_baseline.json` |
| Expired waiver | ARCH-011 | Yes | A recorded waiver outlived its deadline |

Layering, import scanning, cycle detection, API snapshots and report rendering
all live in `src/hunterx/architecture/`. The policy itself is **data**, not
code: `config/architecture.yaml` is the single source of truth for every rule.

## Quick start

```bash
pip install -e ".[all]"          # installs the hunterx-arch console script

hunterx-arch lint                # run every check; exit 1 on violations
hunterx-arch report              # write architecture-report.md (health score)
hunterx-arch matrix              # print the dependency matrix
hunterx-arch graph               # Mermaid layer diagram
hunterx-arch stability --generate  # refresh config/api_baseline.json
```

## Guides

- [Dependency Matrix & Layer Rules](dependency-matrix.md) — the ratified
  matrix, what every layer may import, and the documented exceptions.
- [Developer Guide](developer-guide.md) — commands, CI / pre-commit
  integration, and how to add modules, waivers and API baseline entries.

## Architecture

```
src/hunterx/architecture/
├── __init__.py       package (v1.0.0)
├── layers.py         layer definitions + module→layer resolution
├── imports.py        AST import scanning
├── cycles.py         Tarjan SCC cycle detection
├── violations.py     violation codes + remediation guidance
├── policy.py         YAML policy loading, default policy
├── docs.py           documentation validation (ARCH-007)
├── stability.py      public API snapshot / diff vs baseline
├── report.py         report model, health score, renderers
├── lint.py           the linter orchestrating every validator
├── cli.py            hunterx-arch command line
└── __main__.py       python -m hunterx.architecture
```

## Governance

The matrix, waivers and known cycles in `config/architecture.yaml` may only be
changed by the Architecture Council. Waivers are temporary by design: every
waiver SHALL carry a deadline and SHALL fail CI once it expires
(`ARCH-011`).
