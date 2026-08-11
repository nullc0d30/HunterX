---
layout: default
title: Developer Guide — Architecture Enforcement
description: >-
  How to use hunterx-arch day to day: commands, CI and pre-commit integration,
  adding modules, API stability baseline, and resolving violations.
permalink: /architecture/developer-guide/
---

# Developer Guide — Architecture Enforcement

**Status:** Ratified (Sprint 006.7)
**Version:** 1.0.0
**Owner:** HunterX Architecture Council

## Install

The `hunterx-arch` console script ships with the package:

```bash
pip install -e ".[all]"
hunterx-arch --version
```

The linter is also usable as a library:

```python
from hunterx.architecture.lint import LintOptions, run_lint

report = run_lint(options=LintOptions(repo_root=repo_root))
print(report.health)   # e.g. 85.0
print(report.clean)    # False if any error-grade violation exists
```

## Commands

| Command | Purpose | Exit code |
|---|---|---|
| `hunterx-arch lint` | Run every check against the repo | `0` clean, `1` violations, `2` usage error |
| `hunterx-arch lint --format json` | Machine-readable output | same |
| `hunterx-arch report` | Write `architecture-report.md` (health score, issues, Mermaid graph) | `0` unless report has violations |
| `hunterx-arch matrix` | Print the dependency matrix | `0` |
| `hunterx-arch graph` | Emit the layer diagram as Mermaid | `0` |
| `hunterx-arch stability` | Diff the public API against `config/api_baseline.json` | `0` no breakage, `1` breaking changes |
| `hunterx-arch stability --generate` | Regenerate the baseline (run with care) | `0` |

All commands accept `--root <repo>` and `--policy <path>` before or after the
subcommand.

## Where enforcement runs

1. **Editor** — any IDE hook on save can run `hunterx-arch lint`.
2. **Pre-commit** — the `architecture-lint` hook in `.pre-commit-config.yaml`
   runs `hunterx-arch lint --root .` (needs the package installed).
3. **CI** — the `Test` workflow (`.github/workflows/test.yml`) runs
   `hunterx-arch lint` on every push/PR to `main`/`master`, after ruff and
   before pytest. A violation fails the build.

The `tests/architecture/test_codebase_conformance.py` suite additionally runs
the real linter against the live source tree in CI, so a regression in the
framework itself fails the build too.

## Adding a new module

1. Place it under the layer's `src/hunterx/<layer>/` prefix (see
   [Dependency Matrix & Layer Rules](dependency-matrix.md)).
2. Import only what the matrix allows — check with `hunterx-arch lint`.
3. Give every new package `__init__.py` a docstring with a
   *Responsibilities* section (ARCH-007 warns otherwise).
4. Do not introduce cycles: `__init__.py` files must stay re-export-only.

## Reading a violation

```
ARCH-001 (error): hunterx.application.foo imports hunterx.agents.bar
  The 'application' layer may not depend on the 'agents' layer.
  Allowed: application -> [application, domain, shared, engines, tools].
  Fix: invert the dependency or move the type to a shared/domain contract.
```

Every code has a concrete remediation in `src/hunterx/architecture/violations.py`.
Codes: ARCH-001 matrix, ARCH-002 forbidden imports, ARCH-003 cycles,
ARCH-004 plugin boundary, ARCH-005 tool boundary, ARCH-007 package docstrings,
ARCH-009 API stability, ARCH-011 expired waiver.

## Working with the API baseline

`config/api_baseline.json` snapshots the public surface of every
`src/hunterx` module (classes, functions, constants, signatures).

- You must **not** delete or rename a public symbol without an approved
  breaking-change; CI fails (ARCH-009).
- Adding new public symbols is fine — extend the baseline with:
  `hunterx-arch stability --generate`, then commit the refreshed JSON.
- Use `hunterx-arch stability` locally to see exactly what changed before
  committing.

## Exceptions to the rules

The framework deliberately has **no silent escapes**. Every exception is
visible:

- **Conditional imports** — narrow, module-level allowances in
  `config/architecture.yaml` (e.g. DI raising domain exceptions).
- **Waivers** — documented, time-boxed known issues (e.g. ARCH-W-001). They
  show in reports and fail CI once expired.

To request either, open an issue for the Architecture Council; do not edit the
YAML unilaterally.
