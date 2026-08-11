---
layout: default
title: HunterX Quality Gates Reference
description: >-
  The HunterX quality gate catalog: ruff, mypy, pytest, coverage, architecture,
  deadcode, dependencies, docs, security, performance, compliance, hygiene,
  packaging and git-diff. Thresholds, statuses and configuration.
permalink: /v7-quality-gates/
---

# HunterX Quality Gates Reference

**Status:** Ratified (Sprint 006.9)
**Version:** 1.0.0
**Owner:** HunterX Engineering Council

---

## 1. Purpose / Scope

This document is the reference for every quality gate in the HunterX platform.
It defines what each gate checks, how it is configured, and how to interpret
its result. The gates are orchestrated by `eng.gates.GateRunner` and declared in
`eng/config/gates.yaml`. The CI wiring is described in
[v7-cicd-architecture.md](v7-cicd-architecture.md); the security gate is
expanded in [v7-security-pipeline.md](v7-security-pipeline.md).

A gate is a function `(runner, repo_root, spec) -> GateResult` registered in
`eng.gates.checks.default_checks()`. Every gate in `gates.yaml` defaults to
`mandatory: true`; a mandatory `FAIL` or `ERROR` raises
`eng.gates.GateBlockedError` and blocks the merge.

---

## 2. Gate Configuration

Configuration lives in `eng/config/gates.yaml`:

```yaml
gates:
  - name: coverage
    mandatory: true
    threshold: 80.0
  - name: performance
    mandatory: true
    threshold: 20.0
```

`mandatory` controls blocking; `threshold` is a per-gate numeric setting (a
coverage percentage, a performance drift percentage, a slow-test cutoff).
Optional gates (`packaging`, `git-diff`) never block.

Run the gates:

```bash
python -m eng gates                # full suite
python -m eng gates --gate ruff mypy
python -m eng gates --json         # artifacts/gates-report.json
```

---

## 3. Status Model

| Status | Meaning | Blocks? |
|---|---|---|
| `PASS` | Subject validated | no |
| `FAIL` | Problem found | yes, if mandatory |
| `ERROR` | Gate could not execute | yes, if mandatory |
| `SKIPPED` | Not applicable / tool absent (graceful degradation) | no |

---

## 4. Gate Catalog

### 4.1 ruff

Lints the v7 source tree, the engineering platform, tests, Alembic migrations
and the legacy-excluded configuration. `_SRC = ("src", "eng")` and the `tests/`
tree are the linted targets; the retired v6 flat `hunterx/` package is
deliberately excluded (documented technical debt). Command:

```bash
ruff check src tests eng alembic
ruff format --check src tests eng alembic
```

A violation or an unformatted file fails the gate.

### 4.2 mypy

Runs `mypy` in strict mode over the type-checked surface:

```bash
mypy eng src/hunterx/shared
```

The engineering platform and the shared kernel (including the dependency
injection container in `src/hunterx/shared/di.py`) are kept strict-clean. The
remaining v7 source is type-checked incrementally as Capability Waves land; the
retired v6 flat package is excluded. When the full v7 tree reaches strict-clean,
the target SHOULD be widened to `mypy --no-warn-unused-ignores src eng`.

### 4.3 pytest

Runs the full test suite:

```bash
pytest -q --no-cov -m "not tools" tests/
```

The `tools` marker excludes tests that require live external security tools by
default; they are executed by the dedicated `security-tests.yml` workflow.

### 4.4 coverage

Runs pytest under coverage and enforces a configurable threshold (default
`80.0`):

```bash
pytest -q --cov hunterx --cov-report xml:artifacts/coverage.xml
```

The Cobertura report is uploaded by CI. Coverage below the threshold fails the
gate. Coverage configuration lives in `[tool.coverage.*]` in `pyproject.toml`.

### 4.5 architecture

Enforces the v7 Clean Architecture dependency rule: Delivery → Application →
Domain, with Infrastructure implementing domain ports injected at composition
time. Violations of layer boundaries fail the gate.

### 4.6 deadcode

Runs `vulture` over the source with `config/vulture_allowlist.py` supplying
whitelists for entry points (`main`, `register`, `create_adapter`,
`build_container`, `render_template`, `__version__`). Entry points and library
names are whitelisted, true dead code is not.

### 4.7 dependencies

Validates that `requirements.lock` is consistent with the dependencies declared
in `pyproject.toml` (`eng.supplychain.parse_requirements`). Drift between the
declared and locked sets fails the gate. The audit of *known vulnerabilities*
is handled by the security pipeline's `pip-audit` and `safety` scans.

### 4.8 docs

Runs `eng.docs.validate_docs`: required root files, required sections, the
DevSecOps engineering documents and their mandated anchors, internal markdown
link resolution, balanced fenced blocks and trailing-whitespace hygiene.
Produces `artifacts/docs-report.json`.

### 4.9 security

Runs the full security pipeline (see
[v7-security-pipeline.md](v7-security-pipeline.md)): bandit, semgrep, gitleaks,
pip-audit, safety, and trivy filesystem/image scans. Aggregates into
`artifacts/security-report.json`. Missing scanners are *skipped*, not failed.

### 4.10 performance

Runs the benchmark suite (`tests/performance`) with `pytest-benchmark`,
normalizes results to `artifacts/benchmarks/latest.json` and compares against
`baseline.json`. Drift beyond `threshold` (default `20.0` percent) fails the
gate. The `--durations` summary catches slow tests (default cutoff `10s`).
On the first run a baseline is recorded and the gate passes.

```bash
python -m eng gates --gate performance
```

### 4.11 compliance

Verifies `LICENSE`, `NOTICE`, `THIRD_PARTY_NOTICES` and the license allow-list
(`eng.supplychain.check_licenses`, `_ALLOWED_LICENSES`). Disallowed licenses,
missing attribution or missing license files fail the gate.

### 4.12 hygiene

Verifies repository hygiene: `SECURITY.md`, `CONTRIBUTING.md`,
`CODE_OF_CONDUCT.md`, `.github/CODEOWNERS`, `.github/dependabot.yml`, the issue
templates and the pull-request template.

### 4.13 packaging (optional)

Builds the wheel and sdist (`python -m build`) and validates them
(`eng.packaging.validate_packaging`). Optional by default; enable it when a
release build is part of the workflow.

### 4.14 git-diff (optional)

Fails when the working tree has uncommitted changes (`git status --porcelain`).
Used as a reproducibility gate on release runs; optional so developers can run
the suite mid-work.

---

## 5. Adding or Tuning a Gate

1. Declare the gate in `eng/config/gates.yaml` (name, mandatory, threshold).
2. Implement the checker in `eng.gates.checks` with the uniform signature.
3. Register it in `default_checks()`.
4. Add a test under `tests/engineering/test_checks.py`.
5. Document the gate in §4 of this document.

Thresholds are tunable without code changes — they live in YAML. The blocking
semantics are driven entirely by `mandatory`.
