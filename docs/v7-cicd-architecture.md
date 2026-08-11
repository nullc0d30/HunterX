---
layout: default
title: HunterX CI/CD Architecture
description: >-
  The HunterX GitHub Actions CI/CD architecture: workflow inventory, the
  blocking quality-gate job, artifact flow, and the tag-triggered release
  pipeline.
permalink: /v7-cicd-architecture/
---

# HunterX CI/CD Architecture

**Status:** Ratified (Sprint 006.9)
**Version:** 1.0.0
**Owner:** HunterX Engineering Council

---

## 1. Purpose / Scope

This document describes the GitHub Actions CI/CD topology that enforces the
HunterX DevSecOps platform ([v7-devsecops.md](v7-devsecops.md)). It is the
map: which workflow runs when, what it gates, and how the pieces connect.

The workflows live in `.github/workflows/`. The reusable engine they invoke is
the `eng` package (`python -m eng ...`), documented in
[v7-quality-gates.md](v7-quality-gates.md) and
[v7-security-pipeline.md](v7-security-pipeline.md).

---

## 2. Workflow Inventory

| Workflow | Trigger | Responsibility |
|---|---|---|
| `ci.yml` | push to `main`, PR to `main` | **Blocking** quality gates + PR summary comment |
| `unit-tests.yml` | PR / push | Unit test suite (fast feedback) |
| `integration-tests.yml` | PR / push | Integration tests against real services |
| `architecture-tests.yml` | PR / push | Architecture layer/dependency rules |
| `performance-tests.yml` | PR / push | Benchmark suite + regression check |
| `security-tests.yml` | PR / push | Security pipeline scans |
| `docs-validation.yml` | PR / push | Documentation health gate |
| `packaging-validation.yml` | PR / push | Wheel/sdist build + import smoke |
| `build.yml` | push to `main` | Build distribution artifacts |
| `dependency-review.yml` | PR | Changed-dependency license/known-vuln review |
| `compliance.yml` | PR / push | License + attribution + hygiene |
| `sbom.yml` | push to `main` | Generate + store SBOMs |
| `cosign-sign.yml` | release tags | Sign release artifacts |
| `readiness.yml` | push to `main` | Readiness assessment + Pages deploy |
| `test.yml` | PR / push | Delegates to the eng gate suite |

---

## 3. The Blocking Quality-Gate Workflow (`ci.yml`)

`ci.yml` is the merge gatekeeper. On every push to `main` and every pull request
it runs a single job, `quality-gates`:

1. Checkout the repository.
2. Set up Python 3.11 with pip cache keyed on `pyproject.toml` and
   `requirements.lock`.
3. Install the project with the `dev` and `report` extras plus the scanner
   toolchain (mypy, vulture, bandit, pip-audit, safety, semgrep, twine,
   cyclonedx-py, pip-licenses).
4. Run `python -m eng gates --json` with `continue-on-error: true` so the full
   report is produced even on failure.
5. Upload gate artifacts (`coverage.xml`, docs report, security report,
   readiness, benchmarks) unconditionally.
6. **Enforce:** if the gates step failed, the workflow exits non-zero, blocking
   the merge.
7. **Report:** on pull requests, post a Quality Gates Summary comment built from
   `artifacts/gates-report.json`.

### Why `continue-on-error` + explicit enforcement?

Two-step enforcement means a single gate failure still produces every other
gate's result and all artifacts — so the PR comment shows the complete state
and the developer fixes everything in one round instead of many.

---

## 4. Artifact Flow

All pipeline outputs land under `artifacts/`:

```text
artifacts/
  gates-report.json     <- per-gate status (PR comment source)
  coverage.xml          <- Cobertura coverage report
  docs-report.json      <- documentation health
  security-report.json  <- aggregated scanner report
  security/             <- raw scanner output (bandit, semgrep, trivy, ...)
  benchmarks/           <- raw + normalized benchmark JSON, baseline
  readiness.json        <- readiness assessment
  hunterx.spdx.json     <- SPDX SBOM (release)
  hunterx.bom.json      <- CycloneDX SBOM (release)
  provenance.json       <- provenance manifest (release)
```

`actions/upload-artifact` persists these across jobs and runs for audit.

---

## 5. The Release Pipeline (tag-triggered)

A tag push (e.g. `v7.1.0`) triggers the full release pipeline (previously the
standalone `release.yml`):

1. **Validate the tag** — `python -m eng check-release <version>` enforces
   [semantic versioning](v7-release-guide.md#semantic-versioning).
2. **Build** — `python -m build` produces the wheel and sdist.
3. **SBOM** — CycloneDX and SPDX SBOMs are generated from the lock file.
4. **Checksums** — SHA256 and SHA512 checksum files for every artifact.
5. **Provenance** — `eng.supplychain.write_provenance` records version, commit,
   build date and artifact list.
6. **Sign** — `cosign sign-blob` signs each artifact (`.sig` + `.pem`).
7. **Release notes** — changelog entries are parsed with
   `eng.release.parse_changelog` and rendered by `render_release_notes`.
8. **Publish** — `softprops/action-gh-release` creates the GitHub Release with
   the release-notes body; `fail_on_unmatched_files: true` guarantees every
   declared artifact was uploaded.

The full procedure is in [v7-release-guide.md](v7-release-guide.md).

---

## 6. Security Considerations

- `permissions:` blocks are set to least privilege per job (`contents: read`,
  `security-events: write`, `pull-requests: write`).
- `actions/checkout@v4` and `actions/setup-python@v5` are pinned by tag.
- Secrets are never written to artifacts; scanner outputs are redacted.
- Third-party actions are held to the minimum required permission set.

---

## 7. Adding a Workflow

New workflows MUST delegate to the `eng` platform rather than re-implement
checks inline, so thresholds and behavior stay consistent. Add the workflow
under `.github/workflows/`, document it in the table in §2, and keep the
artifact contract in §4.
