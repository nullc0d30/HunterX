---
layout: default
title: HunterX DevSecOps Platform — Sprint 006.9
description: >-
  The HunterX Production Readiness & Release Engineering platform: DevSecOps
  CI/CD, mandatory quality gates, security pipeline, supply-chain security,
  release engineering, compliance and automated readiness assessment.
permalink: /v7-devsecops/
---

# HunterX DevSecOps Platform

**Status:** Ratified (Sprint 006.9)
**Version:** 1.0.0
**Owner:** HunterX Engineering Council

---

## 1. Purpose / Scope

This document is the reference for the HunterX **production engineering
platform** implemented in the root-level `eng/` package. It does not ship in the
distribution; it is the engineering substrate that keeps the shipped product
safe to release. It covers:

- The DevSecOps principles and threat model this platform enforces.
- The quality gate system and how a gate failure blocks a merge.
- The security pipeline and its graceful-degradation contract.
- Supply-chain security (SBOM, provenance, license allow-list).
- Release engineering (semantic versions, changelog, rollback plans).
- Compliance, repository hygiene, and automated readiness assessment.

Out of scope: security *capabilities* of the shipped product, Recon tool
integration, and Mission logic — those belong to Capability Wave sprints that
follow this foundation.

---

## 2. Principles

1. **Fail closed on release, fail open on tooling.** A failing mandatory quality
   gate blocks the merge and the release. A missing optional scanner is reported
   as *skipped* and does not block the pipeline.
2. **Everything mandatory is explicit.** Every gate lists `mandatory: true` in
   `eng/config/gates.yaml`. There is no silent opt-out.
3. **Artifacts are deterministic and inspectable.** Every pipeline writes JSON
   under `artifacts/` that humans and bots can audit.
4. **Documentation is a deliverable, not a nicety.** The docs gate fails when the
   engineering documentation is missing a mandated section.
5. **Security is a quality gate.** Static analysis, dependency scanning, secret
   detection and SBOM generation run on every CI push, not just at release time.

---

## 3. The Quality Gate System

The quality gate system is the heart of the platform. Every gate is a function
with the uniform signature `(runner, repo_root, spec) -> GateResult` defined in
`eng/gates/checks.py`, driven by `eng.gates.GateRunner` and configured in
`eng/config/gates.yaml`.

Gates run via `eng.tooling.ToolRunner`, a subprocess wrapper that is injectable
in tests. `GateRunner.run_blocking()` raises `eng.gates.GateBlockedError` when a
mandatory gate fails, which the CI workflow treats as a merge blocker.

The full gate catalog is documented in [v7-quality-gates.md](v7-quality-gates.md).
The CI wiring is documented in [v7-cicd-architecture.md](v7-cicd-architecture.md).

### Invocation

```bash
python -m eng gates              # run all configured gates
python -m eng gates --gate mypy  # run a subset
python -m eng gates --json       # write artifacts/gates-report.json
python -m eng gates --blocking   # exit 1 when a mandatory gate fails
```

### Gate Status Model

| Status | Meaning |
|---|---|
| `PASS` | The gate validated its subject. |
| `FAIL` | The gate found a problem; mandatory gates block the merge. |
| `ERROR` | The gate could not execute (e.g. a tool is missing); treated as a block. |
| `SKIPPED` | The gate was configured non-mandatory or its subject does not apply. |

---

## 4. The Security Pipeline

The security pipeline (`eng/security.py`, invoked via `python -m eng security`)
runs a battery of scanners and aggregates their findings into a single report
(`artifacts/security-report.json`). It is described in full in
[v7-security-pipeline.md](v7-security-pipeline.md).

Design contract: **missing scanners degrade gracefully**. When a scanner binary
is not installed, the corresponding scan is reported as *skipped* — it never
fails the pipeline. Scans that target artifacts that do not exist yet (for
example the container image before it is published) use
`skip_failures_containing` to recognize the expected "not found" failure and
report it as skipped rather than blocking CI.

---

## 5. Supply-Chain Security

`eng/supplychain.py` produces supply-chain artifacts and enforces policy:

- `generate_sbom()` — CycloneDX 1.5 SBOM from the lock file.
- `generate_sbom_spdx()` — SPDX 2.3 JSON SBOM.
- `check_licenses()` — enforces the SPDX allow-list in `_ALLOWED_LICENSES`.
- `write_provenance()` — a provenance manifest recording version, commit, build
  date and the artifact set.

Run with `python -m eng sbom [--format cyclonedx|spdx]`. The release workflow
signs the SBOM and checksums with cosign; see
[v7-release-guide.md](v7-release-guide.md).

---

## 6. Compliance and Repository Hygiene

The `compliance` and `hygiene` gates are mandatory. Compliance verifies
`LICENSE`, `NOTICE`, `THIRD_PARTY_NOTICES` and the license allow-list. Hygiene
verifies `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `.github/
CODEOWNERS`, `.github/dependabot.yml`, issue templates and the pull-request
template. Run locally with `python -m eng compliance`.

---

## 7. Readiness Assessment

`python -m eng readiness` (`eng/readiness.py`) computes a weighted readiness
score across architecture, security, quality, coverage, documentation,
dependencies, release and performance, and reports technical debt. The CI
`readiness` workflow publishes the assessment as a Pages site.

---

## 8. Operational Ownership

- **Gate configuration:** `eng/config/gates.yaml`
- **CI orchestration:** `.github/workflows/ci.yml` (blocking)
- **Engineering docs:** `docs/v7-*.md`
- **Reporting artifacts:** `artifacts/`
