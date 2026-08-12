---
layout: default
title: HunterX Release Guide
description: >-
  The HunterX release procedure: semantic versioning, changelog maintenance,
  the tag-triggered pipeline, checksums, provenance, cosign signing, release
  notes and rollback plans.
permalink: /v7-release-guide/
---

# HunterX Release Guide

**Status:** Ratified (Sprint 006.9)
**Version:** 1.0.0
**Owner:** HunterX Engineering Council

---

## 1. Purpose / Scope

This document is the operating manual for producing a HunterX release. It
covers the versioning rules, the changelog discipline, the tag-triggered
release pipeline, and the verification steps (checksums, provenance, signing,
rollback). The CI topology that runs this pipeline is described in
[v7-cicd-architecture.md](v7-cicd-architecture.md).

---

## 2. Semantic Versioning

HunterX follows **Semantic Versioning** (SemVer 2.0.0), enforced by
`eng.release`:

- **MAJOR** — incompatible API changes.
- **MINOR** — backwards-compatible feature additions.
- **PATCH** — backwards-compatible bug fixes.
- **Prerelease** — `-rc.1`, `-beta.2` etc. Precedence is computed per the SemVer
  spec (numeric identifiers compare numerically).

`eng.release.parse_version` and `eng.release.is_valid_version` implement the
grammar; `eng.release.suggest_bump` derives the next bump from conventional
commit messages:

```python
from eng.release import suggest_bump

suggest_bump(["feat!: drop v6 compat"])      # -> "major"
suggest_bump(["feat: add tool registry"])    # -> "minor"
suggest_bump(["fix: pagination bug"])        # -> "patch"
```

Validate any candidate tag locally:

```bash
python -m eng check-release 7.1.0
python -m eng check-release 7.1.0 --json
```

The release workflow refuses a tag that is not a valid semantic version.

---

## 3. Changelog Discipline

The changelog (`CHANGELOG.md`) follows Keep-a-Changelog conventions. Entries are
parsed by `eng.release.parse_changelog` (sections headed `## [version] — date`)
and rendered into release notes by `eng.release.render_release_notes`:

```python
from eng.release import parse_changelog, render_release_notes

entries = parse_changelog(changelog_text)
notes = render_release_notes(entries, "7.1.0")
```

Rules:

- Every user-visible change MUST have a changelog entry.
- `[Unreleased]` is maintained during development and renamed on release.
- Each release entry carries an ISO date and a markdown body.

---

## 4. Release Pipeline (tag-triggered)

Pushing a tag such as `v7.1.0` runs the release workflow. The pipeline:

1. **Validate the tag** — `python -m eng check-release <version>`.
2. **Build** — `python -m build` produces `dist/hunterx-<version>-py3-none-any.whl`
   and `dist/hunterx-<version>.tar.gz`.
3. **SBOM** — CycloneDX (`artifacts/hunterx.bom.json`) and SPDX
   (`artifacts/hunterx.spdx.json`) SBOMs generated from the lock file.
4. **Checksums** — `eng.release.generate_checksums` writes `SHA256SUMS.txt`
   (and a SHA-512 variant) for every artifact.
5. **Provenance** — `eng.supplychain.write_provenance` records version, commit,
   build date and artifact list in `artifacts/provenance.json`.
6. **Sign** — `cosign sign-blob` signs each artifact, producing `.sig` and
   `.pem` sidecars.
7. **Release notes** — rendered from the changelog entry for the tag.
8. **Publish** — a GitHub Release is created with the release-notes body and
   every artifact attached; `fail_on_unmatched_files: true` guarantees no
   declared artifact is silently missing.

### Artifact set

```text
dist/hunterx-<version>-py3-none-any.whl
dist/hunterx-<version>.tar.gz
artifacts/hunterx.bom.json
artifacts/hunterx.spdx.json
artifacts/provenance.json
SHA256SUMS.txt
SHA512SUMS.txt
<each artifact>.sig + .pem   (cosign signatures)
```

---

## 5. Checksum Verification

`eng.release.verify_checksums` verifies a `SHA256SUMS.txt` file and raises on
any mismatch or missing artifact:

```python
from eng.release import verify_checksums

verify_checksums(release_dir)  # raises FileNotFoundError / ValueError on bad state
```

`sha256_file` computes a chunked SHA-256 digest and is the primitive behind
`generate_checksums`.

---

## 6. Rollback Plan

`eng.release.build_rollback_plan` produces a documented rollback strategy for
any release, defaulting to the previous patch:

```python
from eng.release import build_rollback_plan, parse_version

plan = build_rollback_plan(parse_version("7.1.0"))
plan.previous_version  # -> "7.1.0" target minus a bump, e.g. "7.0.1"
plan.image_tag         # -> "nullc0d30/hunterx:7.0.1"
plan.package_version   # -> "hunterxsec==7.0.1"
```

The release workflow fails a tag that cannot produce a rollback plan, so every
release ships knowing exactly how to roll back. DB migrations are called out in
`migration_notes` when a data migration is involved.

---

## 7. Release Checklist

1. Changelog updated with the release entry.
2. `python -m eng gates` green locally (all mandatory gates pass).
3. `python -m eng compliance` and `python -m eng readiness` green.
4. Tag pushed (`vX.Y.Z`); pipeline validates the semantic version.
5. Artifacts, SBOMs, checksums, provenance and signatures attached to the
   GitHub Release.
6. Rollback plan reviewed (`python -m eng check-release <version> --json`).

---

## 8. Definitions of Done

A release is Done when every step in §4 completes and the GitHub Release
contains the full artifact set, the SBOMs, the checksums, the provenance
manifest, and cosign signatures — with a validated semantic version and a
changelog-driven release body.
