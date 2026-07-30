# Release Checklist

This document outlines the steps required to publish a new HunterX release.

---

## Pre-Release

- [ ] All planned features for this release are implemented and merged to `main`
- [ ] All tests pass: `pytest tests/ -v`
- [ ] Linter clean: `ruff check .`
- [ ] Type checker clean: `mypy hunterx/` (if configured)
- [ ] No open issues tagged `blocker` or `release-critical`
- [ ] `CHANGELOG.md` is updated with all changes since last release
- [ ] `CITATION.cff` version updated
- [ ] Version bumped in:
  - `pyproject.toml`
  - `hunterx/__init__.py` (if applicable)
  - `docs/_config.yml` (if applicable)
  - `docs/_layouts/default.html` (SoftwareApplication JSON-LD version)
- [ ] `RELEASE_NOTES_vX.Y.Z.md` created with highlights and migration notes
- [ ] `SECURITY.md` supported versions table updated

## Release Candidates

- [ ] Create release candidate tag: `git tag vX.Y.Z-rc.N`
- [ ] Run full CI pipeline (lint + test + build)
- [ ] Test Docker image: `docker build -t hunterx:rc . && docker run --rm hunterx:rc --help`
- [ ] Verify installation from source: `pip install . && hunterx --version`
- [ ] Smoke test: run a basic scan against a test target
- [ ] If AI provider available, smoke test AI-assisted scanning

## Release

- [ ] Tag the release: `git tag -s vX.Y.Z -m "HunterX vX.Y.Z"`
- [ ] Push tag: `git push origin vX.Y.Z`
- [ ] Create GitHub Release from the tag
- [ ] Attach release notes (`RELEASE_NOTES_vX.Y.Z.md`)
- [ ] Verify Docker image build completes on CI
- [ ] Verify Docker Hub image is updated: `docker pull nullc0d30/hunterx:latest`
- [ ] Verify PyPI package is published: `pip install hunterx==X.Y.Z`
- [ ] Update GitHub Pages docs site if needed
- [ ] Post announcement in GitHub Discussions

## Post-Release

- [ ] Create a new milestone for the next version
- [ ] Move unresolved issues from the released milestone to the next
- [ ] Update `ROADMAP.md` if milestones shifted
- [ ] Close the release milestone on GitHub
- [ ] Monitor for bug reports and regression issues in the first 72 hours

## Hotfix Release

For critical security fixes or regressions:

- [ ] Branch from the release tag: `git checkout -b hotfix/vX.Y.Z+1 vX.Y.Z`
- [ ] Apply fix commits
- [ ] Bump patch version
- [ ] Follow standard release process from "Release" section
