<!-- Copyright (c) 2026 Ahmed Awad (NullC0d3). SPDX-License-Identifier: Apache-2.0. -->

# Release Checklist

This document outlines the steps required to publish a new HunterX v7 release.

---

## Pre-Release

- [ ] All planned features for this release are implemented and merged to `main`
- [ ] Full v7 suite passes: `pytest -m "not tools"`
- [ ] Linter clean: `ruff check src eng tests alembic`
- [ ] Type checker clean: `mypy eng src/hunterx/shared`
- [ ] Security gate clean: `bandit -r src/hunterx`
- [ ] No open issues tagged `blocker` or `release-critical`
- [ ] `CHANGELOG.md` is updated with all changes since last release
- [ ] `CITATION.cff` version updated
- [ ] Version bumped in:
  - `pyproject.toml`
  - `src/hunterx/__init__.py`

## Release Preparation

- [ ] `install.sh` verified against a clean environment
- [ ] Clean install from the wheel/sdist succeeds (`pip install dist/*.whl`)
- [ ] Alembic migrations verified: `alembic upgrade head` on a fresh database
- [ ] Release tree audit: no development artifacts, no secrets, no v6 active
      artifacts
- [ ] Copyright/ownership headers present on project-owned files
- [ ] Responsible-use disclaimer present (README, docs, SECURITY.md)
- [ ] Documentation links resolve (`python -m eng gates --gate docs`)

## Build & Publish

- [ ] Build artifacts: `python -m build`
- [ ] Twine check: `twine check dist/*`
- [ ] Tag the release: `git tag -a vX.Y.Z -m "HunterX vX.Y.Z"`
- [ ] Publish to PyPI: `twine upload dist/*`
- [ ] Publish Docker image: `docker buildx build --push -t nullc0d30/hunterx:latest .`
- [ ] Update the GitHub release with release notes

## Post-Release

- [ ] Verify the PyPI install: `pip install "hunterx[api,db]" && hunterx version`
- [ ] Verify the Docker image: `docker run nullc0d30/hunterx:latest version`
- [ ] Mark release complete in `CHANGELOG.md`
