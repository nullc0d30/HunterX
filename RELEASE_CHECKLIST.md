---
Copyright (c) 2026 Ahmed Awad (NullC0d3)
SPDX-License-Identifier: Apache-2.0
---

# Release Checklist

Use this checklist when preparing a new HunterX release.

---

## Pre-Release

### Code Quality

- [ ] All tests pass: `python -m pytest tests/ -v`
- [ ] Ruff lint clean: `ruff check core/ hunterx.py api/ plugins/ tests/ --ignore=E501`
- [ ] No `TODO`, `FIXME`, or `DEBUG` statements in production code
- [ ] All type hints are correct and complete
- [ ] No hardcoded secrets, tokens, or credentials
- [ ] Copyright headers present on all new files

### Documentation

- [ ] `README.md` updated with new features and examples
- [ ] `ROADMAP.md` updated if scope changed
- [ ] `CHANGELOG.md` or release notes drafted
- [ ] `CITATION.cff` version updated
- [ ] Docstrings updated for new/modified APIs
- [ ] Configuration examples updated (`hunterx.yaml`)
- [ ] Docker usage docs updated if applicable

### Version

- [ ] `pyproject.toml` version bumped
- [ ] `Dockerfile` version label updated
- [ ] `CITATION.cff` version and date updated
- [ ] `api/server.py` version string updated (if changed)
- [ ] All references to old version updated throughout codebase

### Testing

- [ ] Full test suite passed on Python 3.11+
- [ ] Manual smoke test: `python hunterx.py --help`
- [ ] Manual smoke test: `python hunterx.py -u http://example.com --passive-only`
- [ ] Manual smoke test: `python hunterx.py api --port 8443`
- [ ] Docker build succeeds: `docker build -t hunterx:test .`
- [ ] Docker run smoke test: `docker run --rm hunterx:test --help`
- [ ] Edge cases tested (empty payloads, invalid URLs, network errors)

---

## Release

### Git

- [ ] Create release branch: `release/vX.Y.Z`
- [ ] Final commit with message: `chore(release): vX.Y.Z`
- [ ] Tag the release: `git tag -a vX.Y.Z -m "HunterX vX.Y.Z"`
- [ ] Merge to `main` branch
- [ ] Push tags: `git push origin --tags`

### GitHub Release

- [ ] Create GitHub Release from pushed tag
- [ ] Write detailed release notes (see template below)
- [ ] Attach any release artifacts (if applicable)
- [ ] Publish release (not draft)

### Docker

- [ ] Build production image: `docker build -t nullc0d30/hunterx:X.Y.Z .`
- [ ] Tag as latest: `docker tag nullc0d30/hunterx:X.Y.Z nullc0d30/hunterx:latest`
- [ ] Push to Docker Hub: `docker push nullc0d30/hunterx:X.Y.Z`
- [ ] Push latest: `docker push nullc0d30/hunterx:latest`
- [ ] Verify Docker Hub image: `docker run --rm nullc0d30/hunterx:X.Y.Z --version`

### License & Legal

- [ ] `LICENSE` year updated
- [ ] Copyright headers consistent across all files
- [ ] `core/legal.py` constants updated if needed
- [ ] Third-party dependency licenses reviewed (if changed)

### Security

- [ ] Dependencies scanned for known CVEs
- [ ] No new vulnerabilities introduced
- [ ] Destructive payload blocklist verified intact
- [ ] `SECURITY.md` contact information current

---

## Post-Release

- [ ] Announce on GitHub Discussions
- [ ] Update `ROADMAP.md` with completed items
- [ ] Close associated milestone on GitHub
- [ ] Check CI/CD pipeline for the release build
- [ ] Monitor for issues and feedback
- [ ] Update any downstream integrations

---

## Release Notes Template

```markdown
## HunterX vX.Y.Z — Release Title

### Highlights
- Bullet list of major changes

### New Features
- Feature 1 with brief description
- Feature 2 with brief description

### Bug Fixes
- Fix 1
- Fix 2

### Breaking Changes
- (If any) describe migration path

### Docker
`docker pull nullc0d30/hunterx:X.Y.Z`

### Full Changelog
Link to compare view on GitHub

### Contributors
- @contributor1 (feature)
- @contributor2 (bug fix)
```

---

## Emergency Release (Patch)

For critical security fixes, the checklist can be shortened:

- [ ] Fix verified and tested
- [ ] Code reviewed by at least 2 maintainers
- [ ] Version bumped (patch)
- [ ] Release notes written
- [ ] Tagged and released
- [ ] Docker image rebuilt and pushed
- [ ] Security advisory published (if applicable)

---

*This checklist is adapted from industry best practices and should be customized as the project evolves.*
