---
layout: default
title: OpenSSF Readiness — HunterX v6.0.0
description: >-
  HunterX readiness assessment for Open Source Security Foundation (OpenSSF)
  best practices, including Scorecard, Best Practices Badge, SBOM, SLSA,
  and supply chain security.
permalink: /openssf/
---

## OpenSSF Readiness

This document assesses HunterX's readiness for [Open Source Security Foundation (OpenSSF)](https://openssf.org/) best practices and provides a roadmap for achieving OpenSSF adoption.

---

## Current State

### OpenSSF Scorecard

The [OpenSSF Scorecard](https://github.com/ossf/scorecard) evaluates open source projects on security practices. HunterX is currently **not registered** with the Scorecard. Once registered, the following areas will be evaluated:

| Check | Expected Score | Notes |
|-------|---------------|-------|
| Binary-Artifacts | 10/10 | No binaries in repository |
| Branch-Protection | Pending | Requires GitHub branch protection rules |
| CI-Tests | 10/10 | Multiple CI workflows (test, lint, build, publish) |
| Code-Review | 8/10 | PRs reviewed; no formal review requirement enforced |
| Contributors | 7/10 | Single primary contributor; community growing |
| Dangerous-Workflow | 10/10 | No dangerous script patterns |
| Dependency-Update-Tool | 0/10 | Dependabot or Renovate not yet configured |
| Fuzzing | 0/10 | No fuzzing configured |
| License | 10/10 | Apache 2.0 with LICENSE file |
| Maintained | 10/10 | Active development with regular releases |
| Pinned-Dependencies | 10/10 | Dockerfile and CI use pinned versions |
| SAST | 10/10 | Ruff linting; future: CodeQL integration |
| Security-Policy | 10/10 | SECURITY.md with PGP keys and SLA |
| Signed-Releases | 10/10 | Git tags signed; future: Sigstore/cosign |
| Token-Permissions | 8/10 | CI tokens use minimal permissions |
| Vulnerabilities | 10/10 | No known vulnerabilities |

### Best Practices Badge

The [OpenSSF Best Practices Badge](https://www.bestpractices.dev/) is a voluntary program. HunterX satisfies the majority of criteria at the **Passing** level:

| Category | Status | Notes |
|----------|--------|-------|
| Basics | ✅ Complete | Repo, license, documentation all present |
| Change Control | ✅ Complete | Version control, release notes, changelog |
| Reporting | ✅ Complete | Issue tracker, security policy |
| Quality | ✅ Complete | CI/CD, testing, coding standards |
| Security | ⚠️ Partial | Dependabot and fuzzing not yet configured |

### Supply Chain Security

| Practice | Status | Notes |
|----------|--------|-------|
| SBOM (Software Bill of Materials) | ❌ Not generated | Recommended: `pip-audit` or `cyclonedx-bom` |
| SLSA Level | Level 0 | No provenance attestation yet |
| Dependency Review | ❌ Not configured | Recommended: GitHub Dependency Review action |
| CodeQL Analysis | ❌ Not configured | Recommended: `github/codeql-action` |
| Secret Scanning | ✅ Enabled | GitHub pushes secret scanning by default |
| Dependabot | ❌ Not configured | Recommended: enable Dependabot alerts and updates |

---

## Recommendations

### Short-Term (Immediate)

1. **Enable Dependabot** — Add `.github/dependabot.yml` for automated dependency updates
2. **Configure CodeQL** — Add CodeQL analysis workflow to `.github/workflows/`
3. **Run Scorecard** — Register the repository with the OpenSSF Scorecard
4. **Generate SBOM** — Add SBOM generation to the release pipeline

### Medium-Term (Next Release)

1. **Achieve OpenSSF Best Practices Badge** — Register and pass the Passing level
2. **SLSA Level 1** — Add provenance attestation to builds
3. **Branch Protection** — Enforce required reviews and status checks on `main`
4. **Dependency Review** — Add the Dependency Review GitHub Action

### Long-Term

1. **SLSA Level 2+** — Signed provenance with Sigstore/cosign
2. **Fuzzing Integration** — Add OSS-Fuzz or CIFuzz
3. **Supply Chain Levels for AI Artifacts (SLSA for ML)** — If AI models are distributed
4. **CVE Disclosure Program** — Formalize CVE assignment process

---

## Configuration Templates

### Dependabot

Create `.github/dependabot.yml`:

```yaml
version: 2
updates:
  - package-ecosystem: "pip"
    directory: "/"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 10
  - package-ecosystem: "docker"
    directory: "/"
    schedule:
      interval: "weekly"
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
```

### CodeQL

Add to `.github/workflows/codeql.yml`:

```yaml
name: "CodeQL"
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
  schedule:
    - cron: '0 0 * * 1'

jobs:
  analyze:
    name: Analyze
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    strategy:
      fail-fast: false
      matrix:
        language: [python]
    steps:
      - uses: actions/checkout@v4
      - uses: github/codeql-action/init@v3
        with:
          languages: ${{ matrix.language }}
      - uses: github/codeql-action/analyze@v3
```

### SBOM Generation

Add to release workflow:

```yaml
- name: Generate SBOM
  run: |
    pip install cyclonedx-bom
    cyclonedx-py --output sbom.json
- uses: actions/upload-artifact@v4
  with:
    name: sbom
    path: sbom.json
```

---

## Resources

- [OpenSSF Scorecard](https://scorecard.dev/)
- [OpenSSF Best Practices Badge](https://www.bestpractices.dev/)
- [SLSA Framework](https://slsa.dev/)
- [CycloneDX SBOM](https://cyclonedx.org/)
- [Sigstore / cosign](https://www.sigstore.dev/)
- [GitHub Dependency Review](https://docs.github.com/en/code-security/supply-chain-security)
- [GitHub CodeQL](https://codeql.github.com/)
