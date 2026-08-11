---
layout: default
title: CI/CD Security Scanning — HunterX v7
keywords: CI/CD security scanning, security in CI/CD, DevSecOps, shift left security, GitHub Actions security scanning, SARIF, automated security testing pipeline, security scanning pipeline
description: >-
  Running HunterX v7 in CI/CD pipelines: Docker images, REST API, SARIF 2.1
  export for GitHub CodeQL, structured reports and reproducible security
  scanning for DevSecOps teams.
---

# CI/CD Security Scanning

HunterX can be integrated into CI/CD pipelines for authorized security
scanning. Its design — CLI, REST API, Docker, SARIF 2.1 export and structured
reports — makes it practical to add validated security checks to your delivery
pipeline.

## Integration points

- **Docker image** — `nullc0d30/hunterx` multi-stage image running as a
  non-root user, ready for containerized pipeline jobs.
- **CLI** — `hunterx` commands run inside pipeline steps for mission creation,
  toolchain execution, findings and reports.
- **REST API** — a FastAPI application (`hunterx.api.app:create_app`) for
  orchestrating assessments programmatically, with optional API-key
  authentication (admin/read-only roles).
- **SARIF 2.1 export** — SARIF integrates natively with VS Code and GitHub
  CodeQL workflows, letting security results surface where developers work.
- **Structured reports** — Markdown, HTML, JSON, SARIF, PDF and package exports
  for artifacts and dashboards.

## Pipeline example

```bash
# Install HunterX in the pipeline environment (from the source repository)
git clone https://github.com/nullc0d30/HunterX.git
cd HunterX
python -m pip install -e ".[api,db]"

# Run a full-spectrum mission against a target you are authorized to test
hunterx hunt full_security_assessment https://staging.example.com

# Export findings as SARIF for GitHub CodeQL integration
hunterx report sarif
```

> **Scope and authorization.** CI/CD scanning with HunterX must target systems
> the organization owns or is explicitly authorized to test. Use staging and
> test environments; respect scope, authorization and safety policies.

## Why validated findings matter in CI/CD

Security scanning that produces only candidate detections creates noise and
alert fatigue. HunterX's evidence-driven validation, proof and replay model
helps teams focus on findings that have been verified and can be reproduced —
reducing false-positive load on the security team.

## DevSecOps features

- Reproducible results across runs
- Structured, machine-readable output (JSON, SARIF)
- REST API for orchestration and integration
- Scope, authorization and safety guards
- Secret masking and hardened parsing

## Getting started

- [Installation](/installation/)
- [Quickstart](/quickstart/)
- [Reporting](/v7-professional-finding-intelligence-reporting/)
- [DevSecOps](/v7-devsecops/)
- [CI/CD Architecture](/v7-cicd-architecture/)

## Related

- [AI Penetration Testing](/ai-penetration-testing/)
- [Bug Bounty](/bug-bounty/)
- [Red Team](/red-team/)
