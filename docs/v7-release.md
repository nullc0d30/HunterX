---
layout: default
title: HunterX v7 — What's New in v7.0.0
keywords: HunterX v7, HunterX 7.0.0 release, vulnerability proof engine, AI-assisted vulnerability discovery, release notes, vulnerability validation, PoC generation
description: >-
  What's new in HunterX v7.0.0: AI-assisted vulnerability discovery, validation
  and proof engine. Mission orchestration, toolchain intelligence, proof and
  PoC engine, target intelligence, cloud/SaaS intelligence, reporting and
  production readiness.
---

# HunterX v7 — What's New

HunterX v7.0.0 (released 2026-08-11) marks the transition to an
**AI-assisted vulnerability discovery, validation & proof engine**. The product
message is:

> **Less noise. More verified findings.**

HunterX no longer stops at candidate detections. It carries each finding through
discovery, reasoning, testing, verification, proof, PoC generation, validation,
correlation and report generation.

## v7 Highlights

- **Composition root** — a single Clean Architecture platform assembler wires
  every port and service in `src/hunterx` (domain, application, infrastructure,
  engines, agents, tools, plugins, knowledge, reporting, config, CLI, API).
- **Tool integration architecture** — the Tool Integration SDK, tool
  intelligence platform and a 92-tool arsenal manifest with machine-readable
  contracts, structured execution, versioned parsers/normalizers and
  dependency-aware chaining.
- **Autonomous mission orchestration** — create, run, checkpoint, resume and
  finalize full-spectrum security-assessment missions.
- **Adaptive mission planning** — attack-path planning, replanning and
  explainable next-best-action selection.
- **Target intelligence persistence (TIDB)** — SQL storage with Alembic
  migrations, events, audit and versioning; structured target intelligence.
- **Cloud & SaaS intelligence** — evidence-backed cloud/SaaS attack-surface
  intelligence across providers (AWS, Azure, GCP, OCI, Cloudflare, DigitalOcean,
  Akamai, Fastly, Vercel, Netlify, Heroku, Render, Fly.io, Supabase, Firebase,
  Kubernetes, Docker).
- **Topology & events** — network/cloud topology relationships and a typed
  event bus with observability.
- **Knowledge & correlation** — knowledge-graph relationships, cross-tool
  correlation and evidence chains.
- **PoC / evidence architecture** — the Vulnerability Proof & PoC Validation
  Engine: proof contracts, minimal safe proofs, replay, reproducibility, impact
  and evidence-driven confidence.
- **Professional reporting** — findings, evidence bundles, remediation plans
  and multi-format exports (Markdown, HTML, JSON, SARIF, PDF, package).
- **Security hardening** — scope and authorization guards, sandboxing,
  evidence-gated confidence, secret masking, hardened XML parsing.
- **Installation system** — idempotent `install.sh` v7 installer, Docker
  multi-stage image, PyPI packaging.
- **CI/CD** — lint, type, test, security, supply-chain, packaging and release
  pipelines.
- **Documentation** — comprehensive v7 docs and product site.
- **Production readiness** — final hardening, release-tree and architecture
  certification.

## Engineering Validation

At release, the v7 test suite reported **3479 tests passed, 8 skipped,
2 deselected, 0 failed**, with ruff, mypy, bandit, vulture, documentation and
package gates green. This is an engineering validation metric, not a marketing
"quality guarantee".

## From Detection to Proof

v7 maintains the distinction between a potential vulnerability and a validated
finding:

```
DETECTED → SUSPECTED → VALIDATING → VALIDATED → PROVEN → CONFIRMED → REPORT_READY
```

Every report-ready finding carries: Vulnerability + Evidence + Reproducibility +
Impact + PoC.

## Related

- [PoC & Validation]({{ '/poc-validation/' | relative_url }}) — the proof engine
- [Tool Ecosystem]({{ '/tool-ecosystem/' | relative_url }}) — 92 integrated security tools
- [Changelog]({{ '/changelog/' | relative_url }}) — full release history
- [Release Guide]({{ '/v7-release-guide/' | relative_url }}) — building and releasing v7
- [Features]({{ '/features/' | relative_url }}) — platform capabilities
