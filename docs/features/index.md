---
layout: default
title: Features — HunterX v7
keywords: HunterX Features, platform capabilities
description: >-
  HunterX v7 platform capabilities: mission orchestration, adaptive planning,
  toolchain intelligence, vulnerability validation, proof & PoC engineering,
  professional reporting, and persistence.
---

# Features

HunterX v7 is an enterprise security orchestration and intelligence platform.
It plans, orchestrates, executes, validates, correlates and reports authorized
security assessments by integrating open-source security tools.

## Capability areas

- **Autonomous mission orchestration** — create, run, checkpoint and resume
  full-spectrum security-assessment missions. See
  [Mission Orchestration]({{ '/v7-autonomous-mission-orchestration/' | relative_url }}).
- **Adaptive mission planning** — attack-path planning, replanning and
  explainable next-best-action selection. See
  [Adaptive Mission Planning]({{ '/v7-adaptive-mission-planning/' | relative_url }}).
- **Toolchain intelligence** — 92 registered security tools with machine-
  readable contracts, structured execution, parsing/normalization and
  dependency-aware chaining. See
  [Toolchain Intelligence]({{ '/v7-full-toolchain-intelligence/' | relative_url }}).
- **Evidence-driven vulnerability validation** — hypothesis testing,
  validation verdicts and controlled, safe proof/PoC engineering. See
  [Vulnerability Proof & PoC]({{ '/v7-vulnerability-proof-and-poc/' | relative_url }}).
- **Professional reporting** — findings, evidence bundles, remediation plans
  and multi-format exports (markdown, HTML, JSON, SARIF, PDF, package). See
  [Professional Reporting]({{ '/v7-professional-finding-intelligence-reporting/' | relative_url }}).
- **Target memory & campaign intelligence** — target snapshots, diffs, coverage
  and revalidation planning. See
  [Target Memory & Campaign Intelligence]({{ '/v7-target-memory-and-campaign-intelligence/' | relative_url }}).
- **TIDB-backed persistence** — SQL storage with Alembic migrations, events,
  audit and versioning. See [Persistence (TIDB)]({{ '/v7-tidb/' | relative_url }}).
- **Security model** — scope and authorization guards, sandboxing, evidence-
  gated confidence, secret masking and safe execution seams. See
  [Security Pipeline]({{ '/v7-security-pipeline/' | relative_url }}).

## Architecture

The v7 core is a Clean Architecture Python package under `src/hunterx`
(domain / application / infrastructure / engines / agents / tools / plugins /
knowledge / reporting / config / cli / api). See the
[Core Foundation]({{ '/v7-foundation/' | relative_url }}) and [Architecture Enforcement]({{ '/architecture/' | relative_url }}).

## Responsible use

HunterX is an authorized cybersecurity testing and research platform. Obtain
authorization before testing any system. See
[Responsible Use]({{ '/responsible-use/' | relative_url }}).
