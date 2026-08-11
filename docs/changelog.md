---
layout: default
title: Changelog — HunterX Release History
description: >-
  HunterX version history and changelog from v7.0.0 through earlier releases.
  Features, fixes, and breaking changes for each version.
---

## Changelog

> Full changelog maintained at [CHANGELOG.md](https://github.com/nullc0d30/HunterX/blob/main/CHANGELOG.md).

## v7.0.0 (2026-08-11)

### Major Features
- **Clean Architecture v7 core** (`src/hunterx`) — domain, application, infrastructure, engines, agents, tools, plugins, knowledge, reporting, config, CLI and API layers
- **Autonomous mission orchestration** — create, run, checkpoint, resume and finalize full-spectrum security-assessment missions
- **Adaptive mission planning** — attack-path planning, replanning and explainable next-best-action selection
- **Toolchain intelligence layer** — 92 registered security tools with machine-readable contracts, structured execution, parsing/normalization and dependency-aware chaining
- **Evidence-driven vulnerability validation** — hypothesis testing, validation verdicts, and controlled, safe proof/PoC engineering with replay verification
- **Proof & PoC Validation Engine** — proof contracts, minimal safe proofs, replay, reproducibility, evidence-driven impact and confidence
- **Target memory & campaign intelligence** — snapshots, diffs, coverage and revalidation planning
- **Cloud & SaaS attack-surface intelligence** — provider detection, resource/exposure/environment classification and topology for AWS, Azure, GCP, OCI, Cloudflare and more
- **Knowledge graph & correlation** — cross-tool evidence chains and attack-path analysis
- **Professional reporting** — findings, evidence bundles, remediation plans and multi-format exports (Markdown, HTML, JSON, SARIF, PDF, package)
- **TIDB persistence** — SQL storage with 21 linear Alembic migrations, events, audit and versioning
- **`HUNTERX_*` environment-variable configuration overrides**
- **Mission persistence** across CLI invocations and process restarts (restore path)
- **Safe XML parsing** via `defusedxml` (XXE / entity-expansion hardened)
- **`install.sh` v7 installer** (idempotent, database initialization, verified installation)

### Fixed
- Base installation no longer crashes without optional extras (SQLAlchemy now a base dependency)
- `mission create` → `mission start` workflow works across separate CLI invocations
- Harden `hunterx` base install and Docker image runtime
- Ruff, dead-code (vulture) and bandit security gates green

### Engineering Validation
- **3479 tests passed, 8 skipped, 2 deselected, 0 failed**
- Ruff, mypy, bandit, vulture, docs and package gates green

## v6.0.0 (2026-07-26)

### Major Features
- **Security Skills Framework** — 41 built-in skills with MITRE ATT&CK, OWASP, CWE, CAPEC mapping
- **Reasoning Engine** — 18 goal types with planner, prompt builder, validator, and multi-call consensus
- **Multi-Agent Platform** — 10 specialized agents with event/message buses, DAG workflows, checkpoint/resume
- **AI Provider Abstraction Layer** — OpenAI and Ollama providers with session management, caching, metrics, middleware, retry, circuit breaker
- **Knowledge Graph** — Entity-relationship store for findings, targets, attack paths, and contextual data
- **Threat Modeling & Attack Chains** — STRIDE/LINDDUN categorization, trust boundary mapping, chain analysis
- **Payload Intelligence** — SQLite + FTS5 indexing, 5-level execution policy, 10 mutation families, provenance tracking, feedback loop
- **MITRE ATT&CK Mapping** — All skills and findings mapped to Enterprise techniques

### REST API (40+ endpoints)
- Scan lifecycle: submit, poll, cancel, pause, resume
- AI provider management: providers, chat, streaming, sessions, metrics
- Agent management: list, details, start, stop
- Skills: list, search, execute, install, uninstall, categories, MITRE mapping
- Payload: search, stats, mutate, techniques, feedback
- Workflows: list, create, execute, status
- Reasoning: create goals, get results
- System: health, config, version

### CLI
- Commands: `scan`, `module`, `report`, `doctor`, `config`, `update`, `api`
- Subcommands: `skills`, `agents`, `payload`, `workflow`, `reasoning`, `ai`
- Profile support: `internal`, `bounty`, `gov`
- Preset support: `quick`, `full`, `stealth`
- Authentication: basic, bearer, cookie, form, JWT
- AI integration flags with multi-provider support

### Reporting
- JSON, Markdown, SARIF 2.1, HTML
- Visual attack graphs (HTML + Graphviz)
- Purple team detection rules
- ZIP evidence packages

### Testing & Quality
- 623 passing tests
- 0 Ruff errors
- CI matrix for Python 3.11/3.12/3.13

## v4.0.1 (2026-07-22)

### License Change
- **License changed from Proprietary to Apache 2.0** — HunterX is now fully open source
- All source files updated to `SPDX-License-Identifier: Apache-2.0`
- CONTRIBUTING.md updated with DCO (Developer Certificate of Origin) requirement

### Documentation
- Comprehensive README with badges, CI status, and architecture
- GitHub Pages site with SEO metadata and structured data
- Quickstart guide, API reference, Docker guide, FAQ, tutorials

### Infrastructure
- GitHub Actions CI pipeline with Ruff linting and Pytest
- Docker multi-stage build producing 271MB image
- Docker Hub automated builds

## v4.0.0 (2026-07-20)

### Initial Release
- 4-stage reasoning pipeline (Passive Intel, Probe, Confirm, Verify)
- 200+ vulnerability signatures across web, API, and cloud categories
- REST API server with async job queue
- Authentication support (Basic, Bearer, Cookie, Form Login)
- Plugin system with detectors, reporters, and hooks
- Reporting: Markdown, JSON, SARIF 2.1, HTML, ZIP
- WebSocket and GraphQL protocol testing
- OOB detection for blind XXE, SSRF, and RCE
- WAF fingerprinting with 50+ signatures
- Operator profiles (internal, bounty, gov)
- Stealth modes with configurable timing
- 76 passing tests
