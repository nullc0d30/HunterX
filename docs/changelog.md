---
layout: default
title: Changelog — HunterX Release History
description: >-
  HunterX version history and changelog from v6.0.0 through earlier releases.
  Features, fixes, and breaking changes for each version.
---

# Changelog

> Full changelog maintained at [CHANGELOG.md](https://github.com/nullc0d30/HunterX/blob/main/CHANGELOG.md).

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
- Subcommands: `skills`, `agents`, `payload`, `workflow`, `reasoning`, `ai`, `config`
- Profile support: `internal`, `bounty`, `gov`
- Preset support: `quick`, `full`, `stealth`
- Authentication: basic, bearer, cookie, form, JWT
- AI integration flags

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
- All documentation files updated to `SPDX-License-Identifier: Apache-2.0`
- NOTICE file added with third-party dependency attributions
- CONTRIBUTING.md updated with DCO (Developer Certificate of Origin) requirement

### Documentation
- Comprehensive README with badges, CI status, and architecture
- GitHub Pages site with SEO metadata and structured data
- Quickstart guide, API reference, Docker guide, FAQ
- Tutorials for basic scanning, authenticated scanning, and API usage

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
- Operator profiles (internal, bounty, gov) with behavioral constraints
- Stealth modes with configurable timing
- 76 passing tests
- Proprietary license
