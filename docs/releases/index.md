---
layout: default
title: Releases — HunterX
description: >-
  HunterX release notes and version history. Current version 6.0.0
  with Security Skills Framework, Reasoning Engine, Multi-Agent Platform,
  Knowledge Graph, Threat Modeling, Payload Intelligence, and REST API.
  Apache 2.0 licensed.
---

# Releases

## v6.0.0 (Current)

**Date**: 2026-07-26
**License**: Apache 2.0

- Security Skills Framework with 41 plugin-based skills
- Reasoning Engine with 18 goal types and AI consensus
- Multi-Agent Platform with 10 specialized agents
- AI Provider Abstraction Layer (OpenAI, Ollama)
- Knowledge Graph for security relationship analysis
- Threat Modeling with STRIDE/LINDDUN and Attack Chains
- Payload Intelligence with FTS5 indexing and mutation engine
- MITRE ATT&CK + OWASP + CWE + CAPEC mapping
- REST API with 40+ endpoints
- CLI with subcommands (skills, agents, payload, workflow, reasoning, ai)
- Enterprise reporting (JSON, Markdown, SARIF 2.1, HTML, attack graphs)
- Docker multi-stage deployment
- 623 passing tests, 0 Ruff errors

See the [changelog]({{ '/changelog' | relative_url }}) for full details.

## v4.0.1

**Date**: 2026-07-22
**License**: Apache 2.0

- License changed from Proprietary to Apache 2.0
- GitHub Pages documentation site with SEO metadata
- Docker Hub image deployment

## v4.0.0

**Date**: 2026-07-20
**License**: Proprietary

- Initial public release
- 4-stage reasoning pipeline
- 200+ vulnerability signatures
- REST API server
- Plugin system
