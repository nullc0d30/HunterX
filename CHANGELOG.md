# Changelog

All notable changes to HunterX are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [6.0.0] — 2026-07-30

### Added

- Autonomous Multi-Agent Platform — 10 agents with orchestrator, event and message buses, workflow engine, scheduler, state management, memory, and context
- Reasoning Engine — goals, planner, prompts, validator, formatter, policies, consensus, confidence, and memory subsystems
- Security Skills Framework — 41 built-in skills, registry, loader, executor, marketplace, telemetry, cache, policy, validator, and planner
- Payload Intelligence Platform — sync, index, search, reasoning, feedback, graph, provenance, policy, mutation, metadata, ranking, and context modules
- AI Provider Abstraction Layer — OpenAI and Ollama providers with cache, metrics, middleware, conversation management, prompts, config, circuit breaker, and retry
- Knowledge Graph, Threat Model, Attack Chain, MITRE ATT&CK Mapping, Risk Engine, Browser Intelligence, and Adaptive Memory
- Explainable AI engine for all findings
- Purple Team detection rule generation
- Visual Attack Graph (HTML/Graphviz output)
- SARIF 2.1 reporting
- REST API expanded to 40+ endpoints
- CLI expanded to 12 subcommand groups

### Changed

- Test suite expanded from 76 to 623 tests
- Codebase fully Ruff-clean throughout

## [4.0.1] — 2026-07-22

### Changed

- License changed from Proprietary to Apache 2.0
- Docker image optimized via multi-stage build: 700MB to 271MB
- CI matrix expanded to Python 3.11, 3.12, and 3.13

### Fixed

- Security patches applied to requests library (CVE fixes)

### Added

- DCO requirement for all contributions

## [4.0] — 2026-07-22

### Added

- REST API server (FastAPI)
- Authentication providers — Basic, Bearer, Cookie, Form
- 200+ detection signatures
- Time-based blind detection
- OOB detection
- HTML DOM analysis
- Payload mutation engine
- Plugin system
- YAML configuration
- SARIF reporting
- WebSocket and GraphQL testing
- LLM analysis (Ollama)
- Anomaly clustering

## [3.1] — 2026-07-20

### Fixed

- Thread safety fixes
- Rate limiting
- WAF detection (50+ signatures)

### Added

- 29 pytest tests
- GitHub Actions CI
- Operator profiles
- Attack chain reasoning

## [3.0] — 2026-07-01

### Added

- Initial release
- 4-stage pipeline
- 100+ signatures
- Response differential analysis
- Safety guardrails
- CLI with 10+ flags
- Markdown, JSON, and ZIP reports

---

*For a full list of commits, see the GitHub repository.*
