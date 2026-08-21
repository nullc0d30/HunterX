<!-- Copyright (c) 2026 Ahmed Awad (NullC0d3). SPDX-License-Identifier: Apache-2.0. -->

# Changelog

All notable changes to HunterX are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [7.0.1] — 2026-08-21

### Added

- Final release-candidate acceptance hardening: multi-target acceptance across
  generic synthetic profiles (simple web, REST API, GraphQL, authenticated,
  multi-user, file-handling, workflow), production reliability/soak testing,
  failure-recovery matrix, capability-coverage and attack-surface-coverage
  audits, and final security/target-agnostic audits.
- Target-agnostic surface-kind preservation: URL-bearing observation kinds
  (`javascript_endpoint`, `sink`, `source`, `upload`, `client_route`,
  `workflow`, ...) are no longer silently degraded to generic `endpoint`, and
  the same endpoint URL is never registered as two graph nodes under different
  kinds.
- Autonomous model-driven attack loop documentation in the README, including
  exhaustion semantics (`EXHAUSTED` vs `RESOURCE_LIMIT` vs `MODEL_UNAVAILABLE`)
  and model-failure behavior.

### Fixed

- Attack-surface graph accuracy: no silent disappearance of discovery
  information for URL-bearing surface kinds.
- Full-security-assessment orchestration (v7.0.1 regression): `full_security_assessment`
  is no longer a fixed reconnaissance chain. It maps to a new
  `MissionObjective.FULL_SECURITY_ASSESSMENT` whose deterministic plan spans the
  full spectrum (asset/subdomain/DNS/port/service/technology/certificate/endpoint
  enumeration plus content discovery, JavaScript analysis, parameter discovery,
  API mapping and vulnerability scanning), and the adaptive runner wires every
  observation to its class-specific probe (hypothesis → probe → verify).
- Completion gate: a mission may no longer enter `reporting` merely because the
  initial reconnaissance plan is exhausted — reporting requires the objectives
  to be satisfied (meaningful work happened, no pending plan work, no open
  high-value hypotheses) or a legitimate terminal condition; remaining
  open-hypothesis work is reported honestly as `blocked`, never as success.
- Budget semantics: `resource_budget_exhausted` is emitted only when a configured
  budget dimension is genuinely exhausted (`executions_used >= executions_budget`,
  or a positive wall-clock budget overrun); `time_budget_seconds=0` now means
  unlimited, negative budgets are rejected at configuration, and time exhaustion
  is labelled `TIME_BUDGET_EXHAUSTED` instead of being conflated with resource
  exhaustion.
- Observation → hypothesis pipeline: informational-but-security-relevant scanner
  results (e.g. nuclei `deprecated-tls`) are canonicalized to real classes
  (`security-misconfiguration`) and reach the hypothesis/finding pipeline;
  genuinely informational results are explicitly classified as non-actionable
  evidence instead of being silently dropped.
- Deterministic fallback planner: when no action is ready, the runner derives
  work from the current state — class-specific probes for open hypotheses and
  web discovery for incomplete web attack surfaces — so the mission is fully
  functional without AI.
- AI/OpenRouter telemetry: the AI path records provider, model, request
  success/failure, HTTP status (incl. 429), timeouts, fallbacks and
  assisted-decision counts, and distinguishes `AI unavailable/degraded` from
  mission budget exhaustion.
- Browser capability is a probed capability: Playwright/Chromium/headless
  availability is detected and recorded as `browser_testing` (NOT_ASSESSED when
  unavailable) while non-browser web assessment continues.
- Attack-path semantics: only evidence-supported chains are reported as
  discovered attack paths; purely structural adjacency chains are recorded as
  surface relationships, never as discovered attacks.
- Coverage model: per-dimension coverage (recon / attack surface / hypothesis /
  active test / validation / browser / overall) is reported so a single recon
  ratio is no longer presented as full-assessment coverage.

---

## [Unreleased]

### Added
- Multi-provider AI routing closure: runtime adapters for OpenAI, Anthropic/Claude,
  DeepSeek, OpenRouter, Google Gemini and xAI/Grok behind the existing generic
  `AIPort` abstraction — shared OpenAI-compatible transport where appropriate,
  native wire formats for Anthropic and Gemini, independent provider/model
  selection, per-provider API endpoints and credentials, truthful provider
  errors (auth, payment, invalid model, rate limit, outage, timeout) and no
  silent provider/model fallback
- Generic HTTP status/access-control differential capability
  (`http-access-differential`) through the existing capability engine, finding
  bridge and REPORT_READY lifecycle, with status-only changes never promoted
- Authenticated CLI missions: generic session establishment, session propagation
  into discovery/probes/tools, truthful rejection of failed login redirects
- Finding-service bridge verified through the real CLI mission path (validated →
  evidence → reproduction → PoC → replay → proved → REPORT_READY)
- Full autonomous mission lifecycle closure: continuation past the first
  validated finding, zero-finding honesty, artifact reconciliation
  (report.txt / results.json / events.jsonl) and a secret-free event stream

### Fixed
- A failed login POST that 302-redirects to the login page (with a fresh session
  id) is no longer misjudged as an established session
- CLI event recorder now includes masked `auth.*` session events in events.jsonl
- ffuf adapter fails closed on a missing wordlist instead of emitting an invalid
  `-w ''` invocation

---

## [7.0.0] — 2026-08-12

### Added
- Clean Architecture v7 core (`src/hunterx`): domain, application, infrastructure, engines, agents, tools, plugins, knowledge, reporting, config, CLI and API layers
- Autonomous mission orchestration — create, run, checkpoint, resume and finalize full-spectrum security-assessment missions
- Adaptive mission planning — attack-path planning, replanning and explainable next-best-action selection
- Toolchain intelligence layer — 100+ registered security tools with machine-readable contracts, structured execution, parsing/normalization and dependency-aware chaining
- Evidence-driven vulnerability validation — hypothesis testing, validation verdicts, and controlled, safe proof/PoC engineering with replay verification
- Professional reporting — findings, evidence bundles, remediation plans and multi-format exports (markdown, HTML, JSON, SARIF, PDF, package)
- Target memory & campaign intelligence — snapshots, diffs, coverage and revalidation planning
- TIDB persistence — SQL storage with 21 linear Alembic migrations, events, audit and versioning
- `HUNTERX_*` environment-variable configuration overrides
- Mission persistence across CLI invocations and process restarts (restore path)
- Safe XML parsing via `defusedxml` (XXE / entity-expansion hardened)
- `install.sh` v7 installer (idempotent, database initialization, verified installation)

### Fixed
- Base installation no longer crashes without optional extras (SQLAlchemy now a base dependency)
- `mission create` → `mission start` workflow works across separate CLI invocations
- Harden `hunterx` base install and Docker image runtime
- Ruff, dead-code (vulture) and bandit security gates green

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

### Fixed
- N/A (major version release)

### Security
- Safety-by-design destructive payload blocklist
- WAF detection with auto-abort
- Configurable rate limiting
- Policy-driven execution controls

### Performance
- Multi-stage Docker build: 700MB → 271MB
- FTS5-indexed payload search
- Concurrent agent execution

### Documentation
- Comprehensive documentation site at https://nullc0d30.github.io/HunterX
- SDK and plugin development guides
- Architecture and design decision documents

### Developer Experience
- Ruff linting configured project-wide
- MyPy type checking support
- DCO requirement for contributions
- Full CI/CD pipeline (test, lint, build, publish)

### Compatibility
- Python 3.11, 3.12, 3.13
- Linux, macOS, Windows
- Docker multi-platform images
- REST API v1 (breaking from v4.x API)

### References
- GitHub Release: https://github.com/nullc0d30/HunterX/releases/tag/v6.0.0

---

## [4.0.1] — 2026-07-22

### Changed
- License changed from Proprietary to Apache 2.0
- Docker image optimized via multi-stage build: 700MB to 271MB
- CI matrix expanded to Python 3.11, 3.12, and 3.13

### Fixed
- Security patches applied to requests library (CVE fixes)

### Added
- DCO requirement for all contributions

### Security
- License transition to Apache 2.0
- Dependency vulnerability fixes

### Developer Experience
- DCO sign-off requirement introduced
- Expanded CI coverage across Python versions

### References
- GitHub Release: https://github.com/nullc0d30/HunterX/releases/tag/v4.0.1

---

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

### Performance
- Payload mutation engine
- Concurrent scanning support

### Documentation
- REST API documentation
- Authentication guide
- Plugin development guide

### References
- GitHub Release: https://github.com/nullc0d30/HunterX/releases/tag/v4.0

---

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

### Developer Experience
- CI pipeline via GitHub Actions
- Test framework established

### References
- GitHub Release: https://github.com/nullc0d30/HunterX/releases/tag/v3.1

---

## [3.0] — 2026-07-01

### Added
- Initial release
- 4-stage pipeline
- 100+ signatures
- Response differential analysis
- Safety guardrails
- CLI with 10+ flags
- Markdown, JSON, and ZIP reports

### References
- GitHub Release: https://github.com/nullc0d30/HunterX/releases/tag/v3.0

---

*For a full list of commits, see the GitHub repository.*
