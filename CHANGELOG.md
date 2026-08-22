<!-- Copyright (c) 2026 Ahmed Awad (NullC0d3). SPDX-License-Identifier: Apache-2.0. -->

# Changelog

All notable changes to HunterX are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [7.1.1] — 2026-08-22

### Fixed

- **Real-runtime memory runaway (the 5.6 GiB incident).** A real
  `full_security_assessment` on a 7.6 GiB host reached ~5.6 GiB resident
  (~74% of host RAM) with no child tools running. Runtime instrumentation
  (per-cycle VmRSS/VmHWM/VmPeak + process-tree RSS + tracemalloc heap +
  mission-aggregate bytes) traced the root cause to the **attack-path
  analysis**, not the sampler:
  - `MissionOrchestrator.record_attack_paths` rebuilds an attack-surface graph
    from the mission context after every observation. A port scan adds hundreds
    of `context.services`, a crawler adds hundreds of endpoints, and the
    `O(SERVICES × ENDPOINTS)` cross-linking built a dense bipartite graph that
    `AttackPathEngine._chains` expanded with an **exponential BFS on every
    observation** — a transient ~1.7–4.8 GiB allocation per cycle whose freed
    memory ratcheted the process RSS upward and stalled the mission (the hang).
  - The governor sampler was **not** the problem: it tracked `/proc` VmRSS
    within 25% and did transition to EMERGENCY — but enforcement cannot
    interrupt a single long synchronous analysis.
- **Bounded attack-path analysis.** `record_attack_paths` now caps the number
  of services (64) and endpoints (200) used in graph construction, and
  `AttackPathEngine.discover`/`_chains` enforce a **global discovery budget**
  (entry points, BFS visits, chains) so one analysis pass is deterministic and
  cheap regardless of surface size. Reproduction on a dense 1000-service /
  200-endpoint graph: transient peak dropped from ~4.8 GiB to ~292 MiB, and a
  45-second mission now completes at a stable ~195 MiB RSS.
- **Bounded target-model maps.** `apply_mission_bounds` now trims
  `context.services` / `context.assets` / `context.technologies` (previously
  untrimmed — a single port scan added 1000+ service entries) plus byte-level
  bounds: `max_observation_content_bytes` summarizes oversized observation
  content, `max_aggregate_state_bytes` caps the retained aggregate, and
  `max_model_context_bytes` bounds the reasoning context.
- **Continuous enforcement.** Admission decisions now re-sample the process
  tree (not a cached state), and a background sampling **watchdog**
  (`watchdog_interval_s`, default 1 s, started by the platform) keeps the
  resource state current even while the main thread is inside a long single
  operation, so EMERGENCY is observable between explicit evaluation points.

### Added

- **Runtime memory telemetry** (`hunterx.resource.telemetry`): a
  cross-sectional probe records process RSS/VmRSS/VmHWM/VmPeak, process-tree
  RSS, Python heap (opt-in `tracemalloc`), mission-aggregate item counts and
  approximate serialized bytes, model context and queue sizes, plus the
  governor's own reading at the same instant — written as JSON-lines to
  `HUNTERX_RESOURCE_TELEMETRY_FILE`. Enables data-driven failure
  classification (sampler bug vs. enforcement gap vs. unbounded state vs.
  temporary allocation) instead of guessing.
- `scripts/reproduce_resource_runaway.py`: reproduces the incident class and
  prints the classification (governor-vs-`/proc` tracking, peak RSS, aggregate
  bytes, heap).
- Regression tests: `tests/integration/test_resource_attack_path_regression.py`
  asserts attack-path discovery and `record_attack_paths` stay bounded on dense
  graphs, target-model maps are trimmed, and observation content is
  byte-bounded.

---

## [7.1.0] — 2026-08-22

### Added

- **Resource-aware autonomous execution — centralized Mission Resource Governor.**
  A single authoritative resource-governance layer (`hunterx.resource`) manages
  the resource envelope of the *entire* HunterX mission process tree (parent,
  child tools, grandchildren, external binaries, probes, model calls, queues and
  evidence) so HunterX stays safe and usable on constrained 4 GB / 2 CPU hosts
  and never relies on the Linux OOM killer.
- **Environment-aware resource detection**: bare-metal Linux, VM, WSL and
  container/cgroup environments are recognized; cgroup v1/v2 memory limits and
  usage, CPU quota, cpuset-aware CPU count and host memory pressure are read
  where available (`physical RAM != RAM available to HunterX`).
- **Derived mission envelope**: an absolute 3 GB HunterX RAM ceiling (default,
  configurable) with a mission budget derived from the effective environment
  (4 GB → ~2 GB budget; 8 GB → 3 GB; 16 GB+ → 3 GB) while host headroom is
  preserved.
- **Resource states with explicit behaviour**: `NORMAL` (bounded execution),
  `CONSTRAINED` (reduce concurrency), `DEGRADED` (stop nonessential work),
  `CRITICAL` (stop new expensive work), `EMERGENCY` (graceful mission
  termination) — configurable thresholds, throttled `[RESOURCE]` telemetry logs.
- **Admission control through the governor**: every external tool execution
  (approve/delay/deny by memory/cpu class + concurrency cap), HTTP probe, model
  call and assessment-queue scheduling passes through the governor; the
  platform-wide parallel-jobs cap adapts to the current resource state.
- **Process-tree accounting and emergency termination**: the mission process
  tree RSS/CPU is sampled (`/proc` walk); on an emergency budget stop the
  governor stops scheduling, terminates active child processes (SIGTERM then
  SIGKILL, no orphans), persists mission state and reports a structured reason.
- **Bounded in-memory state**: observations, hypotheses, decisions, evidence,
  tool executions, trace, negative evidence, attack paths and the assessment
  queue are capped (bounded collections + backpressure); the database remains
  the durable mission state and open hypotheses / validated findings are never
  evicted.
- **Bounded model reasoning context**: the autonomous attacker feeds the model
  a summarized state (bounded observations, findings, adjacent paths, disproven
  fingerprints, surfaces) instead of an ever-growing full mission history, and
  replanning is bounded by `max_replan_cycles` so the
  observe→hypothesize→decide→probe→reassess→replan cycle terminates.
- **Hard deadlines for every blocking operation**: per-tool (600 s default),
  per-model-call (120 s default) and per-mission wall-clock deadlines; the
  operator-configured `time_budget_seconds` is now a hard loop ceiling, and
  timeouts surface as structured `execution_timeout` observations.
- **SQLite resource-safe persistence**: file-backed databases open with WAL
  journaling, a 30 s busy timeout, foreign keys and concurrent-reader support
  so the mission's many short write sessions never deadlock on
  `database is locked`.
- **New `StopCondition` vocabulary for truthful resource stops**:
  `memory_budget_exhausted`, `resource_pressure`, `mission_deadline_exceeded` —
  a resource-triggered stop is never reported as success (run status
  `degraded`, structured reason on the outcome).
- **Configuration**: all thresholds are exposed through the existing
  `HUNTERX_RESOURCE_*` env vars / `resource:` YAML section with safe defaults
  prioritizing host stability.

### Changed

- The mission runner, tool execution SDK (`ExecutionEngine`,
  `BinaryRunner`), model attacker, mission orchestration persistence and SQLite
  factory now route resource decisions through the centralized governor instead
  of scattered checks.

### Fixed

- A real-world `full_security_assessment` runaway (process tree climbing to
  ~90%+ host memory, kernel `folio_wait_bit_common` swap-thrash) is prevented:
  the governor detects the climb and terminates the mission safely within its
  configured envelope — never driving the host to ~90%+ memory.

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
