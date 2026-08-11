# 02 — HunterX System Architecture

**Status:** Ratified
**Version:** 1.0.0
**Applies to:** Core, all modules, plugins, adapters, SDKs, deployment

---

## 1. Architectural Principles

HunterX follows **Clean Architecture** with strict **dependency inversion**.
The binding rules (enforced by lint gates in CI, see `04 - Coding Standards.md` §7):

1. **Dependency Rule (outward-bound-free):** source code dependencies point
   **inward only**. The Domain layer knows nothing about Infrastructure,
   Frameworks, or Delivery.
2. **Abstraction over implementation:** the Core depends on interfaces (ports);
   implementations (adapters) are injected at composition root.
3. **Loose coupling via events and messages:** subsystems communicate through an
   Event Bus and Message Bus; no subsystem imports another subsystem's internals.
4. **AI isolation:** AI providers are reachable **only** through the AI Provider
   Abstraction. Agents and skills never call LLMs directly.
5. **Pluggability as a contract:** every capability is a plugin behind an
   interface. The core never imports a concrete plugin.
6. **Deterministic core, stochastic periphery:** AI, randomness, and timing are
   pinned and recorded so plans and reports are reproducible.

---

## 2. System Context Diagram (C4 Level 1)

```
                        +---------------------------+
                        |  Engagement Operator      |
                        |  (Pentester / Analyst)    |
                        +-------------+-------------+
                                      |
                    +-----------------+-----------------+
                    |               HunterX             |
                    |   AI-Powered Security Operations  |
                    |           Platform                |
                    +--------+--------+--------+--------+
                             |        |        |
              +--------------+        |        +-----------------+
              |                       |                          |
      +-------+--------+     +--------+-------+         +--------+--------+
      | External Tools |     | AI Providers   |         | External Data   |
      | (nmap, nuclei, |     | (Local/Ollama, |         | (CVE, CWE,      |
      | sqlmap, burp,  |     | Cloud LLMs)    |         |  CAPEC, MITRE,  |
      |  ... 100+ )    |     +----------------+         |  EPSS, CT, DNS) |
      +----------------+                                +-----------------+
```

- **Operator** interacts through CLI, REST API, or scheduled missions.
- **External Tools** are executed through the Tool Execution Sandbox; output is
  parsed and normalized.
- **AI Providers** receive structured prompts, never raw secrets or raw target data
  beyond the engagement scope.
- **External Data** enriches findings (CVE/EPSS) and intelligence (CT logs, DNS).

---

## 3. Container Diagram (C4 Level 2)

```
+------------------------------------------------------------------------------------+
|                              HUNTERX PLATFORM                                      |
|                                                                                    |
|  +------------------+   +------------------+   +------------------+                |
|  |   CLI             |   |   REST API        |   |   Scheduler      |                |
|  |   (Typer/Click)   |   |   (FastAPI)       |   |   (APScheduler)  |                |
|  +--------+---------+   +--------+---------+   +--------+---------+                |
|           |                     |                     |                             |
|           +---------------------+---------------------+                             |
|                                 |                                                   |
|                        +--------v---------+                                        |
|                        |   ORCHESTRATION  |                                        |
|                        |   (Mission)      |                                        |
|                        +--------+---------+                                        |
|                                 |                                                   |
|                 +---------------+----------------+                                 |
|                 |               |                 |                                |
|        +--------v-----+  +-----v--------+  +-----v---------+                       |
|        | Planner      |  | Workflow     |  | Agent Fleet   |                       |
|        | (AI + rules) |  | Engine       |  | (Multi-Agent) |                       |
|        +--------+-----+  +-----+--------+  +-----+---------+                       |
|                 |               |                 |                                |
|                 +-------+-------+-----------------+                                |
|                         |                                                         |
|               +---------v---------+                                               |
|               |   REASONING/      |                                               |
|               |   DECISION CORE   |                                               |
|               +---------+---------+                                               |
|                         |                                                         |
|      +------------------+--------------------+                                    |
|      |                  |                    |                                   |
| +----v-----+     +------v------+     +-------v-------+                           |
| | Tool     |     | Plugin      |     | AI Provider   |                           |
| | Execution|     | Host        |     | Abstraction   |                           |
| | Sandbox  |     | (SDK)       |     | (Routing,     |                           |
| +----+-----+     +------+------+     |  Cache,       |                           |
|      |                  |            |  Retry,       |                           |
| +----v-----+     +------v------+     |  Circuit)     |                           |
| | Parsers  |     | Registry    |     +-------+-------+                           |
| +----+-----+     +-------------+             |                                    |
|      |                                       |                                    |
| +----v---------------------------------------v----+                               |
| |           DATA & INFRASTRUCTURE LAYER           |                               |
| |  SQL (Target Intel DB) | Graph (KG) | Object    |                               |
| |  Store (Evidence) | Cache (Redis) | Queue (Rabbit) | Event Bus | Log/Telemetry |
| +--------------------------------------------------+-----------------------------+
```

---

## 4. Layered Architecture (C4 Level 3 — component view)

```
+----------------------------------------------------------------------------------+
| DELIVERY LAYER                                                                   |
|   CLI Commands   REST API   Webhook Sink   Scheduler Jobs                        |
+----------------------------------------------------------------------------------+
| APPLICATION LAYER (use-cases / application services)                              |
|   MissionService   WorkflowService   ReportService   AuthService   AdminService  |
+----------------------------------------------------------------------------------+
| DOMAIN LAYER (pure Python, no framework imports)                                  |
|   Entities: Target, Asset, Finding, Evidence, Mission, Plan, Task, Report         |
|   Value Objects: Port, Service, Risk, Severity, Confidence, Payload               |
|   Domain Services: Planner, Correlator, Validator, RiskScorer, Deduplicator       |
|   Ports (interfaces): ToolPort, StorePort, AIPort, QueuePort, CachePort,          |
|                       EventPort, SecretPort, SandboxPort, LogPort, MetricPort     |
+----------------------------------------------------------------------------------+
| INFRASTRUCTURE LAYER                                                              |
|   Adapters: SQLAlchemy/PostgreSQL, Neo4j, S3/FS, Redis, RabbitMQ, EventBus,       |
|             Vault, DockerSandbox, OpenTelemetry, JSONLogger                       |
|   Tool Integration: ToolExecutor, Parsers, Normalizers, Adapters, Knowledge Files |
|   AI Integration: OpenAIAdapter, OllamaAdapter, local model adapter, caches       |
+----------------------------------------------------------------------------------+
```

**Dependency direction:** Delivery → Application → Domain. Infrastructure
implements Domain ports and is injected upward at composition root. Nothing in
the Domain layer imports `fastapi`, `sqlalchemy`, `redis`, `requests`, or any
third-party library outside the allowed core set.

---

## 5. Subsystem Specifications

### 5.1 Core Engine

The **Core Engine** is the Domain layer's heart. It owns:

- The **unified security schema** entities (`08 - Unified Security Schema.md`).
- **Domain services:** planner, correlator, validator, deduplicator, risk scorer.
- The **mission lifecycle** state machine (draft → approved → queued → running →
  completed → archived).
- The **ports** that every other layer depends upon.

Responsibilities:

- Enforce scope invariants (a target outside scope is rejected at the domain edge).
- Guarantee determinism of plan IDs and finding hashes.
- Provide the single source of truth for `Entity`, `ValueObject`, and aggregate logic.

Non-responsibilities:

- No I/O, no HTTP, no DB, no subprocess, no AI calls. All of these happen through ports.

### 5.2 AI Engine (Reasoning & Decision Core)

The **AI Engine** converts goals into validated decisions.

Sub-components:

| Component | Responsibility |
|-----------|----------------|
| `GoalAdapter` | Converts agent/mission goals into structured AI tasks |
| `PromptManager` | Builds versioned, schema-tight prompts (no secrets, scoped context) |
| `ProviderRouter` | Selects provider/model per task class, cost, latency, policy |
| `AIMiddlewarePipeline` | Logging, masking, schema validation, augmentation |
| `OutputValidator` | Validates raw LLM output against JSON Schema; rejects malformed |
| `ConsensusEngine` | Aggregates N samples; strict (unanimous) or relaxed (majority) |
| `ConfidenceScorer` | Assigns confidence 0.0–1.0 from agreement + calibration |
| `AICache` | Exact + semantic cache keyed on prompt+model+params |
| `RetryHandler` / `CircuitBreaker` | Provider resilience |

Rules:

- Agents NEVER call AI providers directly; they emit goals only.
- All prompts and completions are logged with masking; never with secrets.
- Every AI decision returns an `AIProvenance` record (prompt hash, model, seed,
  temperature, version, latency) attached to the resulting domain object.
- See `11 - AI Standards.md` for behavior, scoring, and learning rules.

### 5.3 Workflow Engine

Executes **Directed Acyclic Graphs (DAGs)** of steps.

Step types: `condition`, `parallel`, `loop`, `wait`, `agent`, `tool`, `skill`,
`submission`, `transform`, `notify`.

- **Execution model:** async, concurrency-controlled, dependency-resolved.
- **Checkpoint/resume:** every step boundary is a checkpoint; recovery resumes at
  the last successful checkpoint.
- **Retries:** per-step policy (max attempts, backoff, retryable error classes).
- **Validation:** output schema validation gates each step.
- **Cancellation:** graceful (finish in-flight step) and forceful (kill).
- See `10 - Workflow Engine.md`.

### 5.4 Mission Engine

The **Mission Engine** is the top-level orchestrator of a complete assessment.

- Instantiates a **Mission** from a **Mission Profile** (`12 - Mission Profiles.md`).
- Binds profile → workflow template → plan → execution → validation → reporting.
- Owns mission state, progress, phase transitions, and the mission timeline.
- Emits mission-level events (`mission.started`, `mission.phase_changed`,
  `mission.completed`, `mission.failed`, `mission.aborted`).
- Enforces the engagement contract: scope, legality flags, destructive-action flags.

### 5.5 Planner

The **Planner** decides *what to do next*.

Two modes:

1. **Template planner** — deterministic expansion of mission profile templates
   into a plan DAG (reproducible, `plan_id = hash(profile, target_scope, params, version)`).
2. **AI planner** — adaptive replanning during execution: given live findings,
   the planner proposes next actions, reorders phases, prunes exhausted branches,
   and requests operator approval for high-risk actions.

Output: a `Plan` (DAG of `PlanStep`s), each step referencing a workflow step,
tool, skill, or agent with explicit preconditions.

### 5.6 Knowledge Base

The **Knowledge Base** is the read-side, versioned corpus of structured knowledge:

- **Tool Knowledge Files** (`07 - Tool Knowledge Base Specification.md`) — CLI
  syntax, capabilities, profiles, error codes, performance, AI usage rules.
- **Mission Profiles** (`12 - Mission Profiles.md`).
- **Playbooks / skills** — reusable detection and validation procedures.
- **CVE / CWE / CAPEC / MITRE ATT&CK / EPSS** reference data (mirrored, versioned).
- **Best practices** and workflow-position rules per tool.

Consumed by the Planner (what to run), the AI Engine (grounding), and the
Workflow Engine (step definitions).

### 5.7 Knowledge Graph

The **Knowledge Graph** stores *entities and their relationships* for a mission
and across missions:

- Nodes: Asset, Domain, Host, IP, Service, Finding, Evidence, CVE, MITRE
  Technique, Payload, Person (OSINT), Certificate.
- Edges: `resolves_to`, `hosts`, `listens_on`, `runs`, `exposes`, `affected_by`,
  `exploits`, `maps_to`, `derived_from`, `correlates_with`.

Used for:

- Attack-path reconstruction and lateral-movement visualization.
- Correlation across findings (`5.11 Correlation Engine`).
- AI grounding (the planner and correlator read subgraphs, never the full graph).
- Reporting visualizations (graph exports).

### 5.8 Plugin System

The **Plugin System** is the extension backbone. See `05 - Plugin SDK Specification.md`.

- **Registry:** discovers, validates, versions, and catalogs plugins.
- **Host:** isolated runtime (subprocess or process-isolated) with a stable ABI.
- **Lifecycle:** register → validate → install → load → execute → update → unload → remove.
- **Permissions:** capability-based sandboxing (filesystem, network, process, AI).
- **Signing:** plugins are signature-verified; unsigned plugins run in restricted mode.
- **Dependency management:** plugin manifest declares dependencies; resolver
  checks versions and conflicts.

### 5.9 Tool SDK & Adapter Layer

Two-tier integration contract:

1. **Tool Adapter SDK** (`06 - Tool Adapter SDK.md`): Python interfaces —
   `BaseAdapter`, `ScannerAdapter`, `CrawlerAdapter`, `EnumeratorAdapter`,
   `AnalyzerAdapter`, `ReporterAdapter`, `ValidationAdapter`.
2. **Tool Knowledge File** (`07 - Tool Knowledge Base Specification.md`): YAML
   metadata describing how to invoke, parse, and reason about a tool.

Every adapter implements: `execute()`, `parse()`, `normalize()`, `validate()`,
`healthcheck()`, `capabilities()`.

### 5.10 Parser Engine & Normalizer

The **Parser Engine** and **Normalizer** convert arbitrary tool output into the
**Unified Security Schema**.

- **Parser Engine:** pluggable parsers per tool+format (JSON, XML, CSV, HTML,
  plain text, regex streams). Streams large outputs; never loads megabytes into memory.
- **Normalizer:** maps parsed structures onto canonical entities (Finding,
  Service, Technology, Certificate, ...). Applies canonicalization (IP/CIDR,
  FQDN case, dedup keys) and enrichment hooks.

Pipeline: `tool stdout/stderr/file → Parser → Normalizer → CanonicalEvent →
Domain entity → Store`.

### 5.11 Correlation Engine

The **Correlation Engine** derives insight from the store and graph:

- **Deduplication:** identical findings collapsed to one canonical finding with
  `occurrences`.
- **Chaining:** evidence links (e.g., subdomain → IP → service → CVE → payload →
  finding) form attack paths.
- **Aggregation:** a vulnerability class across many hosts → one reportable issue
  with affected assets list.
- **Enrichment:** joins CVE → CWE → CAPEC → MITRE → EPSS automatically.
- **Risk aggregation:** per-asset, per-domain, and mission-level risk rollup
  using the risk model.

### 5.12 Reporting Engine

Generates all output artifacts. See `21 - Reporting Standards.md`.

- **Renderers:** JSON, Markdown, HTML, PDF, SARIF, (future: docx, csv).
- **Views:** technical report, executive summary, evidence package, compliance
  mapping (PCI-DSS, ISO 27001, OWASP Top 10, MITRE), timeline.
- **Template system:** versioned report templates; deterministic rendering.
- **Evidence packaging:** bundles screenshots, raw responses, and logs into a
  checksummed archive.

### 5.13 CLI

The **CLI** is a first-class interface. See `19 - CLI Standards.md`.

- Command groups: `mission`, `workflow`, `scan`, `report`, `tool`, `plugin`,
  `knowledge`, `config`, `secret`, `api`, `admin`, `doctor`, `completion`.
- Deterministic, machine-parseable output (`--output json|csv|yaml|text`).
- Rich terminal UX with non-TTY fallback (no colors/ANSI when piped).

### 5.14 REST API

The **REST API** exposes the platform programmatically. See `20 - REST API Standards.md`.

- Framework: FastAPI; OpenAPI 3.1 schema; pydantic v2 models shared with the schema.
- Auth: API keys, OAuth2/OIDC, mTLS, or local (RBAC enforced at the API boundary).
- Async job model: long operations return `202 + job_id`; status polled via `/jobs/{id}`.
- Pagination, filtering, sorting, HATEOAS-lite envelope.

### 5.15 Target Intelligence Database (TIDB)

The **Target Intelligence Database** is the SQL core store. See `09 - Database Design.md`.

- Stores all normalized entities with full history/versioning (bitemporal).
- Indexed for search (FTS) and graph adjacency.
- Written by the Normalizer; read by Correlation, Reporting, and API.

### 5.16 Cache

- **Purpose:** AI responses, DNS lookups, tool outputs (within retention), plan
  expansion, HTTP responses, WHOIS.
- **Backend:** Redis in distributed mode; in-process TTL cache in single-node mode.
- **Keys:** versioned, namespaced, TTL-aware; cache invalidation on schema or
  knowledge-version bump.
- **Cacheability contract:** only idempotent, side-effect-free operations are
  cached; destructive or state-changing operations bypass cache.

### 5.17 Scheduler

- Backend: APScheduler (or equivalent) for cron-like and interval missions.
- Enqueues missions into the Queue; supports time windows, rate limits, and
  scope calendars (e.g., only within approved testing windows).
- Produces the `continuous` mission type for scheduled delta scanning.

### 5.18 Queue

- Purpose: decoupling between delivery/application and execution.
- Backend: RabbitMQ/AMQP (distributed) or in-process async queue (single-node).
- Messages: typed, schema-validated, durable, DLQ (dead-letter queue) on failure.
- Guarantees: at-least-once with idempotent consumers.

### 5.19 Logging

- Structured JSON logging to stdout and rotating file sinks. See `18 - Logging Standards.md`.
- Fields: `ts`, `level`, `logger`, `correlation_id`, `span_id`, `actor`, `module`,
  `message`, `context`, `event_type`.
- Sensitive data is masked at the boundary; secrets never logged.

### 5.20 Configuration

- Layered: defaults → file (YAML) → environment → CLI flags → remote (envs).
- Schema-validated (`hunterx.yaml`), hot-reloadable, deterministic merge order.
- See `04 - Coding Standards.md` §Config and `docs/configuration.md` (project docs).

### 5.21 Secrets

- Backend-agnostic secret store interface (`SecretPort`): local encrypted store,
  Vault, or cloud KMS.
- Secrets never appear in: logs, reports, AI prompts, config dumps, or errors.
- Rotation-aware; scoped per mission/tool with least-privilege delivery.
- See `13 - Security Standards.md`.

### 5.22 Telemetry

- OpenTelemetry-based: traces (spans per workflow step, AI call, tool run),
  metrics (counters, histograms, gauges), and logs correlated by trace ID.
- Exporters: OTLP, Prometheus, or local console in air-gapped mode.
- See `18 - Logging Standards.md`.

### 5.23 Event Bus

- Typed pub/sub with wildcard subscriptions and historical replay.
- Event categories: `mission.*`, `workflow.*`, `task.*`, `tool.*`, `finding.*`,
  `plan.*`, `ai.*`, `plugin.*`, `system.*`, `audit.*`.
- Events are the primary mechanism for cross-subsystem integration (loose coupling).
- Every event carries `correlation_id`, `actor`, `ts`, `payload_schema_version`.

---

## 6. Key Runtime Flows

### 6.1 Mission Lifecycle Flow

```
Operator submits target+profile
  → MissionService validates scope & legality
  → MissionEngine creates Mission (state: DRAFT)
  → Planner expands mission profile into Plan DAG (state: PLANNED)
  → Operator approval gate (if required by profile) (state: APPROVED)
  → WorkflowEngine executes plan steps (state: RUNNING)
        per step:
          tool run → parser → normalizer → store → correlate → update graph
          AI calls for planning/triage/correlation (through AI Engine)
  → Validation phase (proof-of-exploit / false-positive filter) (state: VALIDATED)
  → Correlation & risk aggregation (state: CORRELATED)
  → ReportingEngine generates artifacts (state: COMPLETED)
  → Archive with retention policy (state: ARCHIVED)
```

### 6.2 Tool Execution Flow

```
Workflow step requests tool execution
  → ToolExecutor resolves adapter + knowledge file + sandbox policy
  → Sandbox prepares: scope envelope, time limit, resource limits, env secrets
  → Adapter.execute() runs tool (process or remote worker)
  → ParserEngine parses output (streamed)
  → Normalizer maps to canonical entities
  → CanonicalEvents written to TIDB (transactional, versioned)
  → Events emitted (tool.completed, finding.created)
  → Correlation Engine triggered on new findings
```

### 6.3 AI Reasoning Flow

```
Goal emitted by agent/planner
  → GoalAdapter → structured AITask
  → PromptManager builds prompt (context from KG subgraph + knowledge base)
  → ProviderRouter selects provider/model
  → Middleware (masking, validation, logging)
  → Provider executes (with cache check first)
  → OutputValidator validates schema
  → ConsensusEngine aggregates samples
  → ConfidenceScorer scores confidence
  → Validated ReasoningResult + provenance returned to requester
```

---

## 7. Deployment Topologies

| Topology | Use case | Components |
|----------|----------|------------|
| **Single node** | Personal, small team | Everything in one process/container |
| **Single node + workers** | Team scanning | API/UI process + N worker processes |
| **Distributed** | Enterprise | API nodes, scheduler, worker fleet, shared Redis/Queue/DB/Graph |
| **Air-gapped** | Sensitive environments | All services local; AI local (Ollama); mirrors of external datasets |

All topologies share the same codebase and configuration schema; only the
deployment profile differs.

---

## 8. Architectural Decision Records (Summary)

| ADR | Decision |
|-----|----------|
| ADR-001 | Clean Architecture with ports & adapters; no framework imports in domain |
| ADR-002 | PostgreSQL as primary TIDB; Neo4j for Knowledge Graph; object store for evidence |
| ADR-003 | Async-first execution (asyncio) with process isolation for untrusted tool runs |
| ADR-004 | AI only through provider abstraction; agents never call LLMs directly |
| ADR-005 | YAML knowledge files as single source of tool truth |
| ADR-006 | Event-driven integration via typed Event Bus + Message Bus |
| ADR-007 | Plan IDs and finding hashes are deterministic (content-addressed) |
| ADR-008 | Long operations are async jobs; API returns `202 + job_id` |
| ADR-009 | Plugins execute in isolated sandboxes with capability-based permissions |
| ADR-010 | Secrets isolated in vault-backed secret store; masked at all boundaries |

---

## 9. Cross-Cutting Concerns

- **Security** → `13 - Security Standards.md`
- **Performance** → `14 - Performance Standards.md`
- **Observability** → `18 - Logging Standards.md`
- **Error handling** → `17 - Error Handling Standards.md`
- **Testing** → `15 - Testing Standards.md`

---

## 10. References

- `01 - Vision.md` — mission, scope, philosophy
- `03 - Folder Structure.md` — repository layout
- `05 - Plugin SDK Specification.md` — plugin contracts
- `06 - Tool Adapter SDK.md` — adapter contracts
- `09 - Database Design.md` — TIDB design
- `10 - Workflow Engine.md` — DAG execution
- `25 - Future Expansion.md` — growth path
