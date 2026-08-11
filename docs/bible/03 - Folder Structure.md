# 03 — HunterX Repository & Folder Structure

**Status:** Ratified
**Version:** 1.0.0
**Applies to:** Entire `HunterX` repository layout

---

## 1. Purpose

This document defines the **complete project hierarchy**. Every folder has a
defined purpose, ownership, and dependency rules. A change to this structure
requires an Architecture Review (`24 - Quality Assurance.md` §6).

---

## 2. Top-Level Layout

```
hunterx/
├── docs/                     # Public-facing documentation (Jekyll site)
├── docs/bible/               # THIS Development Bible (engineering foundation)
├── src/
│   └── hunterx/              # Python package source root (see §3)
├── plugins/                  # Bundled & community plugin packages (see §4)
├── tools/                    # Tool integration packages: adapters + knowledge files (see §5)
├── config/
│   ├── hunterx.yaml          # Default configuration
│   ├── knowledge.schema.yaml # Knowledge file JSON Schema
│   ├── plugin.schema.yaml    # Plugin manifest JSON Schema
│   └── profiles/             # Mission profile definitions (12 profiles)
├── data/
│   ├── mirror/               # Mirrored external datasets (CVE, CWE, CAPEC, EPSS, MITRE)
│   ├── payloads/             # Payload dictionaries (community-sourced)
│   └── golden/               # Golden test datasets (see 15 - Testing Standards)
├── tests/                    # Test suite root (see §6)
├── scripts/                  # Dev/ops helper scripts (non-shipping)
├── deploy/                   # Deployment artifacts
│   ├── docker/
│   ├── helm/
│   ├── systemd/
│   └── air-gap/
├── examples/                 # Runnable examples for missions, plugins, adapters
├── pyproject.toml            # Build config, deps, lint/test config
├── Dockerfile
├── docker-compose.yml
├── .github/                  # CI/CD, issue templates, security advisories
└── LICENSE, NOTICE, SECURITY.md, CONTRIBUTING.md, CHANGELOG.md, README.md
```

---

## 3. Python Package Root (`src/hunterx/`)

> **Note on layout:** The current repository uses a flat `hunterx/` package
> directory. The ratified target layout below uses a `src/` layout. Migration is
> a tracked engineering task; all **new** modules must follow the target layout.

```
src/hunterx/
├── __init__.py               # Version, exports, no side effects
├── py.typed                  # PEP 561 marker
├── cli/
│   ├── __init__.py
│   ├── app.py                # Typer app & command registration
│   ├── groups/
│   │   ├── mission.py
│   │   ├── workflow.py
│   │   ├── scan.py
│   │   ├── report.py
│   │   ├── tool.py
│   │   ├── plugin.py
│   │   ├── knowledge.py
│   │   ├── config.py
│   │   ├── secret.py
│   │   ├── api.py
│   │   └── admin.py
│   ├── render/               # Terminal/JSON/YAML renderers
│   └── params.py             # Shared CLI parameter objects
├── api/
│   ├── __init__.py
│   ├── app.py                # FastAPI app factory
│   ├── routes/               # One module per resource
│   ├── deps/                 # Auth, pagination, RBAC dependencies
│   ├── schemas/              # pydantic request/response models
│   └── middleware.py
├── domain/                   # PURE domain layer (no framework imports)
│   ├── entities/             # Target, Asset, Finding, Evidence, Mission, ...
│   ├── value_objects/        # Port, Service, Risk, Severity, Confidence, Payload
│   ├── services/             # Planner, Correlator, Deduplicator, RiskScorer, Validator
│   ├── ports/                # ToolPort, StorePort, AIPort, QueuePort, CachePort,
│   │                         # EventPort, SecretPort, SandboxPort, LogPort, MetricPort
│   ├── events/               # Typed domain events
│   └── exceptions/           # Domain exception hierarchy
├── application/              # Use-case layer
│   ├── missions.py
│   ├── workflows.py
│   ├── reports.py
│   ├── auth.py
│   ├── admin.py
│   └── dto.py                # Request/response DTOs
├── infrastructure/           # Adapters (implement domain ports)
│   ├── db/
│   │   ├── sql/              # SQLAlchemy models, migrations (Alembic)
│   │   ├── graph/            # Neo4j driver & mappers
│   │   ├── object_store/     # S3 / local FS evidence store
│   │   └── search/           # Full-text index
│   ├── cache/                # Redis adapter
│   ├── queue/                # RabbitMQ adapter
│   ├── event_bus/            # In-process + distributed event bus
│   ├── secrets/              # Vault / encrypted-file adapter
│   ├── sandbox/              # Docker / subprocess sandbox adapters
│   ├── ai/                   # OpenAI, Ollama, local adapters + middleware
│   ├── logging/              # JSON logger, OpenTelemetry exporters
│   └── config/               # YAML/env loader, schema validation
├── engines/
│   ├── mission.py            # Mission Engine
│   ├── workflow.py           # Workflow Engine (DAG executor)
│   ├── planner.py            # Template + AI planner
│   ├── reasoning.py          # AI decision core (Goal→AITask→ValidatedResult)
│   ├── correlation.py        # Correlation Engine
│   └── report.py             # Reporting Engine
├── agents/                   # Multi-agent platform
│   ├── base.py               # SecurityAgent abstract contract
│   ├── registry.py
│   ├── orchestrator.py
│   ├── coordinator.py
│   ├── scheduler.py
│   ├── memory.py
│   ├── context.py
│   ├── events.py             # Agent event bus
│   ├── messaging.py          # Message bus
│   └── plugins/              # Recon, ThreatModeling, Planning, Payload,
│                             # Verification, Risk, Reporting, PurpleTeam,
│                             # Learning, Coordinator agents
├── plugins/                  # Plugin Host, registry, loader, SDK bindings
│   ├── host.py               # Isolated plugin runtime
│   ├── registry.py
│   ├── loader.py
│   ├── manifest.py           # Manifest validation
│   ├── permissions.py        # Capability-based permission model
│   └── sdk/                  # Public SDK types exposed to plugin authors
├── tools/                    # Tool runtime (adapter-side)
│   ├── adapter.py            # Adapter base classes
│   ├── executor.py           # ToolExecutor
│   ├── parser.py             # Parser Engine
│   ├── normalizer.py         # Normalizer
│   └── sandbox.py            # Tool sandbox policy
├── knowledge/                # Knowledge Base runtime
│   ├── loader.py             # Knowledge file loader & validation
│   ├── registry.py
│   ├── graph.py              # Knowledge Graph client & mappers
│   └── mirror/               # Dataset mirror syncers
├── scheduler/
│   ├── service.py
│   └── jobs.py
├── reporting/
│   ├── renderers/            # JSON, MD, HTML, PDF, SARIF renderers
│   ├── templates/            # Versioned report templates
│   ├── evidence.py           # Evidence packaging
│   └── views.py              # Report view models
├── shared/                   # Cross-cutting helpers (no domain logic)
│   ├── ids.py                # Content-addressed IDs (ULID + hashes)
│   ├── masking.py
│   ├── time.py
│   └── result.py             # Result/outcome types
└── config/
    ├── loader.py
    └── hunterx.yaml          # Packaged defaults
```

---

## 4. Plugins Root (`plugins/`)

```
plugins/
├── marketplace/              # Community plugin index (metadata + manifests)
├── bundled/
│   ├── <plugin-name>/        # Each plugin is a self-contained package
│   │   ├── plugin.yaml       # Manifest (see 05 - Plugin SDK Specification)
│   │   ├── __init__.py
│   │   ├── plugin.py         # Plugin entry point
│   │   ├── hooks/            # Hook implementations
│   │   └── tests/
└── SDK.md                    # Pointer to 05 - Plugin SDK Specification
```

Each plugin package must contain its own `plugin.yaml` manifest and tests; it
must not import private internals from `src/hunterx` outside the public SDK.

---

## 5. Tool Integration Root (`tools/`)

```
tools/
├── <tool-id>/                # One directory per integrated tool
│   ├── knowledge.yaml        # REQUIRED: Tool Knowledge File (07 - ...)
│   ├── adapter.py            # REQUIRED: adapter implementing 06 - Tool Adapter SDK
│   ├── parser.py             # REQUIRED: parser for tool output
│   ├── normalizer.py         # REQUIRED: canonical mapping
│   ├── workflows.yaml        # Workflow rules / position
│   ├── mission_rules.yaml    # Mission applicability
│   ├── ai_rules.yaml         # AI usage rules for this tool
│   ├── tests/                # REQUIRED: adapter, parser, normalizer tests
│   └── README.md             # Tool documentation
└── index.yaml                # Tool registry index (capabilities → tools)
```

Every integrated tool must satisfy the full checklist in `22 - Tool Integration Standard.md`.

---

## 6. Tests Root (`tests/`)

```
tests/
├── unit/                     # Fast, isolated, no I/O beyond in-memory
│   ├── domain/
│   ├── application/
│   ├── engines/
│   └── knowledge/
├── integration/              # Real adapters against test doubles/services
│   ├── db/
│   ├── api/
│   ├── tools/                # Runs real tool binaries (marked/skippable)
│   └── ai/                   # Mocked providers
├── golden/                   # Golden dataset regression tests (see 15)
├── acceptance/               # End-to-end mission runs on sandboxed targets
├── performance/              # Benchmarks & load tests
├── security/                 # Sandbox escape, secret-leak, scope-violation tests
├── conftest.py
└── fixtures/
```

---

## 7. Dependency Rules Between Folders

| From | May import | Must NOT import |
|------|------------|-----------------|
| `domain` | stdlib, shared value types | anything in `infrastructure`, `api`, `cli`, `engines` |
| `application` | `domain`, `shared` | `infrastructure` directly (use ports) |
| `infrastructure` | `domain` ports, `shared` | other infrastructure internals (use adapters) |
| `engines` | `domain`, `application`, `infrastructure` via composition | CLI/API renderers |
| `cli` | `application`, `engines` | framework internals |
| `api` | `application`, `engines` | CLI internals |
| `plugins/`, `tools/` | public SDK only | private internals of `src/hunterx` |

---

## 8. File Naming Conventions

- Python modules: `snake_case.py`.
- Test modules: `test_<module>.py`.
- YAML/JSON data: `snake_case.yaml` / `snake_case.json`.
- Tool knowledge files: `knowledge.yaml` inside each tool directory.
- Migration files: Alembic revision hashes; never hand-edited.
- Templates: `*.j2` (Jinja) or `*.html` under `reporting/templates/`.

---

## 9. What Belongs Where (Decision Table)

| Artifact | Location |
|----------|----------|
| Domain entity/port/service | `src/hunterx/domain/` |
| HTTP route | `src/hunterx/api/routes/` |
| CLI command group | `src/hunterx/cli/groups/` |
| Tool adapter | `tools/<tool-id>/adapter.py` |
| Tool knowledge | `tools/<tool-id>/knowledge.yaml` |
| Plugin | `plugins/<plugin>/` |
| Mission profile | `config/profiles/<id>.yaml` |
| Golden dataset | `data/golden/` |
| Migration | `src/hunterx/infrastructure/db/sql/migrations/` |
| Report template | `src/hunterx/reporting/templates/` |
| Deploy manifests | `deploy/` |
| CI pipeline | `.github/workflows/` |
| Dev scratch scripts | `scripts/` (never referenced by shipped code) |

---

## 10. Enforcement

- Architecture lint (imports) runs in CI: domain/application layers are scanned
  for forbidden imports.
- New top-level folders require an Architecture Review ADR.
- `scripts/` content must never be imported by shipping code.
