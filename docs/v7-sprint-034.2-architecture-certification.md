# HunterX v7 — Sprint 034.2
# FINAL RELEASE GATE — Phase 2: Architecture Certification

**Date:** 2026-08-10
**Phase:** 034.2 (architecture certification only — no feature development)
**Author:** Principal Release Engineer (Phase 034.2)
**Scope:** Layer audit, architecture enforcement, composition root, API/CLI
wiring, end-to-end smoke mission, duplicate-concept analysis, validation,
repairs, release-gate verdict.

---

## 1. Executive Summary

HunterX v7's Clean Architecture is **internally coherent, properly layered,
composed, and executable end-to-end**. The composition root
(`hunterx.platform.build_platform`) assembles the full runtime — Core Engine,
the four v7 facades (TIP, Tool Integration SDK, Tool Integration Factory,
Mission Planning), ~40 application services, the observability stack, the
event bus + event store, the TIDB repository factory and 16 in-memory
repository roles — and every port resolves through a single dependency
container shared by the API, CLI, and tests.

**Phase gate: PASS for architecture certification.** All seven gate criteria
are met (see §13). The **overall V7 release gate remains blocked** by the two
034.1 carry-overs that are repository/release-integrity issues, **not**
architecture defects: P0-01 (entire V7 tree untracked in git) and P1-01
(repo-root V6 shadowing breaks `python -m hunterx[.architecture]`).

### Headline results

| Check | Result |
|---|---|
| `hunterx-arch lint --root .` | **0 errors**, 0 cycles (2 known), 87 warnings (ARCH-007 package-docstring recommendations) |
| Architecture pytest suite | **129 passed** |
| Layer/import/cycle/boundary violations in `src/hunterx` | **0** (verified by lint + manual grep) |
| Composition root runtime trace | create → resolve → mission → plan → execute → persist → retrieve ✔ |
| API wiring (`create_app` + shared container) | ✔ no duplicate containers |
| CLI wiring (`hunterx` console script) | ✔ `version/help/platform/hunt` |
| Smoke mission (`tests/acceptance/test_architecture_smoke.py`, new) | **2 passed** |
| Full test suite | **3257 passed, 8 skipped** |
| `ruff` on touched files / `mypy` configured surface | clean |

---

## 2. Architecture Map

Layers as enforced by `config/architecture.yaml` (single source of truth,
consumed by `hunterx-arch`):

```
flowchart LR
    shared; domain; config; security; infrastructure; application
    knowledge; reporting; scheduler; engines; tools; plugins; agents
    api; cli; platform; architecture; facade; root

    shared --> domain
    domain --> plugins          # ARCH-W-001 waiver only (domain.execution -> plugins.sdk.results)
    domain --> shared
    config --> domain
    config --> shared
    security --> domain
    security --> infrastructure
    infrastructure --> config
    infrastructure --> domain
    infrastructure --> shared
    application --> domain
    application --> engines
    application --> shared
    application --> tools
    knowledge --> domain
    knowledge --> shared
    reporting --> domain
    reporting --> shared
    scheduler --> domain
    scheduler --> shared
    engines --> domain
    engines --> infrastructure
    engines --> reporting
    engines --> shared
    engines --> tools
    tools --> domain
    tools --> plugins
    tools --> shared
    plugins --> domain
    plugins --> shared
    agents --> domain
    agents --> shared
    api --> domain
    api --> shared
    api --> config
    api --> platform
    api --> application
    api --> engines
    cli --> domain
    cli --> shared
    cli --> config
    cli --> platform
    cli --> application
    cli --> engines
    platform --> (every lower layer)     # the single composition root
    architecture --> (leaf layer)
    facade --> domain/shared/infrastructure/application/config/managers
    root --> (side-effect-free package __init__)
```

### 2.1 Layer inventory (18 layers, 801 modules, 182,263 source lines scanned)

| Layer | Package(s) | Role |
|---|---|---|
| `shared` | `hunterx.shared` | ids, masking, time, `Result`, `Container` (DI) |
| `domain` | `hunterx.domain` | entities, value objects, ports, services, events, exceptions |
| `config` | `hunterx.config` | typed settings + YAML loader |
| `security` | `hunterx.security` | policies, permissions, secret resolution |
| `infrastructure` | `hunterx.infrastructure` | db, cache, queue, ai, sandbox, secrets, telemetry, tracing, memory adapters |
| `application` | `hunterx.application` | use-case services + DTOs |
| `knowledge` | `hunterx.knowledge` | knowledge runtime + graph client |
| `reporting` | `hunterx.reporting` | report views, renderers, evidence packaging |
| `scheduler` | `hunterx.scheduler` | mission scheduling + jobs |
| `engines` | `hunterx.engines` | mission, workflow, planner, reasoning, correlation, report, orchestration, adaptive planning |
| `tools` | `hunterx.tools` | tool runtime, Tool Integration Factory/Intelligence, SDK |
| `plugins` | `hunterx.plugins` | plugin host, registry, loader, SDK |
| `agents` | `hunterx.agents` | multi-agent platform |
| `api` | `hunterx.api` | FastAPI factory, routers, DI bridge, middleware |
| `cli` | `hunterx.cli` | command framework + registries |
| `platform` | `hunterx.platform` | **composition root** (`Platform`, `build_platform`) |
| `architecture` | `hunterx.architecture` | the enforcement framework itself (leaf) |
| `facade` / `root` | `hunterx` root + `managers/events/cache/queue/observability/telemetry/utils/exceptions` | re-export facades + side-effect-free package |

---

## 3. Dependency Rules

The ratified dependency matrix (`config/architecture.yaml`, version 1.0.0) is
machine-enforced. Dependency direction is **inward**: a layer may depend only
on itself, `shared`, and the layers below it. Notable rules exercised by this
audit:

- **`platform` is the ONLY layer allowed to bind domain + infrastructure.** The
  matrix lists every lower layer for `platform`; no other layer imports
  infrastructure and domain together (verified).
- **`domain` imports nothing** but `domain`, `shared` (one conditional rule) and
  `plugins.sdk.results` under the time-boxed **ARCH-W-001 waiver**.
- **`shared.di → domain.exceptions`** is an explicit `conditional_imports` rule
  (exceptions are the one contract the foundation may reference).
- **Forbidden imports** (`forbidden_imports`): `hunterx.` → `core.` and
  `hunterx.` → `scripts`; **blocked prefixes**: `core.`, `scripts.`,
  `temp_cli_apps.`.
- **Plugin boundary:** plugins may import only `hunterx.plugins.sdk`,
  `hunterx.domain`, `hunterx.shared`.
- **Tool boundary:** tools may import only `hunterx.tools.sdk`,
  `hunterx.domain`, `hunterx.shared`, `hunterx.plugins.sdk`.
- **Known cycles** (documented benign re-export wiring): ARCH-W-002
  (`tools.sdk` package `__init__` re-exports), ARCH-W-003 (`cli` package
  `__init__` re-exports). Any **new** cycle fails the lint (ARCH-003).

---

## 4. Violations

### 4.1 Forbidden imports — **0**
Grep across `src/hunterx` for `core.` / `scripts` / `temp_cli_apps` imports
returned zero real imports (only prose in docstrings).

### 4.2 Cross-layer violations — **0**
- No `domain`/`shared`/`application`/`knowledge`/`reporting`/`scheduler`
  module imports `hunterx.infrastructure`.
- No `infrastructure` module imports `application`/`engines`/`tools`/`api`/
  `cli`/`platform` (no upward leakage).
- No `tools` module imports `application`/`engines` (no tool-specific
  orchestration).
- No `plugins` module imports `infrastructure`/`application`/`engines` (no
  plugin leakage).
- `security/__init__.py → infrastructure.secrets` is **permitted** by the
  matrix (`security: [security, domain, shared, infrastructure]`).

### 4.3 Circular dependencies — **0** new
Lint: `Cycles: 0 (known: 2)`. The two known cycles are documented and benign.

### 4.4 Service locator abuse — **none**
`container.resolve` is used only at the sanctioned boundaries:
- `platform.platform.Platform.resolve/has` (composition root),
- `api/*` handlers via `get_container().resolve(...)` (FastAPI DI bridge),
- `managers.DependencyManager` (facade),
- `shared.di` internals.
No `domain`/`application`/`engines` code performs a container lookup.

### 4.5 Global mutable state — **1, documented**
`_CONTAINER = AppContainer()` in `src/hunterx/api/deps.py` is the single
module-level mutable singleton. It is the intentional FastAPI dependency
bridge: `create_app` points it at the platform container via
`configure_container`, and handlers read services through it. It is scoped,
documented, and the only one of its kind (all other facade modules are pure
re-exports; the DI `Container` keeps its state per instance, not globally).

### 4.6 Known waiver
**ARCH-W-001**: `hunterx.domain.execution → hunterx.plugins.sdk.results`
(FindingResult/EvidenceResult live in the SDK instead of the domain). Time-boxed
debt tracked for a dedicated refactor sprint. Not expiry-dated → reported as a
known issue, does not fail CI.

### 4.7 Warnings (non-failing)
**87 × ARCH-007**: package `__init__` docstrings missing *recommended*
sections (`responsibilities`, `dependencies`, `extension points`). `hunterx-arch
lint` exits 0 on warnings by default; classified P3 (doc-completeness), not a
violation.

---

## 5. Composition Root Analysis

### 5.1 Entry point
`hunterx.platform.build_platform(settings=None) -> Platform` in
`src/hunterx/platform/assembler.py` is the **single composition root**. The
only place in the system that knows concrete implementations.

### 5.2 What it builds (verified live)
1. **Settings** — `load_default_settings()` unless injected.
2. **Adapters** — memory cache/queue by default (Null* when configured),
   `InMemoryEventBus`, `EnvironmentSecrets`, `NullAIClient`,
   `MemoryTelemetry`, `InMemoryKnowledgeGraph`.
3. **Repositories** — 16 roles default to in-memory implementations; six
   entity roles switch to SQL when a non-default DB URL is configured and
   SQLAlchemy is importable (planning/factory stay in-memory by design).
4. **v7 facades** — `ToolIntelligenceAPI` (TIP, 14 tool families registered),
   `ExecutionEngine` (SDK, all adapters registered + installed),
   `ToolIntegrationFactory`, `MissionPlanningAPI`; plus `ToolMasteryAPI`.
5. **Core Engine** — `CoreEngine` aggregates MissionEngine, WorkflowEngine,
   DeterministicPlanner, TargetCorrelator, DefaultRiskScorer, ReasoningEngine,
   ReportEngine and carries the four facades (identity-shared).
6. **Application services** — ~40 use-case services (missions, findings,
   reports, recon/dns/livehost/topology/tech/crawl/js/auth/authorization/cloud,
   vulnerability knowledge/correlation/validation/proof/finding, professional
   reporting, target intelligence/memory, adaptive planning, autonomous
   orchestration, mission dashboard, offensive orchestration, toolchain).
7. **Observability** — event registry, event store (attached to the bus),
   dead-letter queue, metrics, tracer, health registry with 10 probes,
   telemetry provider.
8. **Container** — every port, facade, engine, manager and service registered
   (~60 registrations). Unknown keys raise `RegistrationNotFoundError`.

### 5.3 Runtime trace (verified end-to-end)
```
build_platform()
  -> settings resolved (config)
  -> adapters built (infrastructure)
  -> repositories built (persistence: mission/finding/target/scan/asset/report/
     planning/factory/orchestration roles)
  -> TIP + ExecutionEngine + ToolFactory + MissionPlanning facades (tools/engines)
  -> CoreEngine assembled
  -> application services wired
  -> container registration (platform/shared.di)
  -> Platform aggregate returned
  -> platform.resolve(MissionRepository) == repo instance
  -> mission_orchestration_service.create_mission(target=...)       # create
  -> adaptive_mission_planning_service.create_mission(...)          # plan (graph v1, actions)
  -> mission_orchestration_service.start / ingest_result / verify    # execute
  -> query.mission(id) / hypotheses(id) / coverage(id)               # persist
  -> service.get(id) / status(id)                                    # retrieve
```

### 5.4 Subsystem participation (through approved interfaces only)
| Subsystem | Interface used | Verified |
|---|---|---|
| Platform / assembler | `build_platform()` | ✔ |
| Core Engine | `platform.core` | ✔ |
| TIP | `platform.tip` (`ToolIntelligenceAPI`) | ✔ |
| Execution Engine | `platform.execution_engine` (`ExecutionEngine`) | ✔ |
| Tool Factory | `platform.tool_factory` (`ToolIntegrationFactory`) | ✔ |
| Mission Planning | `platform.mission_planning` (`MissionPlanningAPI`) | ✔ |
| Event Bus | `platform.event_bus` + attached event store | ✔ mission.* events persisted |
| TIDB | `platform.tidb` (`TidbRepositoryFactory`) | ✔ records round-trip |
| Config | `platform.settings` | ✔ |
| Observability | `platform.event_store`, `platform.health` | ✔ |

---

## 6. API Wiring

`hunterx.api.app:create_app(settings=None, *, register_health=True, platform=None)`
is the API factory (FastAPI).

- **When `platform` is provided** — the caller's platform is used and
  `configure_container(platform.container)` points the shared `AppContainer`
  at it. Handlers resolve the same service instances as the rest of the
  runtime.
- **When `platform` is omitted** — one is built from settings (via
  `build_platform`), then the same `configure_container` path is used.
- **No duplicate containers.** `create_app(platform=...)` reuses the caller's
  container (verified: `get_container().resolve(MissionOrchestrationService) is
  platform.mission_orchestration_service`); `create_app()` builds exactly one.
  The `_CONTAINER` bridge is the single holder, reassigned at composition.
- Routes: `/health` + mission orchestration, mission dashboard, finding,
  reporting, target memory, tools, adaptive mission planning (138 routes).
  Exception handlers map domain errors to HTTP responses.
- API integration tests via `fastapi.testclient.TestClient` exercise
  `create_app(platform=platform)` end-to-end
  (`tests/integration/test_mission_orchestration_api.py`,
  `test_mission_dashboard_api.py`, `tests/component/test_toolchain_api.py`).

---

## 7. CLI Wiring

`hunterx.cli:main` (console script) → `CliApplication` →
`register_default_commands(app, platform=None)`:

- When `platform` is omitted, `build_platform()` runs once at registration
  time and **every command shares that same platform** (`platform.<service>`
  access only — no per-command construction).
- Commands registered: `version`, `help`, `config`, `platform` (live
  composition report), plus `mission *`, `hunt *`, `finding *`, `report *`,
  `target *`, `campaign *`, `tools *`.
- Verified live via the installed console script: `hunterx version` →
  `HunterX v7.0.0`; `hunterx platform` → composition JSON; `hunterx help` →
  full V7 command surface (no V6 `scan/doctor/module`); `hunterx hunt` →
  creates + starts a mission and returns the overview.
- CLI wiring tests pass (`tests/unit/test_platform.py::TestCliWiring`,
  `tests/engineering/test_cli.py`).

---

## 8. Mission Smoke Test

New certification test: **`tests/acceptance/test_architecture_smoke.py`**
(2 tests, passing). It drives one minimal mission through the composition
root and approved interfaces only — no subsystem is constructed directly:

1. **Composition** — `build_platform()` returns a `Platform`; Core Engine,
   TIP, Execution Engine, Tool Factory, Mission Planning, Mastery all present;
   Core Engine identity-shares the facades.
2. **Target → Mission** — `mission_orchestration_service.create_mission(
   objective="full_security_assessment", target="shop.example.com")`.
3. **Planning** — `adaptive_mission_planning_service.create_mission` produces
   a deterministic plan (plan_version 1, action graph, topological order) and
   ranked candidate actions.
4. **Execution** — `start()` + `ingest_result()` (synthetic nuclei output),
   hypothesis add/update/verify, finding registration, coverage record.
5. **Persistence** — `mission_orchestration_query_service` reads the mission,
   hypotheses, coverage and observations back from the TIDB store.
6. **Retrieval** — `get()` + `status()` return the mission; `coverage_ratio > 0`.
7. **Event bus** — `platform.event_store.replay(event_type="mission.*")`
   returns the published mission events.
8. **API/CLI sharing** — `create_app(platform=...)` shares the container;
   `register_default_commands(app, platform=...)` exposes the platform.

Also verified live through the installed `hunterx` console script (`hunterx
hunt smoke-cert.example.com`).

---

## 9. Duplicate Concept Analysis

Per the instruction: relationships were established, intentional separation
was confirmed, accidental duplication was identified, and **nothing was
redesigned** (none of it is release-blocking).

| Concept | Definitions | Relationship | Verdict |
|---|---|---|---|
| **Mission** | `domain/entities/mission.py::Mission` (core scheduled-op); `domain/adaptive_mission_planning/mission.py::AdaptiveMission`; `domain/mission_orchestration/mission.py::OrchestratedMission`; `domain/orchestration/models.py::OffensiveMission` | `OrchestratedMission.mission: AdaptiveMission` — **explicit composition** (documented reuse); core `Mission` is a thin lifecycle envelope; `OffensiveMission` is a disjoint third lineage | Related (adaptive→orchestrated); core is legacy lineage; `OffensiveMission` is a separate product surface — **intentional-but-unconsolidated** (P2) |
| **MissionPlan** | `domain/mission_planning.py::MissionPlan` (phase-based); `engines/mission_planning/planner.py::MissionPlanner`; `engines/orchestration/planner.py::MissionPlanner`; adaptive plan (graph-as-plan); `domain/services/planner.py::PlannerService`+`engines/planner.py::DeterministicPlanner` | Each engine↔domain pair is explicit; the two `MissionPlanner` classes share a name but have disjoint semantics; `PlannerService.Plan` and `MissionPlan` are disjoint contracts | **Accidental duplication** of planner contracts/naming (P2) |
| **ExecutionGraph** | `domain/mission_planning.py::ExecutionGraph`; `domain/adaptive_mission_planning/graph.py::AdaptiveExecutionGraph`; `engines/orchestration/graph.py::MissionDependencyGraph` | Three hand-rolled DAGs duplicating Kahn/wave/cycle logic; no cross-imports. Topology/attack-surface/knowledge graphs are deliberately separate (explicit composition) | **Accidental duplication** of the three execution DAGs (P2) |
| **Planning Engine** | `PlannerService`, `DeterministicPlanner`, 2×`MissionPlanner`, `DeterministicMissionPlanner`, 2×`ToolSelectionEngine` (`domain/adaptive_mission_planning/toolchain.py` vs `tools/intelligence/selection.py`) | Five "planner" concepts; each has explicit relationships to its own domain models but no shared planning contract; the two `ToolSelectionEngine`s share only the `ToolMasteryPort` idea | **Naming collisions + duplication** (P2) |
| **Workflow Engine** | `engines/workflow.py::WorkflowEngine` (single) | Domain references workflow by name only; no duplicate workflow classes anywhere | **Intentional / no duplication** |
| **Finding** | `domain/entities/finding.py::Finding` (legacy canonical); `domain/entities/tidb/finding_orchestration.py::FindingRecord` + 17 projections | Explicit bridge — `VulnerabilityFindingService._save_legacy_finding` projects `FindingRecord → Finding` (same id, content-hash dedup); documented backward compatibility | **Intentional with explicit relationship** |
| **Evidence** | `domain/entities/evidence.py::Evidence` (orphaned); `vulnerability_finding.models::EvidenceItem`; `vulnerability_validation/evidence.py::EvidenceBuilder`→`vulnerability_proof/evidence.py::ProofEvidenceBuilder` (explicit reuse); `reporting/evidence.py` | Validation→proof chain explicitly reuses one evidence builder ("there is no second evidence system"); `EvidenceItem` vs `ValidationEvidence` are sibling-context value types; legacy `Evidence` has no consumers | **Mixed** — chain is intentional; sibling types + orphan are P2 |
| **Proof** | `domain/vulnerability_proof/models.py` (pure) ↔ `domain/entities/tidb/proof.py` (persistence projection) ↔ `reporting/proof.py` (view); separate `finding_orchestration` `PoC`/`ReplayRecord` | Wave-15 stack internally consistent (explicit projection pairs); Sprint-028 `PoC`/`ReplayRecord` is a second, disjoint proof lineage | **Intentional internally; second lineage is P2** |

**Release-blocking?** No. None of the duplication violates the ratified
layering, causes data loss, or produces divergent behavior across a single
approved interface — each lineage is wired to its own services/repositories and
all tests pass. **Recommended (P2):** a shared `Mission` port/protocol,
de-collision of the two `MissionPlanner`/`ToolSelectionEngine` names, one
execution-graph primitive, and removal of the orphaned
`domain/entities/evidence.py`.

---

## 10. Repairs

| ID | Repair | Status |
|---|---|---|
| 034.2-R1 | Added **`tests/acceptance/test_architecture_smoke.py`** — the missing single-file end-to-end composition smoke mission (target → mission → planning → execution → persistence → retrieval, plus API/CLI container sharing and event-store participation). | Done, passing (ruff/mypy clean) |
| 034.2-R2 | Confirmed architecture enforcement gate behavior; documented the `hunterx-arch` PATH dependency and the concrete `python -m hunterx.architecture` shadowing manifestation (see §11/§12). No code change — environment/documentation only. | Done |

No P0/P1 architecture violations were found, so no architectural repair was
required. The 87 ARCH-007 docstring warnings and all duplication items are
classified (P2/P3) and deliberately **not** redesigned per the sprint mandate.

---

## 11. Remaining Technical Debt

| ID | Issue | Class |
|---|---|---|
| P2-08 | `ruff check src` still red: **77 pre-existing violations** (unchanged from 034.1). The mandatory CI ruff gate (test.yml/ci.yml) is red. My **touched files** lint clean; this is pre-existing tech debt. | P2 (pre-existing) |
| P2-14 | **Duplicate concepts** (see §9): three mission lifecycles, two `MissionPlanner`, three execution DAGs, two `ToolSelectionEngine`, two PoC/replay lineages, orphaned `domain/entities/evidence.py`. | P2 |
| P2-15 | `mypy strict` is **not** green on the full `src` surface (e.g. 58 errors under `src/hunterx/platform`). The configured mypy gate is deliberately narrow (`eng src/hunterx/shared`) and passes; the wider surface is pre-existing debt. | P2 |
| P2-16 | `engines/orchestration/engine.py` constructs in-memory repositories as constructor defaults (permitted by the matrix but couples the engine to a concrete adapter). Prefer injected ports only. | P3 |
| P3-05 | 87 × ARCH-007 package-docstring recommendations missing (warnings, non-failing). | P3 |
| P3-06 | `api/deps._CONTAINER` module-level singleton (documented FastAPI DI bridge). | P3 (accepted design) |
| P3-07 | Eng `architecture` gate falls back to `python -m hunterx.architecture`, which fails from the repo root due to P1-01 shadowing when the `hunterx-arch` console script is not on `PATH`. | P3 (env) |

---

## 12. Release Blockers

Carried forward from 034.1 — **repository/release integrity**, not architecture:

| ID | Issue | Why it blocks release |
|---|---|---|
| P0-01 | **Entire V7 delivery untracked in git**: `src/`, V7 `tests/`, `eng/`, `alembic/`, `config/`, `capabilities/`, V7 workflows, `requirements.lock`, V7 docs, `THIRD_PARTY_NOTICES`, `CODEOWNERS`, `dependabot.yml`. A clean `main` clone still contains only the retired V6 flat package. | Release tagging/packaging cannot proceed from a committed state. |
| P1-01 | Repo-root V6 shadowing: `import hunterx` / `python -m hunterx` / `python -m hunterx.architecture` from the repo root resolve to the V6 flat package. Only `tests/conftest.py` compensates for tests. | Breaks the developer `python -m` entry points and the eng `architecture` gate fallback path. Needs V6 tree relocation or a documented mitigation. |

Neither of these is an **architecture** defect: the ratified entry points
(`hunterx`, `hunterx-arch`, `hunterx.api.app:create_app`, `python hunterx.py`)
all run V7, and the architecture layer/composition/API/CLI are certified green
in this phase.

---

## 13. Validation

| Check | Result |
|---|---|
| `hunterx-arch lint --root .` | 0 errors, 0 cycles (2 known), 87 warnings — exit 0 ✔ |
| `hunterx-arch graph --root .` | Layer graph emitted ✔ |
| Forbidden-import enforcement (empirical) | Clean repo exit 0; injecting `import core.agents` → **ARCH-002 ERROR (fails)**; injecting `domain → infrastructure` → **ARCH-001 ERROR (fails)** ✔ |
| `pytest tests/architecture` | **129 passed** |
| `pytest tests/unit` | **2008 passed** |
| `pytest tests/component` | **86 passed** |
| `pytest tests/integration` | **127 passed** |
| `pytest tests/golden tests/acceptance tests/security` | **708 passed, 8 skipped** (incl. new smoke test) |
| `pytest tests/engineering tests/performance tests/framework` | **199 passed** |
| **Full suite total** | **3257 passed, 8 skipped** |
| `python -m eng gates --gate architecture` | PASS (with `hunterx-arch` on PATH) ✔ |
| `python -m eng gates --gate docs` | 7/7 PASS ✔ |
| `python -m eng gates --gate hygiene` | PASS ✔ |
| `python -m eng gates --gate compliance` | PASS ✔ |
| `ruff check tests/acceptance/test_architecture_smoke.py` | clean ✔ |
| `ruff check src/hunterx/platform src/hunterx/shared src/hunterx/architecture` | clean ✔ |
| `ruff check src` | 77 pre-existing (P2-08) ✖ — unchanged |
| `mypy eng src/hunterx/shared` (configured gate surface) | clean ✔ |
| `mypy tests/acceptance/test_architecture_smoke.py` | clean ✔ |
| `python -m compileall -q src/hunterx` | clean ✔ |
| `hunterx version` / `hunterx platform` / `hunterx help` / `hunterx hunt` (console script) | V7 output, exit 0 ✔ |
| `create_app(platform=...)` shares container; `create_app()` fresh | ✔ |
| `python hunterx.py version` | `HunterX v7.0.0` ✔ |

---

## 14. Final Verdict

### Architecture certification — **PASS**

- [x] **Architecture rules enforced** — `hunterx-arch lint` 0 errors; pytest
      architecture 129/129; the check **fails** on forbidden imports, layer
      violations, cycles and plugin/tool boundary violations (proven
      empirically).
- [x] **No P0/P1 architecture violations** — zero forbidden/cross-layer/cycle/
      boundary violations; only a time-boxed waiver (ARCH-W-001), one
      documented global (API DI bridge), and non-failing docstring warnings.
- [x] **Composition root works** — `build_platform()` returns a fully wired
      `Platform`; container resolves every port/service; SQL switching tested.
- [x] **API wiring works** — `create_app` shares the platform container; no
      duplicate containers; handler/service identity verified.
- [x] **CLI wiring works** — console script uses the same composition
      architecture; `version/platform/help/hunt` verified.
- [x] **End-to-end smoke mission works** — new
      `tests/acceptance/test_architecture_smoke.py` drives target → mission →
      planning → execution → persistence → retrieval through approved
      interfaces; all subsystems participate.
- [x] **Tests pass** — 3257 passed, 8 skipped; touched files ruff/mypy clean.

**STOP — Phase 034.2 complete. Do not proceed to 034.3 automatically.**

Overall V7 release gate remains **BLOCKED** by the 034.1 carry-overs (P0-01
untracked V7 tree; P1-01 repo-root V6 shadowing), which are release-integrity
issues outside the architecture scope. Resolve them before tagging the release.
