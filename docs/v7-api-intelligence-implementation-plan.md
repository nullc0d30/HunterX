---
layout: default
title: "Sprint 014 — API Discovery & API Attack-Surface Intelligence: Implementation Plan — HunterX"
permalink: /v7-api-intelligence-implementation-plan/
---

# Sprint 014 — API Discovery & API Attack-Surface Intelligence: Implementation Plan

- Capability: API Discovery & API Attack-Surface Intelligence
- Sprint: 014 · Wave 8
- Status: Ratified
- Companion report: [TIDB Gap Analysis](./v7-api-intelligence-tidb-gap-analysis.md)
- Capability doc (deliverable): `v7-api-intelligence` (pending)

## 1. Objective

Add a Wave-8 intelligence capability that discovers, classifies, models,
correlates and historically tracks the **API attack surface** of authorized
assets. It consumes the intelligence already produced by Wave-1..7 (web crawl,
JavaScript, technology fingerprinting, live-host, DNS, topology, recon) and the
historical TIDB surface, and produces a canonical, evidence-backed API inventory
persisted to the TIDB, projected into the existing topology, emitted as `api.*`
events, and exposed through a reporting query service.

**Non-negotiable boundaries:** discovery and intelligence only. No exploitation,
no auth bypass, no credential handling, no unbounded crawling, no state-changing
probes. Scope is enforced at target admission and per-observation persist.

## 2. Guiding constraints (from the mission brief)

- **Never redesign foundations.** Reuse Sprints 007–013 contracts: Tool SDK
  (`ExecutionContextBuilder`/`ExecutionEngine`/`OutputCollector`),
  `TidbEntity` dataclasses + ORM mirror + `TidbRepositoryFactory`, generic
  `registry.py` auto-mapping, event catalog + typed events, `Platform`
  composition root, profile-driven mission planning, TIP taxonomy.
- **No second database/graph/cache/event bus.** The TIDB is the system of
  record; topology relationships live in `tidb_topology_relationships`.
- **Do not auto-activate discovered external API hosts.** Everything discovered
  is intelligence; scope expansion requires explicit operator action.
- **Deterministic** confidence, classification and diffing; no randomness.
- **In-process parsers only** for OpenAPI 2/3/3.1 (JSON/YAML via `pyyaml`),
  GraphQL introspection SDL, WSDL, Postman collections, web crawl + JS-derived
  endpoint hints. No new parser dependency, no subprocess.
- **ARCH-001..007 + docstrings enforced.** Every new module carries a module
  docstring; layer boundaries respected; tools only reach the SDK seam.

## 3. Pipeline architecture

`ApiService.run()` orchestrates the phases below; phases publish
`api.phase.started` events; failure publishes `api.intelligence.failed`.

1. **Scope admission** — `ApiScopeEnforcer.allows_target()`; reject out-of-scope.
2. **Collection** — run each selected registered `tools/api` adapter through the
   ExecutionEngine; each adapter yields canonical `APIObservation` records under
   the pipeline payload key `apis`.
3. **Existing intelligence fold-in** — convert web crawl endpoint/websocket/
   graphql/auth-boundary observations, JS endpoint/route hints, technology
   observations (framework/api-style), and previously persisted TIDB records.
4. **Classification** — `ApiClassifier` assigns `ApiKind` (REST, GraphQL,
   WebSocket, SOAP, RPC, Unknown) + API surface form (OpenAPI spec, Swagger,
   undocumented, GraphQL SDL, WSDL, etc.) with deterministic confidence.
5. **OpenAPI/Swagger modeling** — in-process parser normalizes OpenAPI 2/3/3.1
   into canonical operations/parameters/schemas/auth; GraphQL SDL + schema
   shape analysis; WebSocket endpoint modeling; WSDL → SOAP operations.
6. **Validation** — `ApiValidator` filters invalid/empty records; drops
   out-of-scope observations.
7. **Correlation** — `ApiCorrelator` groups observations into canonical APIs and
   hosts; merges duplicate endpoints; resolves version/identity conflicts.
8. **Confidence scoring** — `ApiConfidenceEngine` per-observation deterministic
   score combining evidence strength, source weight, corroboration.
9. **History diffing** — `ApiHistory.compare(historical, current)` yields
   added/removed/changed events (`ApiChange`).
10. **Persistence** — write API/version/operation/parameter/schema/auth/rate-limit
    /evidence/conflict/change/run entities to the TIDB.
11. **Topology projection** — derive `EXPOSES`/`SERVES`/`ROUTES_TO` edges
    (host → API/endpoint, origin → API, URL → endpoint).
12. **Events + summary** — emit `api.*` events; publish
    `api.intelligence.completed`.

`ApiQueryService` reads the TIDB and answers the reporting queries (inventory,
by-host, versions, endpoints, undocumented, historical, spec, auth, changes,
conflicts, run history).

## 4. Implementation order

| # | Area | Files |
|---|------|-------|
| 1 | TIDB entities + ORM + migration + registry | `domain/entities/tidb/api.py` (extend), new `domain/entities/tidb/api_intelligence.py`, `infrastructure/db/sql/tidb_models/api_intelligence_models.py`, `tidb_models/__init__.py`, `alembic/versions/...api_intelligence_tables.py` |
| 2 | Events | `domain/events/enums.py` (add `API`), `catalog.py`, `types.py` (typed constructors) |
| 3 | Domain models | `domain/api/models.py`, `classification.py`, `scope.py`, `confidence.py`, `correlator.py`, `conflicts.py`, `history.py`, `strategy.py`, `validator.py`, `parsers/` (openapi.py, graphql.py, websocket.py, soap.py, postman.py, hints.py) |
| 4 | Tool adapters | `tools/api/{base,openapi,swagger,graphql,websocket,soap,hints,registry,tip,__init__}.py` |
| 5 | Application service | `application/api.py` (`ApiService`, `ApiQueryService`) |
| 6 | Wiring | `platform/assembler.py`, `platform/platform.py`, `config/capabilities/api-intelligence.json` |
| 7 | Docs | `docs/v7-api-intelligence.md`, this plan, TIDB gap report |
| 8 | Golden + tests | `tests/golden/api/`, `tests/unit/test_api_*.py`, `tests/integration/test_api_platform.py`, `tests/acceptance/test_api_acceptance.py`, `tests/security/test_api_security.py`, `tests/performance/test_api_benchmarks.py` |

## 5. Key contracts

### 5.1 TIDB entities (canonical inventory)

New entities (full list + columns in the gap report):

- `APIRun` — run observability record.
- `APIHost` — discovered API origin/host (per-host base URL, scheme).
- `APISpec` — located spec document (openapi/swagger/wsdl/sdl/postman + source URL).
- `APIVersion` — canonical API version + spec-derived version + endpoint hash.
- `APIOperation` — canonical endpoint operation (method, path, normalized path).
- `APIParameter` — query/path/header/cookie params (name, location, required, type).
- `APISchema` — request/response schema fingerprint (kind, digest).
- `APIAuthentication` — scheme per API/host (type, token location, hints).
- `APIAuthorization` — authz model (scopes, roles, rbac hints).
- `APIRateLimit` — observed/declared rate-limit indicators.
- `APIPagination` — pagination style indicators (page, cursor, offset, limit).
- `APIFilter` — filter capabilities observed on list endpoints.
- `APIConflict`, `APIChange` — conflict + history-change records.
- `APIEvidence` — per-record evidence fragment.
- `APIParameterRelationship`/relationship-free: conflicts/changes keep it simple.

Extensions to existing `domain/entities/tidb/api.py`: no breaking changes; the
existing `API`, `RESTEndpoint`, `GraphQLEndpoint`, `SOAPEndpoint`, `RPCService`,
`AuthenticationScheme`, `AuthorizationModel` entities are kept and reused by the
service when mapping *documented* surfaces, while the new `api_intelligence`
entities carry the full Wave-8 canonical inventory. The gap report documents
exactly which columns are added.

### 5.2 Events (`api.*`)

`API = "api"` category. Specs + typed constructors (see catalog patch):

- `api.intelligence.started`, `api.phase.started`, `api.intelligence.completed`,
  `api.intelligence.failed`
- `api.host.discovered`, `api.spec.discovered`, `api.api.discovered`
- `api.endpoint.discovered`, `api.version.discovered`, `api.auth.discovered`,
  `api.authorization.discovered`
- `api.rate_limit.discovered`, `api.pagination.discovered`, `api.filter.discovered`
- `api.change.detected`, `api.conflict.detected`, `api.undocumented.detected`,
  `api.historical.discovered`

### 5.3 Domain model summary

- `ApiKind` enum (REST, GRAPHQL, WEBSOCKET, SOAP, RPC, UNKNOWN).
- `ApiSurfaceForm` enum (OPENAPI, SWAGGER, GRAPHQL_SDL, GRAPHQL_SCHEMA_SHAPE,
  WSDL, POSTMAN, HINTS_UNDOCUMENTED, WEB_CRAWL, JS_HINT).
- `ApiTarget` (value + target_type).
- `ApiBatch` (raw observations, apis, operations, changes, conflicts, summaries).
- `APIObservation`, `APIOperationObservation`, `APISpecObservation`,
  `APIHostObservation`, `APIAuthObservation`, `APIChange`, `ApiConflict`,
  `ApiExecutionSummary`, `EvidenceStrength`, `ApiEvidence`.
- `ApiStrategy` + `ApiStrategyBuilder`; `ApiScopePolicy` + `ApiScopeEnforcer`;
  `ApiConfidenceEngine`; `ApiCorrelator`; `ApiConflictResolver`;
  `ApiHistory`; `ApiValidator`; `ApiClassifier`.

### 5.4 Tool adapters (all in-process)

Registry ids under `API_TOOL_IDS`: `api-openapi`, `api-swagger`, `api-graphql`,
`api-websocket`, `api-soap`, `api-hints` (web-crawl + JS fold-in). All extend a
shared `ApiToolAdapter`; in-process variants implement `run()` (no CLI) and
`parse_output()` returns `[]`. The `api-hints` adapter is the fold-in path that
maps already-persisted web/JS observations (no network). `api-openapi`/`api-soap`
fetch the spec document through the existing injectable `FetchFn` seam (like
`tools/tech/signature.py`) with a cache TTL; `api-graphql`/`api-websocket` derive
shape from existing web/JS observations + optional fetched SDL.

TIP: `register_api_tools(tip)` registers the six specs, reusing capability id
`api-discovery` from the taxonomy.

### 5.5 Application service

`ApiService.__init__` mirrors `FingerprintService`: engine, stores, event_bus,
cache, scope, strategy_builder, classifier, parser, correlator, conflicts,
validator, history, confidence. `run()` performs the phase pipeline above.
`ApiQueryService` mirrors `TechnologyQueryService` (inventory, by_host, versions,
endpoints, undocumented, historical, spec, auth, changes, conflicts, runs).

### 5.6 Platform wiring

- `assembler.py`: `register_api_tools(tip)` + `register_api_adapters(engine)`,
  build `api_service`/`api_query_service`, register instances, add to `Platform`.
- `platform.py`: new attributes `api_service`, `api_query_service`.

## 6. Scope & security behavior

- `ApiScopePolicy`: authorized roots, cidrs, ips, excluded sets, excluded URL
  patterns; `fail_open_empty_policy=True`, `deny_by_default=False` (matches
  technology fingerprinting).
- `ApiScopeEnforcer.allows_target()` gates the whole run;
  `allows_observation()` gates every persist.
- **No auto-enable of discovered hosts**: discovered origins are stored as
  observations only; nothing re-scans them in the same run.
- No requests are made to discovered external hosts; spec fetching is limited to
  the in-scope target origin (exact-origin policy), with a per-fetch size cap and
  timeout.

## 7. Performance targets

- Correlate 1k observations: well under 100ms (benchmarked).
- OpenAPI 3.1 document parse of a 5k-line spec: under 250ms (benchmarked).
- Run query: under 50ms against 1k persisted APIs.

## 8. Quality gates (all must pass)

- `ruff check` + `ruff format --check`
- `mypy` (strict) per `pyproject.toml`
- `pytest tests/architecture`
- `pytest tests/unit tests/integration tests/acceptance tests/security tests/performance`
- `python -m eng.readiness` / gate script as configured in CI
- Alembic upgrade head + autogenerate produces no diff for new tables
- New modules: docstrings on every module (ARCH-006); no forbidden imports
  (ARCH-002); no cycles (ARCH-003).

## 9. Risks / mitigations

- **Spec size**: cap fetched spec bytes (e.g. 5 MB) + operation count; truncate
  with evidence.
- **WSDL/XSD complexity**: model operations + namespaces at the depth required
  for inventory; skip deep XSD traversal.
- **GraphQL introspection**: only when a prior tool already captured the SDL; no
  live introspection probe.
- **Duplicate endpoints across sources**: correlator key = `(host, method,
  normalized_path)` with conflict resolution, mirroring the technology
  correlator.
- **OpenAPI 3.1 + JSON Schema**: digest schema shapes (hashed) rather than full
  schema trees to avoid unbounded storage.
