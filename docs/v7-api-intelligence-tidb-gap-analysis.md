---
layout: default
title: "Sprint 014 — API Intelligence: TIDB Gap Analysis — HunterX"
permalink: /v7-api-intelligence-tidb-gap-analysis/
---

# Sprint 014 — API Intelligence: TIDB Gap Analysis

- Capability: API Discovery & API Attack-Surface Intelligence
- Sprint: 014 · Wave 8
- Status: Ratified
- Companion: [Implementation Plan](./v7-api-intelligence-implementation-plan.md)

## 1. Scope of analysis

This report inventories the Target Intelligence Database (TIDB) surface that the
API intelligence capability reads and writes, identifies what already exists
(reused unchanged), what is extended, and what is created new, and fixes the
migration + registry + exporter steps needed so the canonical API inventory is a
first-class TIDB citizen — never memory-only.

## 2. Existing TIDB surface reused unchanged (no writes)

| Existing table/entity | Why it is a consumption input |
|---|---|
| `tidb_web_origins` (`WebOrigin`) | Origin keys (`scheme://host[:port]`) that scope API host discovery. |
| `tidb_url_observations` (`URLObservation`) | URL set to mine for endpoint-like paths. |
| `tidb_web_api_endpoints` (`WebAPIEndpoint`) | Undocumented REST endpoint candidates. |
| `tidb_websocket_endpoints` (`WebSocketEndpoint`) | WebSocket surface candidates. |
| `tidb_web_graphql_endpoints` (`WebGraphQLEndpoint`) | GraphQL surface candidates + introspection hint. |
| `tidb_web_authentication_boundaries` (`AuthenticationBoundary`) | Auth-boundary hints (basic/bearer/session). |
| `tidb_js_intelligence_endpoints` (`JSIntelligenceEndpoint`) | Client-side endpoint hints (`fetch`/`xhr`/`axios`/`graphql`/`websocket`). |
| `tidb_js_intelligence_routes` (`JSIntelligenceRoute`) | Route-pattern hints (param markers). |
| `tidb_js_intelligence_configuration` | `api-base-url` / environment hints. |
| `tidb_js_intelligence_auth` | Auth reference hints (oauth/oidc/token/login). |
| `tidb_js_intelligence_services` | Third-party API services. |
| `tidb_technology_observations` | Framework/API-style technology evidence (e.g. Spring, Django, FastAPI, Swagger UI). |
| `tidb_topology_relationships` | Existing host→service edges reused for correlation; API edges are written here. |
| `tidb_apis` + endpoint/scheme/model tables (`domain/entities/tidb/api.py`) | Legacy documented-surface records — **kept unchanged**, read for correlation, and mirrored into the new canonical inventory rather than replaced. |

These are **read-only inputs**: the API intelligence service folds them into
observations; it never mutates them.

## 3. Existing TIDB surface extended (schema additions)

None of the existing API tables (`tidb_apis`, `tidb_rest_endpoints`,
`tidb_graphql_endpoints`, `tidb_soap_endpoints`, `tidb_rpc_services`,
`tidb_authentication_schemes`, `tidb_authorization_models`) require column
additions or constraint changes. The Wave-8 canonical inventory is carried by
**new** tables (below), which is the least-risk path: no migration of populated
legacy rows, no breaking changes, and the registry's name-based auto-mapping
(`<Name>Model` ↔ `<Name>`) keeps the existing entities untouched.

## 4. New TIDB entities required (created)

All new entities derive from `TidbEntity` and get mirrored ORM models in
`infrastructure/db/sql/tidb_models/api_intelligence_models.py`. Names follow the
`<Entity>Model` ↔ `<Entity>` convention so the generic registry derives
repositories automatically.

### 4.1 `APIRun` → `tidb_api_runs`
Run observability record.

| Column | Type | Notes |
|---|---|---|
| `mission_id` | String(26) | index |
| `target_key` | String(512) | index |
| `target_id` | String(26) nullable | |
| `status` | String(16) | running/completed/failed/partial |
| `mode` | String(16) | passive/active/hybrid |
| `hosts` / `apis` / `operations` / `parameters` / `schemas` / `auth_schemes` / `changes` / `conflicts` | Integer | counts |
| `started_at` / `completed_at` | String(32) | |
| `summary` | JSON | tools, stats |
| `correlation_id` | String(26) | index |

### 4.2 `APIHost` → `tidb_api_hosts`
Canonical discovered API origin/host.

| Column | Type | Notes |
|---|---|---|
| `target_key` | String(512) | |
| `scheme` | String(8) | https/http |
| `host` | String(255) | index |
| `port` | Integer nullable | |
| `base_url` | String(512) | canonical API base |
| `origin_key` | String(512) | `scheme://host[:port]` |
| `api_kinds` | JSON | observed ApiKind values |
| `api_count` / `endpoint_count` | Integer | |
| `documented` | Boolean | any spec found |
| `confidence` | Float | |
| `evidence` | JSON | evidence fragments |
| `correlation_id` / `mission_id` / `execution_id` | String | provenance |
| `first_seen` / `last_seen` | String(32) | shared envelope |

### 4.3 `APISpec` → `tidb_api_specs`
Located spec document.

| Column | Type | Notes |
|---|---|---|
| `host_id` | String(26) | owning APIHost |
| `target_key` | String(512) | |
| `source_url` | String(512) | where the spec was located |
| `spec_type` | String(16) | openapi2/openapi3/openapi31/swagger/wsdl/graphql-sdl/postman |
| `format` | String(8) | json/yaml/xml/sdl |
| `version` | String(64) | spec's own version field |
| `title` | String(255) | spec title |
| `operation_count` / `schema_count` | Integer | |
| `integrity` | String(128) | content hash |
| `size_bytes` | Integer | |
| `confidence` | Float | |
| `correlation_id` / `mission_id` / `execution_id` | String | provenance |

### 4.4 `APIVersion` → `tidb_api_versions`
Canonical API version + version-state.

| Column | Type | Notes |
|---|---|---|
| `host_id` | String(26) | |
| `api_name` | String(255) | canonical API name |
| `version` | String(64) | canonical version |
| `spec_version` | String(64) | version declared by a spec |
| `path_prefix` | String(255) | e.g. `/v1`, `/api/v2` |
| `documented` | Boolean | |
| `operation_count` | Integer | |
| `endpoint_hash` | String(64) | digest for change detection |
| `first_seen` / `last_seen` | String(32) | |

### 4.5 `APIOperation` → `tidb_api_operations`
Canonical endpoint operation.

| Column | Type | Notes |
|---|---|---|
| `api_id` | String(26) | owning APIVersion |
| `host_id` | String(26) | |
| `method` | String(16) | index |
| `path` | String(512) | raw path |
| `normalized_path` | String(512) | param-placeholder-normalized |
| `path_hash` | String(64) | dedup key component |
| `operation_id` | String(128) | from spec when present |
| `documented` | Boolean | spec-derived vs discovered |
| `deprecated` | Boolean | |
| `tags` | JSON | |
| `content_type` / `response_content_type` | String(128) | |
| `auth_required` | Boolean | |
| `pagination` | String(16) | none/page/cursor/offset |
| `has_filters` | Boolean | |
| `rate_limit_hint` | String(16) | none/declared/observed |
| `parameter_count` | Integer | |
| `security_schemes` | JSON | referenced scheme names |
| `confidence` | Float | |
| `sources` | JSON | provenance tool ids |
| `correlation_id` / `mission_id` | String | |

### 4.6 `APIParameter` → `tidb_api_parameters`
Operation parameter.

| Column | Type | Notes |
|---|---|---|
| `operation_id` | String(26) | owning APIOperation |
| `name` | String(255) | |
| `location` | String(16) | query/path/header/cookie/body |
| `required` | Boolean | |
| `param_type` | String(64) | string/integer/.../enum name |
| `schema_digest` | String(64) | param schema fingerprint |
| `nullable` | Boolean | |
| `default_value` | Text nullable | |
| `enum_values` | JSON | when finite |
| `pattern` | Text nullable | regex when present |
| `source` | String(32) | spec/web/js |
| `confidence` | Float | |

### 4.7 `APISchema` → `tidb_api_schemas`
Request/response schema fingerprint (bounded: digest + shallow model).

| Column | Type | Notes |
|---|---|---|
| `operation_id` | String(26) nullable | |
| `api_id` | String(26) nullable | when schema is API-global |
| `name` | String(255) | schema/component name |
| `direction` | String(8) | request/response |
| `kind` | String(16) | object/array/primitive/ref |
| `content_type` | String(128) | application/json ... |
| `digest` | String(64) | SHA-256 of normalized model |
| `depth` | Integer | bounded traversal depth |
| `fields` | JSON | flattened field table (name, type, required, nullable, nested digest) |
| `source` | String(32) | spec/web/js |
| `confidence` | Float | |

### 4.8 `APIAuthentication` → `tidb_api_authentications`
Per API/host authentication scheme (intelligence, no secrets).

| Column | Type | Notes |
|---|---|---|
| `api_id` | String(26) nullable | |
| `host_id` | String(26) nullable | |
| `scheme_type` | String(32) | basic/bearer/apikey/oauth2/oidc/session/cookie/mutual-tls/none |
| `name` | String(255) | scheme name from spec |
| `token_location` | String(64) | header/query/cookie |
| `flows` | JSON | oauth2 flows present |
| `scopes` | JSON | |
| `indicators` | JSON | evidence strings |
| `confidence` | Float | |
| `documented` | Boolean | |
| `source` | String(32) | spec/web/js/tidb |

### 4.9 `APIAuthorization` → `tidb_api_authorizations`
Authorization model indicators.

| Column | Type | Notes |
|---|---|---|
| `api_id` | String(26) nullable | |
| `model_type` | String(32) | rbac/abac/acl/scopes/none/unknown |
| `roles` | JSON | |
| `scopes` | JSON | |
| `indicators` | JSON | |
| `confidence` | Float | |
| `source` | String(32) | |

### 4.10 `APIRateLimit` → `tidb_api_rate_limits`
Rate-limit indicators.

| Column | Type | Notes |
|---|---|---|
| `api_id` | String(26) nullable | |
| `host_id` | String(26) nullable | |
| `style` | String(16) | header/token-bucket/fixed-window/unknown |
| `headers` | JSON | observed rate-limit header names |
| `declared` | Text nullable | limit text from spec/docs |
| `confidence` | Float | |
| `source` | String(32) | |

### 4.11 `APIPagination` → `tidb_api_paginations`
Pagination style per endpoint/API.

| Column | Type | Notes |
|---|---|---|
| `api_id` | String(26) nullable | |
| `operation_id` | String(26) nullable | |
| `style` | String(16) | page/cursor/offset/none/unknown |
| `limit_param` | String(64) | |
| `offset_param` / `cursor_param` | String(64) nullable | |
| `total_source` | String(16) | body/header/unknown |
| `confidence` | Float | |

### 4.12 `APIFilter` → `tidb_api_filters`
Filter capabilities observed on list endpoints.

| Column | Type | Notes |
|---|---|---|
| `operation_id` | String(26) nullable | |
| `filter_param` | String(128) | |
| `style` | String(32) | query/field/expression/unknown |
| `operators` | JSON | observed operators |
| `confidence` | Float | |

### 4.13 `APIEvidence` → `tidb_api_evidence`
Evidence fragments backing API intelligence.

| Column | Type | Notes |
|---|---|---|
| `subject_type` | String(32) | host/spec/version/operation/parameter/auth |
| `subject_id` | String(26) | |
| `evidence_type` | String(32) | spec-document/http-header/html/script/tidb-intelligence/tool-output/known-signature |
| `value` | Text | |
| `source` | String(255) | |
| `strength` | String(16) | strong/moderate/weak |
| `tool_id` | String(128) | |
| `detail` | Text | |
| `integrity` | String(128) | optional hash |

### 4.14 `APIConflict` → `tidb_api_conflicts`
Preserved contradictions (version/identity/source).

| Column | Type | Notes |
|---|---|---|
| `subject` | String(512) | affected key (host/api/operation) |
| `subject_type` | String(32) | |
| `conflict_type` | String(32) | version/identity/source/method |
| `observations` | JSON | |
| `selected` | String(512) | |
| `selected_source` | String(255) | |
| `reason` | Text | |
| `confidence` | Float | |
| `mission_id` / `correlation_id` | String | |

### 4.15 `APIChange` → `tidb_api_changes`
Historical added/removed/changed events.

| Column | Type | Notes |
|---|---|---|
| `subject_type` | String(32) | host/api/version/operation/parameter/auth |
| `subject` | String(512) | |
| `change_type` | String(16) | added/removed/changed |
| `previous` / `current` | Text | |
| `tool_id` | String(128) | |
| `confidence` | Float | |
| `mission_id` / `correlation_id` | String | |

### 4.16 Relationship-free design decision

The canonical inventory carries its own `host_id`/`api_id`/`operation_id`
foreign keys instead of a dedicated entity-relationship table. Cross-entity
relationships into the **attack-surface topology** are the only edges persisted
elsewhere: `tidb_topology_relationships` rows of type `EXPOSES` (host→API),
`SERVES` (origin→API), `ROUTES_TO` (URL→endpoint) and `SERVES` (API→operation).
This avoids a duplicate relationship store and keeps the topology as the single
projection layer.

## 5. Migration plan

- **New migration**: `alembic/versions/<rev>_api_intelligence_tables.py`.
  `down_revision` = head (`7ab1a304e8bb` technology tables). Creates the 16
  tables above (4.1–4.15 + index columns). Downgrade drops them.
- All tables follow the existing pattern: `TidbModelMixin` base columns
  (`id`, `created_at`, `updated_at`, `first_seen`, `last_seen`, `version`,
  `revision`, `schema_version`, `deleted_at`, `meta`) plus capability columns.
- `tidb_models/__init__.py` imports the new module and appends all
  `<Entity>Model` names to `__all__` so registry auto-mapping and
  `create_all`/autogenerate see them.

## 6. Registry + repository + exporter wiring

- `infrastructure/db/sql/registry.py` — name-based auto-mapping already derives
  `<Name>Model` ↔ `<Name>`; no change required beyond the `__all__` registration
  (verified mapping logic reads the models module `__all__`).
- `infrastructure/db/sql/crud.py`/`repositories.py` — generic `SqlCrudRepository`
  + `RowMapper` handle the new entities unchanged.
- **Memory / test path**: `InMemoryTidbRepositoryFactory` auto-discovers entities
  from the same registry — new entities become available to integration tests
  without new code.
- **Report/exporter paths**: `APIRun` + summary JSON feed the reporting layer;
  no new exporter subsystem is created (reuse existing reporting).

## 7. Verification steps (gates)

1. `python -m alembic upgrade head` succeeds.
2. `python -m alembic check` / autogenerate produces no unexpected diff for the
   new tables.
3. `pytest tests/architecture` passes (no forbidden imports; every new module has
   a docstring; no cycles; layer rules hold).
4. Integration test writes/reads each new entity through the in-memory factory.
5. `pytest tests/security` confirms no credentials/secrets stored and no scope
   expansion.
