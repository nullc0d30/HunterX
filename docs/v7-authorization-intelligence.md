---
layout: default
title: HunterX v7 Authorization & Access-Control Intelligence
description: >-
  Architecture and reference for the HunterX v7 Authorization & Access-Control
  Intelligence capability (Sprint 016 / Wave 10): authorization subjects, roles,
  groups, permissions, scopes, claims, policies (RBAC/ABAC/ACL/PBAC/ReBAC),
  resources, actions, resource-identifier metadata, ownership, tenant
  boundaries, administrative surfaces, function/object/field-level access
  control, frontend/backend enforcement, API/GraphQL/WebSocket/service
  authorization, decision indicators and historical change detection.
  Intelligence only — never tests authorization.
permalink: /v7-authorization-intelligence/
---

# HunterX v7 Authorization & Access-Control Intelligence

**Status:** Ratified (Sprint 016 · Wave 10)
**Version:** 1.0.0
**Owner:** HunterX Architecture Council

---

## 1. Purpose / Scope

The **Authorization & Access-Control Intelligence** capability gives HunterX a
persistent, evidence-backed understanding of the *authorization model* of an
authorized target — without exploiting it. The capability discovers,
classifies, models, correlates, normalizes, scores, persists, historizes and
reports on:

- authorization subjects (users, roles, groups, service accounts, API clients,
  applications, tenants, organizations, workspaces, projects, system,
  anonymous)
- roles, groups, permissions, scopes, claims and policies
- resources, actions and resource-identifier metadata
- ownership relationships and tenant boundaries
- administrative surfaces
- function-, object- and field-level access-control indicators
- frontend authorization logic (route guards, `isAdmin`, `hasPermission`, …)
- backend authorization indicators (middleware, decorators, guards, policy
  engines)
- API authorization requirements (per-operation role/scope/permission)
- GraphQL, WebSocket and service-to-service authorization
- observed/documented authorization decision indicators (ALLOW/DENY/
  CONDITIONAL)
- mass-assignment structural indicators
- historical changes and deterministic differential analysis

**Security boundary:** intelligence only. The capability never performs IDOR,
BOLA, BFLA, privilege escalation, forced browsing, unauthorized resource
access, role/scope manipulation, tenant-isolation bypass, GraphQL
authorization bypass, mass-assignment exploitation, parameter tampering,
access-control fuzzing or credential attacks. It never substitutes an
identifier, never accesses another user's or tenant's resources and never
stores raw authorization-header values, JWT claims, API secrets or PII.

---

## 2. Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│  AuthorizationService.run()  (application/authorization.py)              │
│                                                                          │
│  DISCOVER → MODEL → CLASSIFY → CORRELATE → NORMALIZE → SCORE             │
│           → PERSIST → DIFF → HISTORIZE → MAP → REPORT                    │
│                                                                          │
│  scope admission → ExecutionEngine (authorization-analysis adapter)      │
│  → existing-intelligence fold-in (TIDB)                                  │
│  → AuthorizationClassifier → AuthorizationValidator                      │
│  → AuthorizationCorrelator → AuthorizationConfidenceEngine               │
│  → AuthorizationHistory → persist to TIDB → topology edges               │
│  → authorization.* events                                                │
└─────────────────────────────────────────────────────────────────────────┘
            ▲                                                        │
   inputs:  │                                                        ▼
   HTTP snapshot, JS content, API schemes/operations,            TIDB
   GraphQL metadata, WebSocket endpoints, policy docs,      authorization_*
   observed URLs, historical TIDB intelligence                tables + topology
                                                              + events
```

The capability is composed of:

| Layer | Modules |
|---|---|
| Domain | `src/hunterx/domain/authorization/` — models, analyzer, classification, confidence, correlator, history, scope, strategy, validator |
| Tool SDK | `src/hunterx/tools/authorization/` — in-process `authorization-analysis` adapter, registry, TIP profile |
| Application | `src/hunterx/application/authorization.py` — `AuthorizationService`, `AuthorizationQueryService` |
| TIDB | `src/hunterx/domain/entities/tidb/authorization_intelligence.py` + ORM mirror + Alembic migration |
| Events | `authorization.*` category in `domain/events/{enums,catalog,types}.py` |
| Topology | `src/hunterx/domain/topology/enums.py` authorization entity kinds |
| Composition | `src/hunterx/platform/assembler.py`, `src/hunterx/platform/platform.py` |

---

## 3. Authorization Model

The capability models authorization as a set of canonical, evidence-backed
records (see §TIDB Mapping). Each record carries the USS envelope (id,
timestamps, versioning, soft-delete) plus provenance (`source`, `tool_id`,
`target_key`, `correlation_id`, `mission_id`), evidence fragments, indicators
and a deterministic confidence in `[0, 1]`.

### 3.1 The core principle

Authorization intelligence answers: **WHO** can perform **WHICH ACTION** on
**WHICH RESOURCE** under **WHICH POLICY** within **WHICH TENANT** using
**WHICH AUTHENTICATION CONTEXT** based on **WHICH EVIDENCE**.

```
SUBJECT → ACTION → RESOURCE → POLICY → SCOPE/TENANT → DECISION INDICATOR
```

### 3.2 Authentication vs Authorization

Authentication intelligence (Sprint 015) answers "Who are you?"; authorization
intelligence answers "What are you allowed to access?". Roles/scopes/
permissions/tenants are shared concepts: the authorization capability consumes
Sprint 015 indicators and builds its own richer authorization model. No
authorization relationship is inferred without evidence.

### 3.3 Anonymous vs Authenticated surface

Authorization decisions are never fabricated. Only safely observed statuses
(401/403 → DENY, 2xx on an already-authorized resource → ALLOW) or documented
decisions produce a `DecisionKind` indicator.

---

## 4. Subject Model

Authorization subjects are represented with the canonical kinds: user, role,
group, service-account, api-client, application, tenant, organization,
workspace, project, system, anonymous and unknown. HunterX never fabricates an
identity — every subject is backed by evidence (script configuration, claims,
service-account declarations, OpenAPI client identifiers).

---

## 5. Action Model

Actions are normalized to a canonical set (read, list, create, update, delete,
execute, approve, publish, manage, configure, invite, assign, revoke, export,
import, rotate, deploy, administer, other) while **preserving the original
terminology** (e.g. `POST /users/{id}/disable` → action `disable` with
`original="disable"`).

---

## 6. Resource Model

Resources are identified by type, identifier, endpoint, parent, tenant, owner,
source, evidence and confidence. Resource kinds cover users, accounts,
organizations, tenants, workspaces, projects, repositories, documents, files,
reports, findings, assets, API keys, tokens, integrations, webhooks,
deployments, configurations, billing objects, security policies, roles and
permissions.

### 6.1 Resource-Identifier Intelligence

Identifier metadata (numeric, UUID, ULID, slug, hash, composite, opaque, path,
query, body, header, GraphQL, encoded) is recorded from paths, query
parameters and API operation templates. Identifiers are **never modified** and
**never substituted** — accessing another identifier is prohibited.

---

## 7. Ownership Intelligence

Ownership indicators (owner_id, user_id, account_id, tenant_id,
organization_id, created_by, updated_by, author, creator, principal, subject,
owner, member, manager, administrator) are recorded evidence-backed. Ownership
is never inferred merely from naming when contradictory evidence exists.

---

## 8. Tenant Authorization

Tenant boundaries (id, header, claim, path, query, subdomain) are correlated
with Sprint 014/015. The model builds `Tenant → Subject → Role → Resource →
Action` only when evidence supports it. **No cross-tenant isolation is ever
tested.**

---

## 9. Policy Intelligence

The analyzer detects policy models: RBAC, ABAC, ACL, PBAC, ReBAC and custom
(Casbin, OPA, Cerbos, Permit.io, Keycloak). Policy presence is **not** inferred
from framework presence alone; each policy observation carries the mechanism
(middleware, decorator, guard, policy-engine) and the evidence that triggered
it.

---

## 10. Administrative Surfaces

The administrative attack-surface inventory covers admin login, admin APIs,
admin routes, admin UI, management APIs, role/permission/user/configuration
management, security controls, audit access, integration/credential/API/token
management and billing management. **No access is attempted.**

---

## 11. Function / Object / Field-Level Access Control

- **Function-level:** privileged functions (admin APIs, role assignment, user
  deletion, configuration changes, deployment, billing, security settings,
  credential management, export/import, audit access) with the observed
  endpoint, method and role/scope requirement.
- **Object-level:** endpoints operating on specific objects (e.g.
  `GET /users/{id}`) with resource, identifier, action and parent.
- **Field-level:** potentially restricted fields (role, permissions, owner_id,
  tenant_id, billing, is_admin, security_settings, api_keys, tokens,
  internal_id, audit) detected from schemas, OpenAPI, GraphQL, responses and
  frontend code.

---

## 12. Frontend & Backend Authorization

- **Frontend:** `isAdmin`, `hasPermission`, `hasRole`, `can()`, `authorize()`,
  `checkAccess()`, route guards and feature flags are correlated from static
  JavaScript. Frontend checks are explicitly classified as **frontend-only**
  indicators — never treated as authoritative backend enforcement.
- **Backend:** middleware, decorators, guards, policies, authorization
  services, permission/role/resource-ownership/tenant/scope checks are recorded
  from observable behaviour and declared API metadata.

---

## 13. API / GraphQL / WebSocket / Service Authorization

- **API correlation:** every operation is mapped to endpoint, method,
  authentication, role, scope, permission, resource, action, tenant and policy
  with evidence and confidence.
- **GraphQL:** queries, mutations, subscriptions, types, fields and
  directive-based authorization are represented from schema metadata; no
  unauthorized GraphQL operations are performed.
- **WebSocket:** connection/channel/topic/subscription authorization and
  channel membership are recorded only from observable/documented evidence.
- **Service-to-service:** service accounts, API clients, machine identities,
  client credentials, mTLS and internal-API authentication indicators are
  recorded; service credentials are never used.

---

## 14. Decision Model

Observed/documented decision structures are represented as ALLOW, DENY,
CONDITIONAL or UNKNOWN. A decision is never claimed unless it was safely
observed (HTTP status on an already-authorized in-scope resource) or
documented.

---

## 15. Historical Intelligence & Differential Analysis

`AuthorizationHistory.compare(historical, current)` diffs snapshots
deterministically by canonical subject key and value, producing
added/removed/changed changes. This detects new/removed roles, changed
permissions/scopes, new admin endpoints, changed ownership/tenant models,
changed policy models, changed frontend/backend enforcement, changed API
security schemes and changed field exposure. Identical snapshots yield zero
changes.

---

## 16. Evidence

Every record carries provenance: `source`, `tool_id`, `mission_id`,
`correlation_id`, `execution_id`, timestamps, asset, URL, detection method
(evidence type), a masked evidence value and a deterministic confidence.
Evidence types include `http-header`, `http-status`, `html`, `url-pattern`,
`javascript`, `openapi-security`, `api-operation`, `graphql`, `websocket`,
`policy-config`, `js-indicator`, `documentation`, `response`,
`tidb-intelligence`, `tool-output`, `known-signature` and `other`.

### 16.1 Confidence

Confidence is deterministic and explainable (`AuthorizationConfidenceEngine`):

- **Strong evidence** — direct HTTP observation (status/headers), OpenAPI
  security/operation declarations, valid policy documentation, direct JS API
  calls, multiple independent sources.
- **Weak evidence** — URL naming, HTML text, single heuristic, historical-only
  data.

The score combines the declared evidence-aware confidence with the strongest
evidence factor and source reliability, with corroboration boosts and conflict
discounts.

---

## 17. TIDB Mapping

29 canonical TIDB entities in `authorization_intelligence.py`:

| Entity | Table |
|---|---|
| `AuthorizationRun` | `tidb_authorization_runs` |
| `AuthorizationSubject` | `tidb_authorization_subjects` |
| `AuthorizationRole` | `tidb_authorization_roles` |
| `AuthorizationGroup` | `tidb_authorization_groups` |
| `AuthorizationPermission` | `tidb_authorization_permissions` |
| `AuthorizationScope` | `tidb_authorization_scopes` |
| `AuthorizationClaim` | `tidb_authorization_claims` |
| `AuthorizationPolicy` | `tidb_authorization_policies` |
| `AuthorizationResource` | `tidb_authorization_resources` |
| `AuthorizationAction` | `tidb_authorization_actions` |
| `AuthorizationIdentifier` | `tidb_authorization_identifiers` |
| `AuthorizationOwnership` | `tidb_authorization_ownership` |
| `AuthorizationTenant` | `tidb_authorization_tenants` |
| `AuthorizationAdminSurface` | `tidb_authorization_admin_surfaces` |
| `AuthorizationFunctionLevel` | `tidb_authorization_function_level` |
| `AuthorizationObjectLevel` | `tidb_authorization_object_level` |
| `AuthorizationFieldLevel` | `tidb_authorization_field_level` |
| `AuthorizationFrontend` | `tidb_authorization_frontend` |
| `AuthorizationBackend` | `tidb_authorization_backend` |
| `AuthorizationApiCorrelation` | `tidb_authorization_api_correlations` |
| `AuthorizationGraphQL` | `tidb_authorization_graphql` |
| `AuthorizationWebSocket` | `tidb_authorization_websockets` |
| `AuthorizationService` | `tidb_authorization_services` |
| `AuthorizationDecision` | `tidb_authorization_decisions` |
| `AuthorizationMassAssignment` | `tidb_authorization_mass_assignment` |
| `AuthorizationAccessControl` | `tidb_authorization_access_control` |
| `AuthorizationObservation` | `tidb_authorization_observations` |
| `AuthorizationEvidence` | `tidb_authorization_evidence` |
| `AuthorizationChange` | `tidb_authorization_changes` |

All tables share the USS envelope (`TidbModelMixin`). The registry maps
`XModel ↔ X` automatically; the in-memory and SQL repository factories pick the
entities up without configuration. Migration:
`b7e2f9a4c1d3_authorization_intelligence_tables`.

---

## 18. Topology

Authorization records are projected into the existing attack-surface topology
(`tidb_topology_relationships`) as edges:

```
WEB_ORIGIN ──SERVES──▶ ADMIN_SURFACE
WEB_ORIGIN ──SERVES──▶ AUTHORIZATION_RESOURCE
WEB_ORIGIN ──SERVES──▶ AUTHORIZATION_ENDPOINT
WEB_ORIGIN ──USES────▶ AUTHORIZATION_ROLE
WEB_ORIGIN ──USES────▶ AUTHORIZATION_PERMISSION
WEB_ORIGIN ──USES────▶ AUTHORIZATION_POLICY
WEB_ORIGIN ──USES────▶ AUTHORIZATION_TENANT
```

New topology entity kinds: `AUTHORIZATION_SUBJECT`, `AUTHORIZATION_ROLE`,
`AUTHORIZATION_PERMISSION`, `AUTHORIZATION_SCOPE`, `AUTHORIZATION_POLICY`,
`AUTHORIZATION_RESOURCE`, `AUTHORIZATION_ACTION`, `AUTHORIZATION_TENANT`,
`ADMIN_SURFACE`, `AUTHORIZATION_ENDPOINT`.

---

## 19. Security

- **No authorization exploitation.** No IDOR/BOLA/BFLA, privilege escalation,
  forced browsing, unauthorized resource access, role/scope/JWT manipulation,
  tenant-isolation bypass, GraphQL authorization bypass, mass-assignment
  exploitation, parameter tampering or access-control fuzzing.
- **No identifier substitution.** Identifiers are metadata-only.
- **No scope expansion.** The enforcer authorizes the analysed asset; a
  discovered role/resource/admin surface on an external host is recorded as
  metadata and never requested or persisted if out of scope.
- **No sensitive storage.** Authorization-header values, JWT claims, API
  secrets and PII are never persisted; retained context snippets are masked
  (`shared.masking`).
- **Deterministic** detection, classification, confidence and diffing.
- **Fail-closed scope** with `fail_open_empty_policy=True`.

---

## 20. Testing

| Suite | Files | Focus |
|---|---|---|
| Golden | `tests/golden/authorization/*.json` | deterministic input fixtures |
| Unit | `test_authorization_domain.py`, `test_authorization_analyzer.py`, `test_authorization_service.py`, `test_authorization_tip.py` | models, serialization, detection, pipeline, TIP |
| Integration | `test_authorization_platform.py` | platform wiring + end-to-end |
| Acceptance | `test_authorization_acceptance.py` | Sprint 016 acceptance criteria |
| Security | `test_authorization_security.py` | leakage, scope, malformed input, contamination |
| Performance | `test_authorization_benchmarks.py` | analysis, correlation, query baselines |

### Quality gates

- `ruff check` clean; `mypy` (strict) clean on the capability modules.
- `pytest tests/unit tests/integration tests/acceptance tests/security tests/performance tests/architecture`.
- `alembic upgrade head` / `downgrade base` clean; new tables registered in the
  TIDB metadata.

## 21. References

- `config/capabilities/authorization-intelligence.json` — machine-readable
  capability contract.
- `docs/v7-authentication-intelligence.md` — the pipeline pattern this sprint
  mirrors (Sprint 015 / Wave 9).
- `docs/v7-api-intelligence-implementation-plan.md` — API operation source.
- `docs/v7-tidb.md` — TIDB system of record.
- `docs/v7-tool-integration-sdk.md` — Tool SDK adapter contract.
- `docs/v7-platform-composition-root.md` — platform composition.
- `docs/bible/08 - Unified Security Schema.md` — USS envelope.
