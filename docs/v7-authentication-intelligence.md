---
layout: default
title: HunterX v7 Authentication, Session & Identity Intelligence
description: >-
  Architecture and reference for the HunterX v7 Authentication, Session &
  Identity Intelligence capability (Sprint 015 / Wave 9): authentication
  surfaces, endpoints, modeled flows, identity providers, OAuth/OIDC/SAML
  configurations, JWT indicators, authentication schemes, cookie security
  metadata, token storage, CSRF/CORS protections, MFA/WebAuthn mechanisms,
  roles/scopes/permissions/tenants, public-vs-authenticated classification and
  historical change detection. Intelligence only — never authenticates.
permalink: /v7-authentication-intelligence/
---

# HunterX v7 Authentication, Session & Identity Intelligence

**Status:** Ratified (Sprint 015 · Wave 9)
**Version:** 1.0.0
**Owner:** HunterX Architecture Council

---

## 1. Purpose / Scope

The **Authentication, Session & Identity Intelligence** capability gives HunterX
a persistent, evidence-backed understanding of the *authentication and identity
attack surface* of an authorized target — without exploiting it. The capability
discovers, classifies, models, correlates, normalizes, scores, persists,
historizes and reports on:

- login / logout / registration / password-reset / recovery surfaces
- authentication endpoints (token, authorization, callback, userinfo, JWKS …)
- modeled stateful authentication flows
- identity providers (Auth0, Okta, Keycloak, Entra ID, Google, Cognito,
  Firebase, Supabase, GitHub, GitLab, Ping, custom)
- OAuth 2.x, OIDC and SAML configurations
- JWT indicators
- authentication schemes and headers
- session cookies and cookie security metadata
- client-side token storage
- CSRF and CORS protections
- MFA and WebAuthn / passkey mechanisms
- roles, scopes, permissions, claims and tenant indicators
- public vs authentication-required classification
- historical changes and deterministic differential analysis

**Security boundary:** intelligence only. The capability never performs
credential attacks, MFA bypass, token replay, authorization bypass, OAuth/SAML
abuse, JWT exploitation, or validation of discovered credentials/tokens. It
never stores passwords, session-cookie values, access/refresh tokens, API
secrets, OTPs, recovery codes or authorization-header values.

---

## 2. Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│  AuthService.run()  (application/auth.py)                                │
│                                                                          │
│  DISCOVER → CLASSIFY → MODEL → CORRELATE → NORMALIZE → SCORE             │
│           → PERSIST → DIFF → HISTORIZE → MAP → REPORT                    │
│                                                                          │
│  scope admission → ExecutionEngine (auth-analysis adapter)               │
│  → existing-intelligence fold-in (TIDB)                                  │
│  → AuthClassifier → AuthValidator → AuthCorrelator → AuthConfidenceEngine│
│  → AuthHistory → persist to TIDB → topology edges → auth.* events        │
└─────────────────────────────────────────────────────────────────────────┘
            ▲                                                        │
   inputs:  │                                                        ▼
   HTTP snapshot, JS content, API security schemes,             TIDB auth_* tables
   OIDC/SAML documents, observed URLs, historical              + topology + events
```

The capability is composed of:

| Layer | Modules |
|---|---|
| Domain | `src/hunterx/domain/auth/` — models, analyzer, classification, confidence, correlator, history, scope, strategy, validator |
| Tool SDK | `src/hunterx/tools/auth/` — in-process `auth-analysis` adapter, registry, TIP profile |
| Application | `src/hunterx/application/auth.py` — `AuthService`, `AuthQueryService` |
| TIDB | `src/hunterx/domain/entities/tidb/auth_intelligence.py` + ORM mirror + Alembic migration |
| Events | `auth.*` category in `domain/events/{enums,catalog,types}.py` |
| Topology | `src/hunterx/domain/topology/enums.py` auth entity kinds |
| Composition | `src/hunterx/platform/assembler.py`, `src/hunterx/platform/platform.py` |

---

## 3. Authentication Model

The capability models authentication as a set of canonical, evidence-backed
records (see §TIDB Mapping). Each record carries the USS envelope (id,
timestamps, versioning, soft-delete) plus provenance (`source`, `tool_id`,
`target_key`, `correlation_id`, `mission_id`), evidence fragments, indicators
and a deterministic confidence in `[0, 1]`.

### 3.1 Authentication vs Authorization

The models keep the two concerns strictly separate:

- **Authentication** ("Who are you?") — surfaces, endpoints, flows, identity
  providers, OAuth/OIDC/SAML configurations, schemes, sessions, MFA.
- **Authorization** ("What are you allowed to access?") — roles, scopes,
  permissions, claims, tenants. These are recorded as *indicators* only; no
  authorization relationship is inferred without evidence.

### 3.2 Anonymous vs Authenticated surface

Resources are classified into `public`, `auth-required`, `authenticated-only`
or `unknown` (`AuthAccessState`) with evidence explaining the classification
(HTTP 401/403, `WWW-Authenticate`, login redirect, login-form presence). The
classifier never fabricates a state that was not observed.

### 3.3 Session state model

Observable session states are modeled as `SessionState` values
(`anonymous`, `auth-initiated`, `authenticated`, `session-established`,
`session-refresh`, `logout`, `session-expired`, `recovery`, `mfa-challenge`,
`mfa-verified`, `unknown`). States are bounded by flows and never fabricated.

---

## 4. Authentication Flows

Flows are represented as stateful relationships over endpoints. The analyzer
builds deterministic flow models from observed endpoints/metadata:

- **Traditional login** — `anonymous → login → authentication → authenticated`.
- **OAuth 2 authorization-code** — `client → authorization endpoint → identity
  provider → callback → token endpoint → session`.
- **OIDC authorization-code** — `client → authorization → identity provider →
  callback → token → id-token → session`.
- **SAML SSO** — `client → SSO request → identity provider → assertion (ACS) →
  session`.

The flows are *models of observed state* — HunterX never executes them.

---

## 5. OAuth Intelligence

Detected metadata (never secrets): authorization/token/revocation/
introspection/userinfo endpoints, issuer, JWKS URI, client identifiers
(non-secret), redirect URIs, scopes, response types, grant types, PKCE and
state-parameter indicators. OAuth discovery runs over:

- OIDC/OAuth discovery documents supplied as parsed JSON,
- OpenAPI `securitySchemes` (OAuth2 flows/scopes),
- JavaScript configuration (client ids, redirect URIs, scopes, grants),
- URL path patterns (`/authorize`, `/token`, `/userinfo`, `/jwks`…).

HunterX never executes authorization flows and never tests OAuth
vulnerabilities.

---

## 6. OIDC Intelligence

A valid OIDC discovery document yields the canonical `OIDCConfig` record:
issuer, endpoints, scopes, claims, response types, subject types, ID-token
signing algorithms and PKCE methods, with `openid-discovery` evidence at
strength `strong`. When only an issuer is observed in static material, a
moderate-confidence record is produced. Tokens are never validated.

---

## 7. SAML Intelligence

SAML detection records safe metadata only: entity IDs, SSO/ACS URLs, metadata
URLs, IdP/SP labels and `RelayState` indicators. SAML metadata documents are
parsed for `entityID`, `SingleSignOnService` and `AssertionConsumerService`.
HunterX never submits or manipulates SAML messages.

---

## 8. JWT Intelligence

JWT-like structures are detected safely across transports
(`authorization-header`, `cookie`, `local-storage`, `session-storage`,
`static`). The analyzer records only indicators (transport, location,
algorithm from the non-secret header segment) and masks token material. It
never forges, modifies, brute-forces, replays or validates tokens.

---

## 9. Sessions & Cookies

`AuthCookieObservation` records cookie *security metadata only*: name, scope
(domain/path), `Secure`, `HttpOnly`, `SameSite`, `Max-Age`, `Expires`,
`Priority`, `Partitioned`, prefixes (`__Secure-`, `__Host-`), and whether the
cookie is a session or persistent cookie. Raw cookie values are never stored.
Session-state observations (401/403 challenges, logout redirects, session
cookie presence) are recorded as generic `AuthObservation` records.

---

## 10. Token Storage

Client-side token storage is detected from static JavaScript
(`localStorage`, `sessionStorage`, `IndexedDB`, `document.cookie`, memory/
wrapper patterns) and recorded as `TokenStorageObservation` with the storage
type, token category and a *masked* context snippet. Actual tokens are never
persisted.

---

## 11. CSRF & CORS

- **CSRF** — synchronizer tokens, double-submit cookie/header pairs,
  framework cookies (`csrftoken`, `XSRF-TOKEN`, `_token`), custom headers and
  SameSite controls are recorded as `CSRFMechanism`. Bypass is never tested.
- **CORS** — `Access-Control-Allow-*` headers, credentials, methods, headers,
  exposed headers and preflight behavior are recorded as `CORSPolicy`.
  Exploitation is never performed.

---

## 12. MFA & WebAuthn

MFA mechanisms (TOTP, SMS/email OTP, push, WebAuthn/FIDO2/passkeys, recovery
codes) are detected from HTML keywords, input fields and JavaScript API usage.
WebAuthn indicators (`navigator.credentials`, `PublicKeyCredential`,
registration vs authentication) are recorded as static metadata with a
challenge *reference* only — never the challenge value. MFA bypass is never
attempted.

---

## 13. Roles, Scopes, Permissions & Tenancy

Evidence-backed indicators are recorded from JavaScript configuration, OAuth
scopes declared in OpenAPI security schemes, and static claims references:

- `RoleObservation`, `ScopeObservation`, `PermissionObservation`,
  `TenantObservation`.

Tenant indicators cover IDs, headers (`X-Tenant-ID`…), claims, path/query
parameters and API resources. No tenant isolation is tested.

---

## 14. Historical Intelligence & Differential Analysis

`AuthHistory.compare(historical, current)` diffs snapshots deterministically by
canonical subject key and value, producing `added`/`removed`/`changed`
`AuthChange` records. This detects: new/removed login surfaces, new identity
providers, changed authentication mechanisms, new/changed OAuth flows, new/
removed MFA, changed cookie attributes, new/removed token storage, new/
deprecated API authentication schemes and changed authorization surfaces.
Identical snapshots yield zero changes (deterministic comparison).

---

## 15. Evidence

Every record carries provenance: `source`, `tool_id`, `mission_id`,
`correlation_id`, `execution_id`, timestamps, asset, URL, detection method
(evidence type), a masked evidence value, and a deterministic confidence.
Evidence types include `http-header`, `cookie`, `html`, `http-status`,
`url-pattern`, `location`, `javascript`, `openid-discovery`,
`saml-metadata`, `openapi-security`, `js-indicator`, `tidb-intelligence`,
`tool-output`, `known-signature`.

### 15.1 Confidence

Confidence is deterministic and explainable (`AuthConfidenceEngine`):

- **Strong evidence** — direct HTTP observation (headers, status, cookies),
  valid OIDC discovery document, valid OpenAPI security scheme, direct JS API
  call, multiple independent observations.
- **Weak evidence** — URL naming, HTML text, single heuristic, historical-only
  data.

The score combines the declared evidence-aware confidence with the strongest
evidence factor and source reliability, with corroboration boosts and conflict
discounts.

---

## 16. TIDB Mapping

22 canonical TIDB entities in `auth_intelligence.py`:

| Entity | Table | Purpose |
|---|---|---|
| `AuthRun` | `tidb_auth_runs` | run observability |
| `AuthSurface` | `tidb_auth_surfaces` | authentication surface + access state |
| `AuthEndpoint` | `tidb_auth_endpoints` | authentication endpoint |
| `AuthFlow` | `tidb_auth_flows` | modeled flow |
| `IdentityProvider` | `tidb_identity_providers` | identity provider |
| `OAuthConfig` | `tidb_oauth_configs` | OAuth metadata |
| `OIDCConfig` | `tidb_oidc_configs` | OIDC metadata |
| `SAMLConfig` | `tidb_saml_configs` | SAML metadata |
| `AuthScheme` | `tidb_auth_schemes` | authentication scheme |
| `AuthCookie` | `tidb_auth_cookies` | cookie security metadata |
| `TokenStorageIndicator` | `tidb_token_storage_indicators` | token storage |
| `CSRFMechanism` | `tidb_csrf_mechanisms` | CSRF protection |
| `CORSPolicy` | `tidb_cors_policies` | CORS configuration |
| `MFAMechanism` | `tidb_mfa_mechanisms` | MFA mechanism |
| `WebAuthnIndicator` | `tidb_webauthn_indicators` | WebAuthn/passkey |
| `RoleIndicator` | `tidb_role_indicators` | role |
| `ScopeIndicator` | `tidb_scope_indicators` | scope |
| `PermissionIndicator` | `tidb_permission_indicators` | permission |
| `TenantIndicator` | `tidb_tenant_indicators` | tenant |
| `AuthObservation` | `tidb_auth_observations` | generic observation |
| `AuthEvidence` | `tidb_auth_evidence` | evidence fragment |
| `AuthChange` | `tidb_auth_changes` | historical change |

All tables share the USS envelope (`TidbModelMixin`). The registry maps
`XModel ↔ X` automatically; the in-memory and SQL repository factories pick the
entities up without configuration. Migration:
`4a9c1d5f3e82_authentication_intelligence_tables`.

---

## 17. Topology

Authentication records are projected into the existing attack-surface topology
(`tidb_topology_relationships`) as edges:

```
WEB_ORIGIN ──SERVES──▶ AUTH_SURFACE ──SERVES──▶ AUTH_ENDPOINT
WEB_ORIGIN ──USES────▶ IDENTITY_PROVIDER
WEB_ORIGIN ──USES────▶ AUTHENTICATION_SCHEME
```

New topology entity kinds: `AUTH_SURFACE`, `AUTH_ENDPOINT`,
`IDENTITY_PROVIDER`, `AUTHENTICATION_SCHEME`, `SESSION`.

---

## 18. Security

- **No credentials or tokens stored.** Cookie values, token values, OTPs,
  recovery codes and authorization-header values are never persisted; retained
  context snippets are masked (`shared.masking`).
- **No scope expansion.** The enforcer authorizes the analysed asset; discovered
  identity-provider endpoints are recorded as metadata and never requested.
- **No exploitation.** No credential attacks, MFA bypass, token replay, OAuth/
  SAML abuse, JWT exploitation, CSRF/CORS exploitation, authorization bypass.
- **Deterministic** detection, classification, confidence and diffing.
- **Fail-closed scope** with `fail_open_empty_policy=True` (matching technology
  fingerprinting).

---

## 19. Testing

| Suite | Files | Focus |
|---|---|---|
| Golden | `tests/golden/auth/*.json` | deterministic input fixtures |
| Unit | `test_auth_domain.py`, `test_auth_analyzer.py`, `test_auth_service.py`, `test_auth_tip.py` | models, serialization, detection, pipeline, TIP |
| Integration | `test_auth_platform.py` | platform wiring + end-to-end |
| Acceptance | `test_auth_acceptance.py` | Sprint 015 acceptance criteria |
| Security | `test_auth_security.py` | leakage, scope, malformed input, contamination |
| Performance | `test_auth_benchmarks.py` | analysis, correlation, query baselines |

### Quality gates

- `ruff check` clean; `mypy` (strict) clean on the capability modules.
- `pytest tests/unit tests/integration tests/acceptance tests/security tests/performance tests/architecture`.
- `alembic upgrade head` / `downgrade base` clean; new tables registered in the
  TIDB metadata.

## 20. References

- `config/capabilities/authentication-intelligence.json` — machine-readable
  capability contract.
- `docs/v7-api-intelligence-implementation-plan.md` — the pipeline pattern this
  sprint mirrors.
- `docs/v7-tidb.md` — TIDB system of record.
- `docs/v7-tool-integration-sdk.md` — Tool SDK adapter contract.
- `docs/v7-platform-composition-root.md` — platform composition.
- `docs/bible/08 - Unified Security Schema.md` — USS envelope.
