# 09 — Database Design

**Status:** Ratified
**Version:** 1.0.0
**Applies to:** Target Intelligence Database (TIDB), Knowledge Graph, Object Store, Cache, Indexes

---

## 1. Stores Overview

| Store | Engine | Purpose |
|-------|--------|---------|
| TIDB (SQL) | PostgreSQL 15+ | Canonical relational data: targets, assets, findings, evidence metadata, missions, reports, users, audit |
| Knowledge Graph | Neo4j (or compatible) | Relationship-rich: attack paths, correlations, MITRE mapping |
| Object Store | S3-compatible / local FS | Blobs: screenshots, raw outputs, report files, payload binaries |
| Cache | Redis | Hot reads: AI responses, DNS/WHOIS, plan expansion, API throttling state |
| Search | PostgreSQL FTS / optional Elasticsearch | Full-text: findings, hosts, endpoints |
| Queue | RabbitMQ/AMQP | Workflow tasks (see `02` §5.18) |

Single-node deployments may substitute embedded equivalents through the same
ports; distributed deployments use the production engines.

---

## 2. ER Diagram (Logical)

```
ENGAGEMENT 1───< MISSION >───1 PROFILE(config/profiles)
   │              │
   │              ├──< PLAN ──< PLAN_STEP
   │              ├──< WORKFLOW_RUN ──< TASK_RUN
   │              └──< TIMELINE_ENTRY
   │
TARGET 1───< ASSET(abstract)
             ├── DOMAIN ──< SUBDOMAIN
             ├── HOST ──< IP ──< PORT ──< SERVICE ──< TECHNOLOGY
             ├── URL ──< ENDPOINT ──< PARAMETER
             ├── DIRECTORY
             └── API

MISSION ──< FINDING ──< EVIDENCE(meta) ──blob──> OBJECT_STORE
   │          │
   │          ├──< RISK_RATING
   │          ├──< VULN_REF  (CVE)
   │          ├──< CWE_REF
   │          ├──< CAPEC_REF
   │          ├──< MITRE_REF
   │          └──< EPSS_REF
   └──< REPORT ──< REPORT_ARTIFACT

GLOBAL REFERENCE: CVE ──< CWE ; CVE ──< EPSS ; CVE ──< CAPEC ; CVE ──< MITRE

USERS ──< AUTH_SESSION ; USERS ──< ROLE (RBAC) ; USERS ──< AUDIT_LOG
```

---

## 3. Core Tables (TIDB)

### 3.1 Naming & Conventions

- `snake_case`; plural table names; `id` UUID/ULID text PK; all rows carry
  `created_at`, `updated_at`; soft-delete via `deleted_at` where retention allows.
- Every table has a **bitemporal** twin for history where mutation occurs
  (see §History below).

### 3.2 Principal Tables

| Table | Key columns (beyond USS fields) | Notes |
|-------|---------------------------------|-------|
| `engagements` | `id`, `name`, `scope_policy_id` | |
| `scope_policies` | `id`, `rules jsonb`, `windows` | |
| `missions` | `id`, `engagement_id`, `profile_id`, `plan_id`, `status`, `ai_seed` | |
| `targets` | `id`, `kind`, `value`, `scope`, `engagement_id` | unique `(engagement_id, kind, value)` |
| `domains` | `id`, `target_id`, `name`, `parent_domain_id` | unique name per engagement |
| `subdomains` | `id`, `domain_id`, `name` | |
| `hosts` | `id`, `target_id`, `address`, `is_alive` | |
| `ips` | `id`, `host_id`, `address` (canonical), `asn`, `geo` | |
| `ports` | `id`, `ip_id`, `number`, `protocol`, `state` | unique `(ip_id, number, protocol)` |
| `services` | `id`, `port_id`, `name`, `version`, `state`, `banner` | |
| `technologies` | `id`, `service_id`, `name`, `version`, `cpe` | |
| `urls` | `id`, `target_id`, `url` | unique url |
| `endpoints` | `id`, `url_id`, `method`, `path`, `auth_required` | |
| `parameters` | `id`, `endpoint_id`, `name`, `location`, `type` | |
| `directories` | `id`, `target_id`, `path`, `status_code` | |
| `apis` | `id`, `target_id`, `base_url`, `auth_scheme` | |
| `findings` | `id`, `hash`, `title`, `severity`, `confidence`, `status`, `category`, `payload jsonb` | see §Indexes |
| `finding_assets` | `finding_id`, `asset_id` | M:N |
| `evidence` | `id`, `finding_id`, `type`, `object_key`, `sha256`, `redacted` | |
| `screenshots` | `id`, `evidence_id`, `url`, `dimensions` | |
| `payloads` | `id`, `value`, `type`, `encoding`, `provenance jsonb` | |
| `risk_ratings` | `id`, `finding_id`, `score`, `vector jsonb`, `formula_version` | |
| `reports` | `id`, `mission_id`, `type`, `format`, `content_hash` | |
| `report_artifacts` | `id`, `report_id`, `path`, `size` | |
| `timeline_entries` | `id`, `mission_id`, `at`, `actor`, `type`, `summary` | |
| `users` | `id`, `username`, `email`, `scopes`, `rbac_roles` | |
| `auth_sessions` | `id`, `user_id`, `token_hash`, `expires_at` | |
| `audit_log` | `id`, `correlation_id`, `actor`, `action`, `resource`, `detail jsonb`, `at` | append-only |
| `kv_cache_meta` | cache-key meta (version, ttl) | optional durability |
| `mirror_*` | CVE/CWE/CAPEC/MITRE/EPSS normalized tables | global reference data |

---

## 4. Indexes

Mandatory indexes (beyond PK/unique):

| Table | Index | Type | Purpose |
|-------|-------|------|---------|
| `findings` | `(hash)` | btree unique | dedup |
| `findings` | `(mission_id, severity, status)` | btree | mission triage |
| `findings` | `(category)` | btree | taxonomy filter |
| `findings` | `(epss_percentile desc)` | btree | prioritization |
| `findings` | `(title)` | FTS gin | search |
| `targets` | `(value)` | btree | scope lookup |
| `targets` | `(engagement_id, scope)` | btree | scope checks |
| `ips` | `(address)` | btree | adjacency |
| `ports` | `(ip_id, state)` | btree | port state query |
| `domains` | `(name)` | btree | recon lookup |
| `urls` | `(url)` | btree unique | dedup |
| `evidence` | `(sha256)` | btree | integrity checks |
| `timeline_entries` | `(mission_id, at)` | btree | timeline |
| `audit_log` | `(correlation_id)` | btree | trace |
| `audit_log` | `(actor, at)` | btree | audit queries |
| `users` | `(username)` | btree unique | auth |
| `auth_sessions` | `(token_hash)` | btree unique | auth |
| `mirror_cves` | `(cve_id)` | btree unique | ref |
| `mirror_cves` | `(published)` | btree | recency |

Guidelines: every FK referenced in a hot query has an index; every `WHERE`/
`JOIN`/`ORDER BY` column in the top-20 queries has an index; indexes are added
via Alembic migrations and reviewed in Performance Review
(`24 - Quality Assurance.md` §8).

---

## 5. Relationships

- `engagements → missions → workflow_runs → task_runs` (parent-child cascade, soft-delete).
- `missions → findings` (1:M); `findings → evidence` (1:M); `findings → assets` (M:N).
- `targets → assets` (1:M, polymorphic via per-type tables).
- `findings → vuln_refs` (M:N through reference join tables).
- Knowledge Graph mirrors these with edges for traversal (see §10).

---

## 6. History & Versioning

- **Bitemporal model** for every mutable entity: `valid_from`, `valid_to`
  (state-time) + `created_at`, `updated_at` (assertion-time).
- Implemented via **append-only history tables** (`<table>_history`) or
  PostgreSQL temporal features; every UPDATE inserts a history row.
- History retention: full for `findings`, `evidence`, `missions`, `audit_log`;
  configurable rollup for high-volume `timeline_entries` (> 90 days → daily summary).
- Schema versioning: `schema_migrations` (Alembic) + per-row `schema_version`.

---

## 7. Caching Strategy

| Cache | Key | TTL | Invalidated by |
|-------|-----|-----|----------------|
| AI responses | `ai:v1:<prompt-hash>:<model>:<params>` | 24h | schema/knowledge bump |
| DNS | `dns:<name>` | 10m | none (short TTL) |
| WHOIS | `whois:<domain>` | 24h | none |
| Plan expansion | `plan:v1:<profile>:<scope-hash>` | 30d | profile/knowledge bump |
| Tool outputs (idempotent) | `toolout:<tool>:<input-hash>` | profile | explicit |
| HTTP client | `http:<url>` | 1h | none |
| Session/auth | `sess:<token>` | per session | logout/expiry |
| API rate limits | `rl:<user>:<bucket>` | window | none |

Cache key namespace is versioned (`v1`); bump on schema change. Never cache:
destructive ops, evidence-carrying sensitive blobs, or anything containing secrets.

---

## 8. Data Retention Policy

| Data | Retention | Action |
|------|-----------|--------|
| Findings + evidence (raw responses, screenshots) | Indefinite unless engagement mandates purge | archive |
| Timeline (detail) | 90 days → daily summary | rollup |
| Tool raw outputs (beyond evidence) | 30 days | purge |
| Audit log | 2 years (configurable) | archive to cold store |
| AI completions (logs) | 90 days | purge (masked already) |
| Deleted mission data | 90 days in soft-delete | purge |

Purge is scheduled, logged, and reversible until the final purge step
(audit trail remains). Compliance overrides per engagement (e.g., client
NDA retention windows).

---

## 9. Search

- PostgreSQL FTS (tsvector, `gin`) for `findings`, `endpoints`, `hosts`, `urls`.
- Query: ranking by `ts_rank`, filters on severity/status/category/mission.
- The Search adapter (`infrastructure/db/search`) exposes a stable API so
  Elasticsearch can replace it without touching callers.
- Search is scoped: results filtered by the caller's engagement/tenant access.

---

## 10. Knowledge Graph Relationships

The Graph mirrors TIDB entities and adds traversal edges:

| Edge | Example |
|------|---------|
| `RESOLVES_TO` | subdomain → IP |
| `HOSTS` | IP → host |
| `LISTENS_ON` | host → port |
| `RUNS` | port → service |
| `EXPOSES` | service → endpoint |
| `HAS_PARAM` | endpoint → parameter |
| `AFFECTED_BY` | asset → finding |
| `VULN_IS` | finding → CVE |
| `MAPS_TO` | finding/CVE → CWE/CAPEC/MITRE |
| `EXPLOITS` | payload → finding |
| `DERIVED_FROM` | evidence → finding |
| `CORRELATES_WITH` | finding → finding |
| `PART_OF_PATH` | attack-path node |

Used for: shortest attack paths, blast-radius queries, cross-mission correlation,
and AI grounding subgraph extraction. Graph writes are asynchronous (event-driven).

---

## 11. Write Path & Integrity

- All writes happen through the `StorePort`; the Normalizer produces
  **CanonicalEvents** that the store applies transactionally.
- Events are idempotent: replayed events do not duplicate rows (unique keys +
  event `id`).
- Referential integrity enforced in SQL; Graph is eventually consistent with
  the SQL source of truth (rebuilt on demand).
- Evidence blobs: `sha256` recorded at upload; integrity re-verified on read.
- Backups: WAL-based, point-in-time recovery; Graph exported via cypher dump.

---

## 12. Performance Targets (see also `14 - Performance Standards.md`)

- TIDB supports **millions of findings** with the above indexes at <100ms for
  common queries (triage, dedup, report pulls).
- Bulk ingest: ≥ 10,000 canonical events/sec on standard hardware (batch
  inserts, no per-row commits).
- Query plans are reviewed when a query exceeds 500ms P95 in performance tests.

---

## 13. Migration Governance

- All schema changes via Alembic migrations; forward + rollback scripts.
- Breaking changes require: dual-write window or backfill + versioned API.
- Migration rollouts staged: staging → canary → production, with verification
  checks per stage.
- Schema change approval is part of the Schema Change Process
  (`24 - Quality Assurance.md` §7).

---

## 14. References

- `08 - Unified Security Schema.md` (entity definitions)
- `14 - Performance Standards.md` (capacity & indexing targets)
- `02 - Architecture.md` §5.15–5.16 (TIDB & Cache)
