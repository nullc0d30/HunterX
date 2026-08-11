# 08 — Unified Security Schema

**Status:** Ratified
**Version:** 1.0.0
**Applies to:** All entities stored in TIDB, Knowledge Graph, API models, report models, adapter events

---

## 1. Purpose & Governance

The Unified Security Schema (USS) is the **single canonical data model** of
HunterX. Every tool output, AI decision, API request/response, and report is
mapped to USS entities. Schema changes are governed by the
**Schema Change Process** in `24 - Quality Assurance.md` (major/minor/patch
with backward-compatible defaults; breaking changes require a major schema bump
and a migration path).

Conventions:

- **IDs:** content-addressed where meaningful (`sha256` over canonical content),
  otherwise ULID. All IDs are opaque strings to callers.
- **Timestamps:** UTC ISO-8601 with `Z`.
- **Enums:** closed sets; new values = minor bump; removals = breaking.
- **Optionality:** nullable vs absent distinguished; `null` means "not
  applicable/unknown", absent means "not provided".

---

## 2. Core Entity Relationship Overview

```
Engagement ──< Mission ──< WorkflowRun ──< TaskRun
                 │
                 ├──< Target ──< Asset
                 │                ├── Domain ──< Subdomain
                 │                ├── Host ──< IP ──< Port ──< Service ──< Technology
                 │                ├── URL ──< Endpoint ──< Parameter
                 │                ├── Directory
                 │                └── API
                 ├──< Finding ──< Evidence ──< Screenshot / Payload
                 ├──< RiskRating
                 └──< Report ──< Timeline
Knowledge (global): CVE, CWE, CAPEC, MITRE, EPSS
```

---

## 3. Entity Definitions

### 3.1 `Engagement`

| Field | Type | Notes |
|-------|------|-------|
| `id` | ULID | |
| `name` | str | |
| `client` | str | optional |
| `scope_policy_id` | ref ScopePolicy | |
| `starts_at` / `ends_at` | datetime | testing window |
| `legality` | { authorized, statement_of_work } | |
| `created_by`, `created_at` | Actor, datetime | audit |
| `status` | enum | active\|completed\|archived |

### 3.2 `Mission`

| Field | Type | Notes |
|-------|------|-------|
| `id` | ULID | |
| `profile_id` | ref MissionProfile | from `12 - Mission Profiles.md` |
| `engagement_id` | ref Engagement | |
| `targets` | ref[Target] | |
| `plan_id` | ref Plan | deterministic plan |
| `status` | enum | draft\|planned\|approved\|running\|validated\|correlated\|completed\|failed\|aborted\|archived |
| `risk_model` | ref RiskModel | |
| `params` | map | profile-specific |
| `ai_seed` | str | reproducibility |
| `timeline` | ref[TimelineEntry] | |

### 3.3 `Target`

| Field | Type | Notes |
|-------|------|-------|
| `id` | ULID | |
| `kind` | enum | domain\|ip\|cidr\|url\|hostname\|api\|cloud-account\|container\|cluster\|mobile-app\|ad-domain |
| `value` | str | canonical (FQDN lowercase, CIDR canonical, URL normalized) |
| `scope` | enum | in-scope\|out-of-scope\|pending-review |
| `engagement_id` | ref | |
| `attributes` | map | e.g., `{asn, org, country}` |

### 3.4 `Asset` (abstract; specialized below)

Shared: `id`, `target_id`, `discovered_at`, `source_tool`, `evidence_refs`,
`confidence` (0..1), `meta`.

#### `Domain`
`name` (FQDN), `parent`, `is_authoritative`, `registrar`, `dns_servers`, `mx`,
`txt`, `dnsssec_enabled`.

#### `Subdomain`
`name`, `parent_domain`, `resolution_confidence`.

#### `Host`
`address` (IP or name), `os_hint`, `is_alive`, `last_seen`.

#### `IP`
`address` (canonical IPv4/IPv6), `cidr`, `asn`, `owner_org`, `geo`, `ports:[Port]`.

#### `Port`
`number`, `protocol` (tcp|udp), `state` (open|closed|filtered), `banner`,
`service_hint`.

#### `Service`
`name`, `port_ref`, `protocol`, `version`, `state`, `banner`, `tls_info`,
`technologies:[Technology]`.

#### `Technology`
`name`, `category` (web-server, framework, cms, waf, language, ...), `version`,
`cpe`, `confidence`, `detected_by`.

#### `URL`
`url` (normalized), `scheme`, `host`, `path`, `query`, `is_internal`,
`status_code` (last observed), `content_type`, `discovered_by`.

#### `Endpoint`
`url`, `method`, `parameters:[Parameter]`, `auth_required`, `content_type`,
`response_meta`, `discovered_by`.

#### `Parameter`
`name`, `location` (query|body|path|cookie|header), `value` (masked), `type`
(string|int|file|json|xml|...), `is_interesting` (session, id, file, upload).

#### `Directory`
`path`, `parent`, `status_code`, `title`, `is_auth_required`, `discovered_by`.

#### `API`
`name`, `base_url`, `version`, `auth_scheme`, `endpoints:[Endpoint]`,
`spec_source` (swagger/openapi), `discovered_by`.

### 3.5 `Finding`

| Field | Type | Notes |
|-------|------|-------|
| `id` | ULID | |
| `hash` | str(sha256) | canonical dedup key |
| `title` | str | short, action-oriented |
| `description` | str | technical detail |
| `severity` | enum | info\|low\|medium\|high\|critical |
| `confidence` | float 0..1 | |
| `status` | enum | new\|confirmed\|refuted\|inconclusive\|triaged\|accepted\|reported |
| `category` | enum | see taxonomy below |
| `affected_assets` | ref[Asset] | |
| `vuln_refs` | ref[CVE] | enriched |
| `cwe_ids` | ref[CWE] | |
| `capec_ids` | ref[CAPEC] | |
| `mitre` | ref[MITRE] | techniques |
| `epss` | ref[EPSS] | score + percentile |
| `evidence` | ref[Evidence] | |
| `risk` | ref[RiskRating] | computed |
| `discovery` | { tool, phase, date, workflow_run_id } | provenance |
| `reproduce` | { steps, payload_refs, conditions } | |
| `recommendation` | str | mitigation guidance |
| `remediation` | { owner, due_date, status } | optional |
| `ai_notes` | ref[AIProvenance] | drafting trace |

**Finding taxonomy** (categories):
`injection` (SQLi, XSS, SSTI, command, LDAP, XXE), `auth`, `session`, `access-control`,
`ssrf`, `csrf`, `file-upload`, `file-inclusion`, `misconfiguration`, `information-disclosure`,
`weak-crypto`, `tls`, `headers`, `network`, `service`, `cloud`, `container`,
`kubernetes`, `mobile`, `active-directory`, `crypto`, `supply-chain`, `dos`,
`logic`, `other`.

### 3.6 `Evidence`

| Field | Type | Notes |
|-------|------|-------|
| `id` | ULID | |
| `type` | enum | raw-response\|screenshot\|log\|payload\|har\|trace\|artifact\|verification |
| `data_ref` | ref ObjectStore | object key + size + sha256 |
| `mime_type` | str | |
| `captured_at` | datetime | |
| `captured_by` | str | tool/step |
| `context` | map | {request, response headers, status, matched text} |
| `redacted` | bool | PII masking applied |

### 3.7 `Screenshot`

`evidence_id`, `url`, `viewport`, `full_page`, `timestamp`, `dimensions`,
`ocr_text` (optional), `file_ref`.

### 3.8 `Payload`

| Field | Type | Notes |
|-------|------|-------|
| `id` | ULID | |
| `value` | str | the payload string (maskable) |
| `type` | enum | sqli\|xss\|ssti\|command\|ssrf\|file\|lfi\|xxe\|upload\|auth\|fuzz |
| `encoding` | enum | raw\|url\|base64\|hex\|json |
| `provenance` | { source (repo/commit/tag), checksum, hash } | auditable |
| `effective_against` | ref[Finding] | linkage |
| `mutations` | ref[Payload] | derived variants |
| `feedback` | { success, notes } | learning loop |

### 3.9 `RiskRating`

| Field | Type | Notes |
|-------|------|-------|
| `id` | ULID | |
| `finding_id` | ref | |
| `score` | float 0..10 | composite |
| `vector` | map | {exploitability, impact, exposure, likelihood, detectability} |
| `formula_version` | str | which risk model version |
| `overrides` | { reason, by } | human overrides recorded |
| `calculated_at` | datetime | |

### 3.10 `CVE`

Mirrored reference entity: `id` (CVE id), `description`, `cvss_v2`/`cvss_v3`/`cvss_v4`,
`cwes`, `references`, `published`, `last_modified`, `vendor/product` (CPE),
`known_exploited` (bool), `poc_available` (bool).

### 3.11 `CWE`

`id` (CWE id), `name`, `description`, `mitigations`, `related_cwes`, `taxonomy` (OWASP etc.).

### 3.12 `CAPEC`

`id`, `name`, `description`, `prerequisites`, `steps`, `related_weaknesses`,
`severity_hint`.

### 3.13 `MITRE`

`technique_id` (ATT&CK), `name`, `tactics`, `subtechniques`, `detection`,
`mitigations`, `platforms`.

### 3.14 `EPSS`

`cve_id`, `score` (0..1), `percentile`, `date`, `source`.

### 3.15 `Report`

`id`, `mission_id`, `type` (technical|executive|evidence|compliance|timeline),
`format` (json|markdown|html|pdf|sarif), `template_version`, `artifacts:[path]`,
`content_hash`, `generated_at`, `status`, `viewable_by`.

### 3.16 `Timeline` / `TimelineEntry`

`id`, `mission_id`, `at`, `actor`, `type` (phase|event|finding|approval|tool-run|ai-decision),
`summary`, `refs`, `meta`.

### 3.17 `ScopePolicy`

`id`, `rules:[ {kind, value, action(allow|deny), note} ]`,
`destructive_allowed`, `approval_required_for:[action]`, `windows:[{start,end,timezone}]`.

### 3.18 `AIProvenance`

`id`, `ai_task_id`, `prompt_hash`, `model`, `provider`, `seed`, `temperature`,
`schema_version`, `latency_ms`, `tokens`, `consensus`, `confidence`, `decision`,
`grounding_refs`.

---

## 4. Canonical Event Types (produced by adapters/normalizer)

| Event | Payload (canonical) |
|-------|---------------------|
| `domain.discovered` | Domain |
| `subdomain.discovered` | Subdomain |
| `host.alive` | Host + IP |
| `port.open` | IP + Port |
| `service.discovered` | Service |
| `technology.discovered` | Technology |
| `url.discovered` | URL |
| `endpoint.discovered` | Endpoint |
| `parameter.discovered` | Parameter |
| `directory.discovered` | Directory |
| `api.discovered` | API |
| `finding.created` | Finding (draft) |
| `finding.updated` | Finding delta |
| `evidence.captured` | Evidence |
| `payload.used` | Payload |
| `verification.completed` | ValidationVerdict |

---

## 5. Severity Model

| Severity | Score range | Conditions |
|----------|-------------|------------|
| `critical` | 9.0–10.0 | Remote, unauthenticated, systemic impact |
| `high` | 7.0–8.9 | Remote or high-impact; auth or chained |
| `medium` | 4.0–6.9 | Local or requires conditions |
| `low` | 0.1–3.9 | Limited impact |
| `info` | 0.0 | Informational only |

Severity is a **starting point**; the final risk uses the mission risk model
(`12 - Mission Profiles.md` §Risk).

---

## 6. Confidence Model

| Value | Meaning |
|-------|---------|
| 0.0–0.3 | Unverified / speculative |
| 0.4–0.6 | Single-source, plausibly real |
| 0.7–0.8 | Multi-source or reproducible |
| 0.9–1.0 | Exploit confirmed / PoC verified |

---

## 7. Deduplication Contract

- Canonical finding `hash = sha256(canonical(dedup_key_spec fields))`.
- `dedup_key_spec` per tool (see `07` §8); platform-level fallback:
  `title + primary affected asset + category + severity`.
- Duplicates increment `occurrences`; originals keep first-seen provenance.
- Merge policy: keep highest-confidence evidence set; never lose audit history.

---

## 8. Serialization & Compatibility

- JSON is the canonical interchange; pydantic models at delivery boundary.
- Schema versions travel with every event, API model, and stored record
  (`schema_version`).
- Unknown fields: tolerant on read (ignored), strict on write (rejected).
- Enums serialized as strings; never integers.

---

## 9. References

- `09 - Database Design.md` (persistence of these entities)
- `07 - Tool Knowledge Base Specification.md` (output contract mapping)
- `21 - Reporting Standards.md` (report view models derived from USS)
- `20 - REST API Standards.md` (API models derived from USS)
