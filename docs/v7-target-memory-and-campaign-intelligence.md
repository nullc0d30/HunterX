---
layout: default
title: HunterX v7 Target Memory & Campaign Intelligence
description: >-
  Architecture and reference for the HunterX v7 Target Memory & Campaign
  Intelligence capability (Sprint 030): the persistent, queryable historical
  understanding of every authorized target. Covers the memory model, first/last
  seen tracking, observation history, snapshots, deterministic diffs, change
  significance, mission/hypothesis/tool memory, freshness, revalidation,
  campaigns, coverage memory, coverage gaps, attack-path history, contradiction
  detection, memory confidence, poisoning defense, next-action
  recommendations, security, performance, testing and the extension model.
permalink: /v7-target-memory-and-campaign-intelligence/
---

# HunterX v7 Target Memory & Campaign Intelligence — Architecture & Reference

**Status:** Ratified (Sprint 030)
**Version:** 1.0.0
**Owner:** HunterX Architecture Council

---

## 1. Purpose / Scope

Sprint 030 makes HunterX *remember*.

The objective is a persistent, queryable historical understanding of every
authorized target:

```text
CURRENT TARGET STATE
      + HISTORICAL OBSERVATIONS
      + PREVIOUS MISSIONS
      + PREVIOUS FINDINGS
      + PREVIOUS VALIDATION
      + PREVIOUS PoCs
      + CHANGES
      + FAILED HYPOTHESES
      + ATTACK PATH HISTORY
      ↓
  TARGET MEMORY
      ↓
  NEXT MISSION INTELLIGENCE
```

HunterX must **not** repeatedly rediscover information that is already known
and still valid. It must remember what it tested, what failed, what was
validated, what changed, and what remains unknown — and use that memory to
plan the next authorized mission.

### In scope

Target memory, first/last seen tracking, observation history, reproducible
snapshots, deterministic snapshot diffs, change significance, mission memory,
failed/successful hypothesis memory, tool observation provenance, tool result
comparison, freshness classification, revalidation planning, target risk
history, finding history and recurrence detection, campaigns, campaign
intelligence, coverage memory and coverage-gap detection, attack-path history,
contradiction detection, memory confidence, memory-aware planning integration,
next-action recommendations, TIDB persistence, events, API, CLI, security,
performance, golden datasets and end-to-end testing.

### Out of scope (belongs outside Sprint 030)

New vulnerability classes, new offensive tools, new PoC types, new reporting
formats, new AI providers, new reverse-engineering capabilities, new attack
techniques, unrelated architecture.

---

## 2. Memory Model — DO NOT DUPLICATE ENTITIES

Target Memory is **NOT** a replacement for Target Intelligence, TIDB, Finding,
Evidence, Mission, Knowledge, Correlation or PoC systems. It is a **historical
intelligence layer that references canonical entities by id** and adds the
historical dimension on top of them.

The canonical aggregate is `TargetMemory`
(`hunterx.domain.target_memory.models`):

| Field | Meaning |
|---|---|
| `observations` | memory observations keyed by canonical key (`observation_type:normalized_value`) |
| `coverage` | per-cell coverage memory |
| `findings` | finding lifecycle records keyed by `finding_id` |
| `gaps` | coverage gaps |
| `recommendations` | advisory next-action recommendations |
| `contradictions` | preserved contradictions |

### Referenced canonical entities

Targets, assets, domains, subdomains, IP addresses, ports, services, URLs,
endpoints, parameters, HTTP methods, technologies, frameworks, APIs, GraphQL
endpoints, authentication surfaces, cloud resources, identities, secrets,
findings, evidence, PoCs, attack paths, missions, tool observations,
hypotheses, validation attempts, remediation state, historical changes and
risk state are referenced — never re-created.

---

## 3. First-Seen / Last-Seen Tracking

Every persistent observation in the memory layer exposes the full tracking
envelope:

| Field | Meaning |
|---|---|
| `first_seen` | first observation stamp (UTC ISO-8601) |
| `last_seen` | most recent observation stamp |
| `observation_count` | number of raw observations aggregated |
| `first_mission` | mission that first observed the value |
| `last_mission` | mission that most recently observed the value |
| `first_source` | source of the first observation |
| `last_source` | source of the most recent observation |
| `current_state` | classified state (`known_current`, `known_stale`, `known_changed`, `unknown`, `contradicted`, `needs_revalidation`) |

`first_seen`/`first_mission`/`first_source` are **never lost across missions**:
the application service merges each freshly assembled observation into the
persisted record, keeping the earliest stamps and accumulating the count.

---

## 4. Observation History

The memory layer tracks changes such as:

- new / removed asset
- new subdomain, IP change
- port opened / closed, service changed
- technology / framework changed
- endpoint appeared / disappeared
- parameter appeared / disappeared
- TLS changed, HTTP behavior changed
- DNS changed, cloud resource changed
- security header changed, authentication behavior changed
- finding appeared / disappeared / reopened / remediated

Each is represented as an observation key transition between snapshots
(section 6) and recorded as a structured `TargetChange`.

---

## 5. Target Snapshot

`TargetSnapshot` represents the known target state at a specific point in
time:

```text
snapshot_id · target_id · mission_id · created_at
schema_version · observation_count · state_hash · state
```

- **Reproducible** — the same stored observations + mission produce the same
  snapshot.
- **Deterministic hash** — `state_hash` is a SHA-256 over the recursively
  key-sorted serialized state, so identical states always hash identically.
- When `mission_id` is given, the observation state reflects the observations
  collected during that mission, so consecutive mission snapshots support
  change detection.

---

## 6. Target Diff Engine

`TargetDiffEngine` compares Snapshot A vs Snapshot B and detects:

`added` · `removed` · `changed` · `unchanged` · `reappeared` · `disappeared` ·
`reopened` · `remediated`

- **Determinism** — the same snapshot pair always yields the same diff
  (every comparison iterates sorted canonical keys).
- **Reappeared / disappeared** require an optional `baseline` snapshot: a key
  present in the baseline, absent in A and present in B is `reappeared`.
- **Finding lifecycle** — a finding whose `remediation_state` closes between
  snapshots is `remediated`; one that reopens is `reopened`.

The engine answers: *"What changed since the last Nmap?"*, *"What changed
since the last HTTPx run?"*, *"What new endpoints appeared?"*, *"What
disappeared?"*, *"What changed since the previous campaign?"*.

---

## 7. Change Significance

`ChangeSignificanceEngine` classifies every change:

`INFORMATIONAL` < `LOW` < `MEDIUM` < `HIGH` < `CRITICAL`

| Example | Significance |
|---|---|
| new subdomain | informational / low |
| new admin endpoint | high |
| new exposed service | medium / high |
| new cloud identity | high |
| new externally exposed credential | critical |

**Severity stays evidence-backed:** the classified significance is always
capped by the confidence of the evidence backing the change (a low-confidence
"credential" report is never classified critical).

---

## 8. Mission Memory

`MissionMemory` stores historical mission context by referencing canonical
entities: `scope`, `started_at`/`ended_at`, `tools_used`,
`assets_discovered`, `findings_discovered`, `findings_validated`,
`pocs_generated`, `hypotheses`, `successful_hypotheses`, `failed_hypotheses`,
`blocked_tests`, `tool_failures`, `coverage_achieved`, `coverage_gaps`.

---

## 9. Failed Hypothesis Memory

HunterX must remember *what* it tested, *why* (the hypothesis), *which tool*
was used, *what evidence* was observed, *why validation failed*, *when* and
*under what conditions*. `HypothesisMemory` with `outcome=failed` retains all
of these — preventing repeated useless testing.

---

## 10. Successful Hypothesis Memory

Successful records retain the reusable pattern as historical intelligence:
`vulnerability_type`, `asset_type`, `technology`, `endpoint_pattern`,
`parameter_pattern`, `authentication_context`, `tool`, `validation_strategy`,
`poc_strategy`, `evidence_pattern`.

---

## 11. Tool Observation Provenance

`ToolObservation` retains for every meaningful tool result: `tool`,
`tool_version`, `execution_id`, `target`, `scope`, `timestamp`,
`normalized_result`, `evidence_refs`, `derived_entities`, `confidence`,
`provenance`. **Raw output is never stored** — only normalized results and
references.

---

## 12. Tool Result Comparison

Because memory keeps observations per canonical key with `last_seen`, two
snapshots or two tool runs can always be compared via the diff engine
(section 6).

---

## 13. Memory-Aware Planning

Target Memory is exposed to Mission Planning through
`TargetMemoryService.build_planner_context` → `PlannerContext` (a port-style
plain object):

```text
known_state · unknown_state · stale_state · changed_state
coverage_gaps · previous_failures · previous_successes · risk_priorities
```

The planner receives **classified state and previous results** — never raw
historical data.

---

## 14. Smart Recon

Observations are classified, not blindly trusted:

```text
KNOWN_CURRENT · KNOWN_STALE · KNOWN_CHANGED · UNKNOWN
CONTRADICTED · NEEDS_REVALIDATION
```

Known-but-fresh values are reused; known-but-stale values enter the
revalidation plan; the mission planner decides what requires fresh
verification.

---

## 15. Staleness Engine

`ObservationFreshnessEngine` classifies observations as `FRESH` / `AGING` /
`STALE` / `EXPIRED` / `UNKNOWN`. Freshness is **configurable by observation
type** (TTL in seconds):

| Observation type | Freshness window |
|---|---|
| DNS / IP / host | short (6 h) |
| port / service | moderate (12–24 h) |
| technology fingerprint | moderate (7 d) |
| cloud resource / secret | short (4–6 h) |
| historical finding | persistent (no auto-expiry) |

An explicit `expires_at` overrides the type policy.

---

## 16. Revalidation Engine

`RevalidationPlanner` identifies observations that need revalidation and
prioritizes: high-risk, high-change, stale, contradicted, previously-unstable
and security-sensitive observations (`HIGH` > `MEDIUM` > `LOW`).

---

## 17. Target Risk Evolution

`TargetRiskEvaluator` + `TargetRiskEntry` track risk over time. Risk history
is **append-only**: historical risk is never overwritten. Each entry records
`risk_level`, `previous_risk_level`, `reason` and `driving_changes`.

```text
Campaign 1  Risk: Medium
Campaign 2  New exposed service      Risk: High
Campaign 3  Critical vuln validated  Risk: Critical
Campaign 4  Fix verified             Risk: High → Medium
```

---

## 18. Finding History

`FindingMemory` tracks per finding: `first_detected`, `first_validated`,
`last_validated`, `last_observed`, `remediation_state`, `retest_state`,
`reopened_count`, `closed_at`, `affected_assets`, `affected_endpoints`,
`root_cause`, `recurrence_count`.

---

## 19. Finding Recurrence

`FindingRecurrenceDetector` detects when a previously remediated vulnerability
or root cause returns:

```text
SQLi fixed on /api/search  →  SQLi appears on /api/export
same root-cause family · new affected location · potential regression
```

Kinds: `same_location`, `new_location`, `root_cause_regression`.

---

## 20. Campaign Model

`Campaign` groups related missions against a target or target set:

```text
campaign_id · name · objective · scope · status · target_ids · mission_ids
started_at · ended_at · risk_history · findings · coverage · changes · attack_paths
```

Lifecycle: `planned` → `active` → (`paused`) → `completed` / `cancelled`.

---

## 21. Campaign Intelligence

`CampaignIntelligenceEngine` answers:

- What changed? → `changed`
- What was discovered? → `discovered`
- What was validated? → `validated`
- What remains untested? → `untested`
- What failed? → `failed`
- What was fixed? → `fixed`
- What regressed? → `regressed`
- What should be tested next? → `next`

---

## 22. Coverage Memory & 23. Coverage-Gap Detection

Coverage memory is tracked per asset × capability. `CoverageGapEngine`
distinguishes `DISCOVERED` / `TESTED` / `VALIDATED` / `NOT_TESTED` /
`BLOCKED` / `OUT_OF_SCOPE` and surfaces gaps such as:

- discovered but untested endpoint
- API without parameter testing
- technology without relevant checks
- cloud resource without configuration validation
- authenticated surface never tested
- new asset never assessed
- stale observation requiring revalidation

---

## 24. Attack-Path History

`AttackPathMemory` persists historical attack-path observations: `path`,
`nodes`, `edges`, `evidence_refs`, `confidence`, `first_seen`, `last_seen`,
`status`, `changes`. **Theoretical paths are never treated as confirmed
compromise.**

---

## 25–26. Memory-Aware Planning & Next-Action Intelligence

`NextActionRecommender` returns structured advisory recommendations
(`action`, `reason`, `priority`, `required_tool_capabilities`,
`evidence_required`, `expected_outcome`, `historical_context`).
Recommendations are **advisory only** — the mission planner decides execution;
memory never executes actions directly.

---

## 27. Contradiction Detection

`ContradictionDetector` detects contradictions such as:

- Nmap says port open, later Nmap says closed
- HTTPx says server exists, DNS no longer resolves
- Cloud inventory says resource exists, external observation says unavailable

Both observations are **preserved** and the current state is classified
(`open`/`resolved`/`escalated`). Historical evidence is never silently
overwritten.

---

## 28. Memory Confidence

`MemoryConfidenceEngine` computes the effective confidence of every memory
item from observation confidence × source reliability × freshness ×
corroboration count × contradiction state.

---

## 29. Memory Correlation

Target Memory integrates with Target Intelligence, the Knowledge Engine, the
Correlation Engine, Finding Intelligence, the PoC system, Cloud Intelligence,
Reporting and Mission Planning through the composition root.

---

## 30. Database (TIDB)

Target Memory extends TIDB **only where required**, adding one migration
(`fc52d0b58c3f`) with 15 tables:

| Table | Purpose |
|---|---|
| `tidb_memory_observations` | observation history + first/last seen |
| `tidb_target_snapshots` | reproducible snapshots |
| `tidb_target_diffs` | deterministic diffs |
| `tidb_mission_memories` | mission memory |
| `tidb_hypothesis_memories` | failed/successful hypothesis memory |
| `tidb_tool_observations` | tool observation provenance |
| `tidb_target_risks` | append-only risk history |
| `tidb_finding_memories` | finding lifecycle history |
| `tidb_finding_recurrences` | recurrence detection |
| `tidb_campaigns` | campaigns |
| `tidb_coverage_gaps` | coverage gaps |
| `tidb_revalidations` | revalidation state |
| `tidb_attack_path_memories` | attack-path history |
| `tidb_memory_contradictions` | preserved contradictions |
| `tidb_next_actions` | advisory next-action records |

Indexes cover `target_id`, `asset_key`, observation type, `first_seen`,
`last_seen`, `mission_id`, `campaign_id`, `current_state` and composite
target×state paths. Existing entities (Target Intelligence, Finding, Evidence,
Mission, Knowledge, Correlation, PoC) are reused, never duplicated.

---

## 31. Events

Typed events (registered in `hunterx.domain.events.catalog`):

```text
target.memory.updated          target.snapshot.created
target.diff.created            target.change.detected
target.observation.stale       target.revalidation.required
campaign.created               campaign.updated
campaign.completed             coverage.updated
coverage.gap.detected          hypothesis.recorded
hypothesis.failed              hypothesis.succeeded
risk.changed                   finding.recurred
```

New event categories `target` and `campaign` were added to
`EventCategory`; typed constructors live in `hunterx.domain.events.types`.

---

## 32. API

Mounted at `/targets` in `hunterx.api.target_memory`:

```text
GET  /targets/{target_id}/memory
GET  /targets/{target_id}/snapshots
GET  /targets/snapshots/{snapshot_id}
GET  /targets/snapshots/{snapshot_a}/compare/{snapshot_b}
GET  /targets/{target_id}/changes
GET  /targets/{target_id}/history
GET  /targets/{target_id}/coverage
GET  /targets/{target_id}/gaps
GET  /targets/{target_id}/risk
GET  /targets/{target_id}/revalidate
GET  /targets/{target_id}/hypotheses
GET  /targets/{target_id}/findings
GET  /targets/{target_id}/attack-paths
GET  /targets/campaigns
GET  /targets/campaigns/{campaign_id}
GET  /targets/campaigns/{campaign_id}/intelligence
POST /targets/campaigns
POST /targets/campaigns/{campaign_id}/complete
```

---

## 33. CLI

Registered in `hunterx.cli.commands`:

```text
hunterx target memory
hunterx target snapshot
hunterx target diff
hunterx target changes
hunterx target history
hunterx target coverage
hunterx target gaps
hunterx target risk
hunterx target revalidate
hunterx campaign list
hunterx campaign show
hunterx campaign intelligence
```

---

## 34. Security

Strict tenant/target/mission isolation is enforced on every write through
`TargetMemoryService.authorize` + `_check_target`: a record is persisted only
when its target belongs to an authorized tenant. Queries are always
target-scoped.

Security tests (`tests/security/test_target_memory_security.py`) cover:
cross-target leakage, cross-mission leakage, unauthorized historical access,
evidence leakage, secret leakage, memory poisoning, malicious tool output,
timestamp manipulation and state tampering.

---

## 35. Memory Poisoning Defense

Historical memory is **untrusted data**. A single low-confidence observation
can never permanently redefine target state. The layer gates every memory item
by source reliability, corroboration, freshness, confidence and contradiction
handling. `MemoryConfidenceEngine.is_poisoned` flags items below a confidence
threshold so the planner does not act on them.

---

## 36. Performance

`tests/performance/test_target_memory_benchmarks.py` exercises assembly of
10k / 100k / 1M-scale observation sets, repeated-count aggregation, large
snapshot hashing and large diffs with generous budgets. No N+1 queries for
current-state queries (repository streaming), no unbounded memory.

---

## 37. Golden Datasets

`tests/golden/test_target_memory_golden.py` covers: new asset, removed asset,
changed IP, new/removed endpoint, technology change, new/remediated
vulnerability, regression, failed hypothesis, successful hypothesis,
contradictory tool output, stale observation, coverage gap, attack-path change
and cloud resource change.

---

## 38. End-to-End Test

`tests/integration/test_target_memory_platform.py` runs the Sprint 030
acceptance scenario through the composed platform:

1. **MISSION 1** — recon, discover assets/endpoints/technologies, validate a
   finding, record mission/hypothesis/tool memory, create snapshot.
2. **MISSION 2** — load memory, detect changes, skip unnecessary rediscovery,
   identify stale observations and coverage gaps, prioritize the changed
   attack surface, update memory, create snapshot + diff.
3. **CAMPAIGN INTELLIGENCE** — what changed, was discovered, was fixed,
   remains vulnerable/untested, and what should happen next.

---

## 39. Determinism

Same historical state + same snapshot pair ⇒ same diff
(`tests/unit/test_target_memory_domain.py::TestSnapshotsAndDiffs`).

---

## 40. Capability Manifest

`capabilities/target-memory-campaign-intelligence.json` ratifies the
capability (wave 15, sprint 30), its states, events, persistence entities,
API and CLI surface.

---

## Extension Model

Add a new memory record type by following the TIDB pattern:

1. Add a `@dataclass` entity extending `TidbEntity` in
   `hunterx.domain.entities.tidb.memory`.
2. Add a matching ORM model in
   `hunterx.infrastructure.db.sql.tidb_models.memory_models`.
3. Register both in their package `__init__.py` (name-convention driven
   registry picks them up).
4. Generate an Alembic migration (`python -m alembic revision --autogenerate`).
5. Wire mapping helpers in `hunterx.application.target_memory`.

No other wiring is needed: `SqlCrudRepository` / `InMemoryCrudRepository` and
the entity↔model registry work generically.
