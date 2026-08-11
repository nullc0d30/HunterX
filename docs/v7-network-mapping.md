---
layout: default
title: HunterX v7 Network Mapping & Attack-Surface Topology Capability - Architecture & Reference
description: >-
  Architecture and reference for the HunterX v7 Network Mapping & Attack-Surface
  Topology Capability: the capability that transforms individual asset
  observations into a unified, queryable, historical attack-surface topology.
  Canonical relationship types, entity resolution, correlation, conflict
  preservation, temporal history, topology analysis, attack-surface views, path
  analysis, the topology.* event catalog, TIDB persistence, scope control, the
  traceroute tool integration, platform wiring and a developer extension guide.
permalink: /v7-network-mapping/
---

# HunterX v7 Network Mapping & Attack-Surface Topology Capability - Architecture & Reference

**Status:** Ratified (Sprint 010)
**Version:** 1.0.0
**Owner:** HunterX Architecture Council

---

## 1. Purpose / Scope

The **Network Mapping & Attack-Surface Topology Capability** turns individual
asset observations into a unified, queryable attack-surface topology. HunterX
understands the relationships between targets, organizations, domains,
subdomains, hostnames, IPs, CIDRs, ASNs, networks, ports, services,
certificates and DNS infrastructure — and preserves that understanding as
historical, evidence-backed intelligence.

### Core principle

**The topology is NOT a second database.** The existing TIDB is the single
system of record. The topology layer **derives** its state from canonical TIDB
entities and relationships; it never introduces a parallel asset database, a
separate graph truth, a second cache or a duplicate event system.

Two mandates:

1. **Derive.** `TopologyService` (the application use-case) collects the
   canonical TIDB intelligence produced by Sprint 007–009 capabilities,
   optionally runs route-mapping tools through the guarded SDK lifecycle,
   derives relationships deterministically, correlates and de-duplicates them,
   preserves conflicts, diffs history, analyzes the graph and persists the
   derived topology back into the TIDB.
2. **Query.** `TopologyQueryService` reads persisted topology relationships and
   answers the canonical graph queries (neighbors, ancestors, descendants,
   shortest relationship paths, shared infrastructure, clusters and the seven
   attack-surface views).

Scope: `src/hunterx/domain/topology/`,
`src/hunterx/application/topology.py`, `src/hunterx/tools/topology/`, the
`tidb_topology_*` TIDB entity set, the `topology.*` event catalog and the
platform wiring in `src/hunterx/platform/assembler.py`.

Out of scope: exploitation paths, vulnerability scanning, and active
scope expansion. Path analysis is **infrastructure topology only** — never
attack execution.

---

## 2. Design Goals

- **Derived, not parallel.** Every relationship is derived from canonical TIDB
  entities. Nothing is stored twice; the topology is a queryable projection.
- **Deterministic & explainable resolution.** Equivalent spellings
  (`WWW.Example.COM.` vs `www.example.com`, canonical IP/CIDR forms) collapse
  to one entity; similar-looking-but-distinct names are never merged. Every
  merge decision is a pure function of normalization rules.
- **Correlation preserves provenance.** Multiple sources observing the same
  edge produce one relationship carrying every source, merged evidence, a
  combined confidence and the first/last seen window.
- **Conflicts are preserved, never overwritten.** Disagreements surface as
  explicit `TopologyConflict` records with a selected canonical value and an
  explainable reason.
- **Temporal, incremental, historical.** First/last seen per edge, detected
  new/removed/changed relationships, and incremental updates without rebuilding
  the graph after every discovery.
- **Scope-aware by construction.** Deny-by-default; discovered infrastructure
  never silently expands mission scope.
- **Performance headroom.** Thousands of assets / hundreds of thousands of
  relationships with an in-memory adjacency index rebuilt from TIDB on query.

---

## 3. Topology Model

The canonical node model (hierarchy of authority):

```
Organization → Target → Domain → Subdomain → Hostname → IP → CIDR → Port → Service → Certificate
```

Additional supported relations:

```
IP → ASN   ASN → Organization   Certificate → Domain
Certificate → IP   Hostname → IP   IP → Hostname
Domain → Nameserver   Domain → MX   Network → Asset   Asset → Asset
```

### Entities

`TopologyEntity` is a canonical node with `kind`, `name`, `key` (stable
`kind:name`), optional `entity_id`, `label` and `meta`. Kinds are enumerated in
`hunterx.domain.topology.enums.EntityKind`.

### Relationships

`GraphRelationship` is a correlated edge preserving:

| Field | Meaning |
| --- | --- |
| `rel_type` | canonical `RelationshipType` |
| `source` / `target` | canonical nodes |
| `sources` | provenance sources that reported the edge |
| `evidence` | merged per-source evidence |
| `confidence` | merged `[0, 1]` |
| `first_seen` / `last_seen` | temporal window |
| `mission_id` / `execution_id` / `correlation_id` | provenance |
| `in_scope` | authorization flag |
| `source_id` / `target_id` | TIDB entity ids when known |
| `key` | stable dedup key `rel:src\|dst` |

### Relationship types

`RESOLVES_TO`, `POINTS_TO`, `HOSTED_ON`, `BELONGS_TO`, `PART_OF`, `ROUTES_TO`,
`ANNOUNCED_BY`, `USES`, `EXPOSES`, `SERVES`, `CERTIFICATE_FOR`, `SIGNED_BY`,
`DELEGATED_TO`, `MAILS_TO`, `RELATED_TO`, `DISCOVERED_BY`, `OBSERVED_WITH`,
`SHARES_INFRASTRUCTURE_WITH`, `SHARES_CERTIFICATE_WITH`, `SHARES_IP_WITH`,
`SHARES_NAMESERVER_WITH`.

---

## 4. Entity Resolution

`TopologyNormalizer` collapses equivalent spellings:

- Hostnames/domains: lowercase, strip trailing dots.
- IP addresses / CIDRs: canonical form via the `ipaddress` module.
- Certificate fingerprints: lowercase, separators removed.

`EntityResolver` keeps a per-run cache so an asset always has exactly one node
in a build. **Dissimilar names are never merged** (`www.example.com` vs
`wwwexample.com` stay distinct); merging is a deterministic function of the
normalization rules, never fuzzy similarity.

---

## 5. Relationship Derivation

`RelationshipDeriver` turns canonical TIDB entities into raw
`RelationshipObservation` records. Every edge records its provenance source
(e.g. `tidb:subdomain`, `tidb:ip`) and evidence. Derivation rules:

| Source TIDB data | Relationship |
| --- | --- |
| `Subdomain.domain_id` → `Domain` | `subdomain PART_OF domain` |
| `Domain.parent_domain_id` | `domain PART_OF parent` |
| `Hostname` name suffix | `hostname PART_OF domain` |
| `IPAddress.hostname_id` → `Hostname` | `hostname RESOLVES_TO ip` |
| `IPAddress.cidr_id` → `CIDR` | `ip PART_OF cidr` |
| `IPAddress.asn_id` → `ASN` / `CIDR.asn_id` | `ip|cidr ANNOUNCED_BY asn` |
| `Port.ip_address_id` → `IPAddress` | `ip EXPOSES port` |
| `Service.port_id` → `Port` | `port SERVES service` |
| `Certificate.hostname_id` / SAN entries | `hostname USES cert`, `cert CERTIFICATE_FOR name` |
| `Domain.dns_servers` / `Nameserver` | `domain DELEGATED_TO ns` |
| `Domain.mx` / `MXRecord` | `domain MAILS_TO mx` |
| `DNSRecord` A/AAAA / CNAME / MX | `name RESOLVES_TO\|POINTS_TO\|MAILS_TO value` |
| `Domain/Hostname/IP.target_id` → `Target` | `entity BELONGS_TO target` |
| `source_tool` | `entity DISCOVERED_BY tool` |
| host/service observations | `entity OBSERVED_WITH other` |

`routes_to` edges are produced by the `traceroute` tool adapter
(`tools/topology/`): consecutive route hops form a directed `ROUTES_TO` chain.

---

## 6. Validation & Correlation

`TopologyValidator` drops structurally or semantically invalid observations
(self-loops, unknown relationship types, `routes_to` non-IP targets,
`part_of` IPs outside their CIDR).

`TopologyCorrelator` groups observations by their stable key and merges them
into one `GraphRelationship`:

- **Sources** are unioned (order-preserving).
- **Evidence** is merged per source.
- **Confidence** is combined via the probabilistic sum `1 - ∏(1 - cᵢ)`
  scaled by source reliability, capped at 0.99 (`TopologyConfidenceEngine`).
- **First/last seen** are the min/max observation timestamps.

Duplicate observations from multiple tools become **one edge**, never two.

---

## 7. Conflicts

`TopologyConflictResolver` detects endpoint pairs reported under more than one
relationship type. All observations are preserved; the canonical value is
selected by combined confidence with a human-readable reason, and the conflict
is recorded as a `TopologyConflict` (persisted to the TIDB and surfaced via the
`topology.conflict.detected` event). Intelligence is **never silently
overwritten**.

---

## 8. Temporal History

`TopologyHistory.diff` compares the previous persisted topology with the newly
correlated one:

- **New** edges (NEW change, added to the graph).
- **Removed** edges (REMOVED change).
- **Changed** edges (CHANGED change when sources/confidence/ids differ).

Merged edges preserve the earliest `first_seen` while advancing `last_seen`, so
the temporal model is append-only and explainable. Changes persist as
`TopologyChange` entities.

---

## 9. Topology Analysis

`TopologyAnalyzer` computes deterministic analytics over the correlated graph:

- **Asset clusters** — `same_ip`, `same_cert`, `same_nameserver`, `same_asn`,
  `same_cidr`, `service`.
- **Shared infrastructure** — pairwise `SHARES_*` edges for small clusters.
- **Density**, **connected components**, largest component size.
- **Orphan assets** (nodes with no edges), **dangling DNS relationships**,
  **unresolved hostnames**, **stale relationships** (decayed last-seen).

---

## 10. Attack-Surface Views

`TopologyViewBuilder` projects the graph into serializable views:

1. Asset inventory graph
2. Network graph (IP/CIDR/ASN/port/service)
3. DNS graph (domain/subdomain/hostname/NS/MX/resolution)
4. Service graph (host → port → service)
5. Certificate graph
6. Organization infrastructure graph
7. External attack surface (all in-scope edges)
8. Shared infrastructure & asset clusters
9. Historical changes view

---

## 11. Path Analysis (safe queries only)

`TopologyGraph` + `TopologyPathFinder` support safe, read-only navigation:

- Neighbors (undirected adjacency with edge types)
- Ancestors / descendants (directed BFS)
- Shortest relationship path (bidirectional BFS, e.g.
  `domain → hostname → ip → port → service`)
- Related assets, shared infrastructure

**No exploitation paths.** These are infrastructure-intelligence queries only;
they never mutate state or act on targets.

---

## 12. Topology Queries

`TopologyQueryService` (application layer) answers, from persisted TIDB
relationships:

`neighbors`, `ancestors`, `descendants`, `shortest_path`, `related_assets`,
`shared_infrastructure`, `asset_cluster`, `service_cluster`,
`certificate_relationships`, `network_relationships`,
`historical_relationships`, plus the view builders and the analysis summary.

---

## 13. Performance

- The graph is an in-memory adjacency index (`TopologyGraph`) rebuilt from
  persisted relationships on query — no graph database.
- Correlation is O(n) grouping + merge; benchmarked at ~10k observations
  correlated in tens of milliseconds.
- **Incremental updates**: history diff detects only new/removed/changed edges
  and persists them; unchanged edges keep their temporal state. The full
  graph is not rebuilt after every discovery — only the derived relationship
  layer is refreshed.
- Benchmarks live in `tests/performance/test_topology_benchmarks.py` and run
  under the performance quality gate.

---

## 14. Caching

Derived/query data may be cached through the **existing** `CachePort`
abstraction; canonical intelligence always lives in the TIDB. No new cache
system is created.

---

## 15. Events

Emitted under the `topology.*` namespace (see `domain/events/catalog.py` and
typed events in `domain/events/types.py`):

`topology.build.started`, `topology.relationship.discovered`,
`topology.relationship.updated`, `topology.relationship.removed`,
`topology.entity.correlated`, `topology.conflict.detected`,
`topology.cluster.created`, `topology.analysis.started`,
`topology.analysis.completed`, `topology.build.completed`,
`topology.build.failed`.

---

## 16. Observability

Every build persists a `TopologyBuild` record capturing: entities processed,
relationships processed, new/updated/removed relationships, conflicts, duration
and a summary. Per-source `TopologyExecutionSummary` records report tool vs TIDB
contribution. These feed reporting and the `topology.*` event stream.

---

## 17. TIDB Integration

Topology entities map to the canonical TIDB (`domain/entities/tidb/topology.py`
+ `infrastructure/db/sql/tidb_models/topology_models.py`, tables
`tidb_topology_relationships`, `tidb_topology_conflicts`,
`tidb_topology_changes`, `tidb_topology_clusters`, `tidb_topology_builds`).
The schema is extended through the proper Alembic migration
(`7f1c9a2b0e4d_topology_tables.py`, revising `53b3e0bb8ed2`).

**Schema-gap policy:** if a required relationship cannot be represented, the
capability STOPS, documents the gap and extends the approved TIDB architecture
via migration. No undocumented side database is ever created.

---

## 18. Security & Scope Control

- **Deny-by-default scope.** `TopologyScopePolicy` authorizes domains, CIDRs,
  IPs and target ids; `TopologyScopeEnforcer` decides node/relationship
  authorization. An empty policy authorizes nothing.
- **No scope expansion.** A relationship is incorporated only when its source
  data is authorized and within mission policy. `allow_third_party=False`
  excludes fully out-of-scope observations entirely. Discovered infrastructure
  never becomes authorized scan scope.
- **No exploitation / no command injection.** The traceroute adapter builds
  argv from typed parameters (no shell), and untrusted tool output is treated
  strictly as data (never executed).
- **Cross-target/mission isolation.** Canonical keys and provenance preserve
  mission boundaries; queries filter by `mission_id`.

---

## 19. Tools

### traceroute (integrated, Sprint 010)

- **Purpose:** map the hop-by-hop network route to a target IP.
- **Capabilities:** `route-mapping`, `network-topology`.
- **CLI:** `traceroute [-n] [-m hops] [-f ttl] [-w sec] <target>`.
- **Input:** target IP/host/domain.
- **Output:** plain-text hop lines parsed into canonical `RouteRecord`s
  (`routes` payload) → `routes_to` relationships.
- **Exit codes / errors / timeouts:** handled by the SDK pipeline
  (`BinaryRunner`); non-zero exits fail validation.
- **Privileges:** user-level (may need elevated for some probe types).
- **Version:** 2.1.0. **Install:** `apt install traceroute`.
- **Limitations:** ICMP/UDP probes may be filtered; hops can be `*`.
- **Security:** numeric output default; typed params only; golden-tested.
- **Parser / normalizer:** `tools/topology/traceroute.py`; TIDB mapping via
  `TopologyRelationship`.

Evaluated and **not** integrated: RustScan (naabu/masscan already cover port
discovery), Nmap graph features (nmap already integrated under Live Host &
Service Discovery). BBOT relationship data is covered by its existing
integration. Only tools providing information unavailable through existing
capabilities are integrated.

---

## 20. Platform Wiring

`platform/assembler.py` registers the `traceroute` adapter on the
`ExecutionEngine`, its profile on the Tool Intelligence Platform, and builds
`TopologyService` + `TopologyQueryService` against the TIDB stores, event bus
and cache. Both services are available on the `Platform` composition root and
in the dependency container.

---

## 21. Testing

- **Unit** — `tests/unit/test_topology_domain.py` (resolution, derivation,
  validation, correlation, conflicts, history, analysis, graph/paths, views,
  scope, confidence, TIDB bridge), `tests/unit/test_topology_service.py`
  (orchestrator + query service), `tests/unit/test_topology_adapters.py`
  (traceroute argv/parsing).
- **Integration** — `tests/integration/test_topology_platform.py` (assembled
  platform round-trip).
- **Security** — `tests/security/test_topology_security.py` (scope control,
  injection, isolation).
- **Performance** — `tests/performance/test_topology_benchmarks.py`.
- **Acceptance** — `tests/acceptance/test_topology_acceptance.py` (end-to-end
  intelligence flow).
- **Golden datasets** — `tests/golden/topology/` (plain, hostname,
  unreachable and malformed traceroute output).

---

## 22. Developer Extension Guide

- **Add a relationship type:** extend `RelationshipType` in
  `domain/topology/enums.py`, add a derivation rule in
  `RelationshipDeriver`, and add a migration if the TIDB representation
  changes.
- **Add a route tool:** implement a `TopologyToolAdapter` subclass, register it
  in `tools/topology/registry.py` and add a TIP profile in
  `tools/topology/tip.py`.
- **Add a view:** extend `TopologyViewBuilder`.
- **Add a query:** extend `TopologyQueryService` and `TopologyPathFinder`.
- **New TIDB entity:** create the entity + ORM model, export both, and add an
  Alembic migration; the generic registry and row mapper pick it up
  automatically.

---

## 23. Related Documentation

- `docs/v7-tidb.md` — canonical TIDB (system of record).
- `docs/v7-reconnaissance-capability.md` / `docs/v7-dns-intelligence.md` /
  `docs/v7-live-host-service-discovery.md` — Sprint 007–009 data sources.
- `docs/v7-tool-integration-sdk.md` — the guarded tool execution pipeline.
- `docs/v7-tool-intelligence-platform.md` — the TIP knowledge plane.
- `docs/v7-event-bus-observability.md` — the `topology.*` event catalog.
