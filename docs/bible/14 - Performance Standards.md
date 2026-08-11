# 14 — Performance Standards

**Status:** Ratified
**Version:** 1.0.0
**Applies to:** All components, `tests/performance/`, capacity planning, scaling

---

## 1. Performance Goals

| Goal | Target |
|------|--------|
| CLI cold start | < 1.5s to first command |
| API p95 latency (read) | < 150ms |
| API p95 latency (write/ingest) | < 300ms |
| Tool step dispatch overhead | < 5ms |
| Canonical event ingest | ≥ 10,000 events/s (single node, batch) |
| Finding triage query (1M findings) | < 100ms p95 |
| Mission with 1,000 targets | completes within profile constraints |
| Concurrent missions | ≥ 200 active (single node) |
| Horizontal scale-out | ≥ 1,000 concurrent targets across workers |

---

## 2. Memory

- **Streaming-first:** tool outputs and large files are processed in chunks/lines;
  no unbounded slurping. Parser API is iterator-based (`06` §3).
- **Bounded caches:** every cache has TTL + max entries + eviction (LRU/LFU);
  no unbounded memoization.
- **Graphs/adjacency:** subgraphs loaded on demand, never the full graph.
- **AI context:** hard token budgets (`11` §4); never whole-database in prompt.
- **Leak discipline:** async resources closed via context managers; per-mission
  heaps released; `ResourceWarning` treated as test failure.
- Per-process ceilings: workers enforce `max_memory_mb` per tool run (sandbox).

---

## 3. CPU

- CPU-bound work (normalization, hashing, dedup, report rendering) off the
  event loop: `asyncio.to_thread`/executor pools, or process pools for heavy jobs.
- Hot paths are lazy and cached (e.g., knowledge file lookups compiled once).
- No busy-wait loops; all waits are async/sleep-based with cancellation.

---

## 4. Concurrency & Parallelism

- asyncio for I/O; per-mission and global concurrency semaphores.
- Worker fleet for tool execution (process isolation); worker count
  configurable; default = `2 × cores`.
- Distributed mode: workers consume from the shared queue
  (`02` §5.18); mission steps execute on any worker (idempotent consumers).
- Rate limiting at the tool layer prevents target/network saturation
  (from knowledge file `performance` + `rate_limit`).

---

## 5. Caching & Hot-Path Optimization

- Cache tiers: in-process → Redis → (optional) DB materialized views.
- Dedup/normalization caches keyed by canonical hashes.
- Report rendering caches compiled templates.
- Cache stampede protection: single-flight locks for hot keys.

---

## 6. Large-Target Support

Target sizing model (approximate per engagement):

| Class | Targets | Notes |
|-------|---------|-------|
| small | < 100 | single node default |
| medium | 100–10k | worker fleet; batch tool runs |
| large | 10k–1M | partition by scope; chunked tool invocation; streaming ingest |
| extreme | > 1M | distributed workers; sharded DB; aggregated reporting |

Mechanisms:

- **Chunking:** tools run over chunks (100 hosts/URLs per invocation) with
  configurable chunk size.
- **Streaming ingest:** events batched (executemany); no per-event commits.
- **Sampling/prioritization:** when full coverage impossible within budget,
  prioritize by risk exposure and mark coverage gaps.
- **Rollup:** high-volume data (timeline, raw outputs) rolled up per
  `09` §8 retention.

---

## 7. Database Optimization

- Index design: `09` §4; every hot query covered.
- Partitioning: `findings` by `mission_id`/date; `audit_log` by month.
- Read replicas for reporting/search in distributed mode.
- Connection pooling with bounded pool sizes; async drivers.
- Query budget: any query > 500ms p95 is an automatic perf-review trigger.
- Vacuum/maintenance scheduled off-peak; never during peak missions.

---

## 8. Reporting Performance

- Rendering is streaming and chunked for large evidence sets.
- Report artifacts generated asynchronously (job model); no blocking of API.
- Image/PDF generation has its own bounded worker pool.

---

## 9. Performance Testing

- Benchmarks in `tests/performance/` (pytest-benchmark or custom).
- Regression gates in CI: core hot-path benchmarks must not regress > 10%.
- Load tests: `tests/performance/load/` (locust or k6) for API and ingest.
- Capacity tests: 1M findings triage, 10k/s ingest, 1,000 concurrent targets
  (staged: CI smoke + nightly full).
- Profiling artifacts committed on failures (cProfile/flame graphs).

---

## 10. Operational SLAs

- SLO: API availability 99.9% (distributed); no data loss on worker crash
  (at-least-once queue + checkpointing).
- Degradation mode: on resource pressure, scheduler lowers concurrency and
  pauses non-critical missions (graceful, logged).

---

## 11. References

- `04 - Coding Standards.md` §12 (performance coding)
- `09 - Database Design.md` §4, §12 (indexes, targets)
- `10 - Workflow Engine.md` §12 (workflow perf budget)
- `15 - Testing Standards.md` §4 (performance tests)
