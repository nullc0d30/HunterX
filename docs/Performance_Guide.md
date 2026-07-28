---
layout: default
title: Performance Guide — HunterX v6.0.0
description: Performance characteristics, caching strategies, concurrency tuning, and benchmark estimates for HunterX.
permalink: /performance-guide/
---

# Performance Characteristics

This document describes the performance architecture and expected performance characteristics of HunterX.

---

## Architecture Performance

HunterX is designed for concurrent, thread-safe operation:

- **Thread-safe design** — All shared state is protected by locks or uses thread-safe data structures. Caches use LRU eviction with thread-safe access.
- **Async operations** — Skill and agent execution uses `asyncio` for cooperative concurrency. I/O-bound operations (AI provider calls, file loading, HTTP requests) run without blocking the event loop.
- **C3 (Command-Query Separation)** — The system clearly separates commands (writes) from queries (reads). This allows cache-friendly read patterns and predictable locking behavior.

---

## Caching Layers

| Cache                | Key                 | Eviction        | Purpose                                        |
|----------------------|---------------------|-----------------|------------------------------------------------|
| AI Cache             | SHA256(input)       | TTL + LRU       | Caches AI provider responses to identical prompts |
| Skill Cache          | SHA256(input)       | TTL + LRU       | Caches skill execution results for identical inputs |
| Reasoning Memory     | Goal hash           | TTL + LRU       | Stores reasoning results for repeated goals     |
| Agent Memory         | Agent ID + context  | Per-agent TTL + LRU | Stores per-agent state and intermediate results |

All caches use:

- **SHA256 hashing** for deterministic cache keys
- **Configurable TTL** (time-to-live) to limit stale data
- **LRU eviction** to bound memory usage

---

## Concurrent Execution

- **AgentScheduler** — Manages agent execution with a priority queue and dependency resolution. Agents with higher priority or no dependencies execute first. Dependent agents wait until their prerequisites complete.
- **SkillExecutor** — Executes skills with configurable concurrency limits. Skills are dispatched to the thread pool for blocking operations or run as async tasks for non-blocking operations.
- **Thread pool** — A configurable thread pool handles blocking HTTP requests and other synchronous I/O. Pool size is set via `HX_THREAD_POOL_SIZE` (default: 10).

---

## Database Performance

- **SQLite** with WAL mode for concurrent reads
- **FTS5** for full-text search on payload content
- **Indexed queries** on all commonly filtered columns
- **Connection pooling** with a configurable pool size
- Streaming payload loading with a **50 MB per file limit** prevents memory exhaustion

---

## Memory Management

- **LRU eviction** in all caches prevents unbounded memory growth
- **Configurable TTLs** allow tuning cache freshness vs. memory usage
- **Streaming payload loading** avoids loading entire payload files into memory
- **Resource limits** on agent and skill concurrency bound peak memory

---

## Benchmark Estimates

These estimates are based on the architecture and component-level profiling. Actual performance depends on hardware, network conditions, and AI provider responsiveness.

| Operation              | Estimated Duration | Notes                                    |
|------------------------|--------------------|------------------------------------------|
| AI response (cloud)    | 500 ms - 5 s       | Varies by model, provider, and prompt    |
| AI response (local)    | 1 s - 30 s         | Depends on GPU/CPU and model size        |
| Skill execution        | 100 ms - 30 s      | Network-heavy skills take longer         |
| Cache hit (any cache)  | < 1 ms             | In-memory LRU cache lookup               |
| Payload indexing       | 1 s - 60 s         | Depends on payload size and complexity   |
| Report generation      | 100 ms - 5 s       | Larger reports with AI summaries take longer |
| Scan throughput        | Configurable       | Set via `HX_THREAD_POOL_SIZE` and concurrency limits |

For optimal throughput, tune the thread pool size, cache TTLs, and concurrency limits to match your workload and available resources.