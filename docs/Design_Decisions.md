---
layout: default
title: Design Decisions — HunterX v6.0.0
description: Key architectural design decisions for HunterX AI-assisted vulnerability scanner. Rationale behind security testing framework choices.
permalink: /design-decisions/
---

# Design Decisions

This document explains the key architectural decisions made in HunterX and the rationale behind them.

---

## 1. Agents Don't Talk to AI

**Decision:** Agents express Goals. The Reasoning Engine converts Goals to AI prompts and validates results.

**Rationale:** Agents never directly interact with AI providers. This prevents prompt injection attacks that could arise from a compromised agent sending malicious instructions to the AI. By centralizing all AI communication through the Reasoning Engine, the system has a single point for auditing, safety enforcement, and rate limiting. Agents remain deterministic components that define work to be done, while the Reasoning Engine handles all AI interaction based on those goals.

---

## 2. Skills Don't Talk to AI

**Decision:** Skills perform deterministic security operations only. AI is reserved for the Reasoning Engine.

**Rationale:** Skills are designed to be reliable, repeatable, and auditable. By restricting skills to deterministic operations (HTTP requests, file analysis, command execution), their behavior is predictable and testable. AI-generated variability is isolated within the Reasoning Engine, where results are validated against expected schemas. This separation makes skills easier to test, debug, and secure.

---

## 3. Plugin-First Architecture

**Decision:** All major subsystems use plugin-based discovery.

**Rationale:** Plugin-based architecture allows the system to be extended without modifying core code. Providers, skills, agents, detectors, and reporters are all discovered and loaded dynamically. This enables community contributions, custom deployments, and independent versioning of components. The plugin interface is defined by abstract base classes with clear contracts.

---

## 4. Layered Safety

**Decision:** Five-level policy system at reasoning, skill, and payload execution levels, with multiple independent validation layers.

**Rationale:** Security testing tools have inherent risk. The layered safety approach ensures that no single component can bypass safety checks. The five policy levels (`default`, `prompt`, `auto`, `ask`, `prohibited`) provide granular control over what actions are permitted. Validation occurs independently at the reasoning layer (what should the AI generate?), the skill layer (what actions can be taken?), and the payload execution layer (what inputs are processed?).

---

## 5. SQLite for Local Storage

**Decision:** SQLite with FTS5 for full-text search. No external database required.

**Rationale:** SQLite provides zero-configuration persistent storage without requiring a separate database server. This aligns with HunterX's goal of being easy to deploy and use. FTS5 enables efficient full-text search across payloads and results. The trade-off is limited multi-user access, which is acceptable for a security testing tool that operates on single workstations or CI/CD runners.

---

## 6. Async Throughout

**Decision:** `async/await` for skill and agent execution. Thread pool for blocking HTTP.

**Rationale:** Security testing involves many I/O-bound operations (AI provider calls, HTTP requests, file I/O). Asynchronous execution allows concurrent operations without the overhead of thread-per-operation. The thread pool is used only for operations that are genuinely blocking (some HTTP clients, subprocess calls). This design maximizes throughput while minimizing resource usage.

---

## 7. SHA256 Caching

**Decision:** Deterministic cache keys from input hashing using SHA256.

**Rationale:** SHA256 produces consistent, collision-resistant cache keys regardless of execution order or timing. This ensures that identical inputs produce cache hits even across different runs or system states. Combined with TTL and LRU eviction, this provides efficient caching without the complexity of dependency tracking or invalidation logic.

---

## 8. Single AI Entry Point

**Decision:** `ReasoningOrchestrator` is the only component that sends prompts to AI providers.

**Rationale:** Centralizing all AI communication through a single component simplifies:

- **Auditing** — Every AI interaction passes through one code path
- **Rate limiting** — Enforcement at a single point prevents accidental circumvention
- **Safety enforcement** — Policy checks, prompt validation, and response validation occur in one place
- **Provider abstraction** — Changing AI providers requires changes in only one component

This decision is complementary to decisions 1 and 2: agents don't talk to AI, skills don't talk to AI, and the Reasoning Engine is the only component that does.