---
layout: default
title: HunterX Architecture Guide — HunterX v6.0.0
description: >-
  Architecture guide for HunterX v6.0.0 AI-assisted vulnerability scanner.
  System design, component relationships, and data flow for the open-source
  Linux security tool and red team framework.
permalink: /architecture/
---

## HunterX Architecture Guide

**Version:** 6.0.0

---

## 1. Overview

HunterX is a modular, layered security intelligence platform. The architecture follows Clean Architecture principles with strict dependency inversion. Each layer communicates through well-defined interfaces, ensuring that internal implementations can be swapped without affecting upstream consumers. The platform is organized into distinct domains -- agent coordination, reasoning, skills execution, AI provider abstraction, intelligence enrichment, and reporting -- all governed by a central orchestration engine.

---

## 2. Architecture Diagram

```
+----------------------------------------------------------------+
|                   CLI / REST API / Docker                       |
+----------------------------------------------------------------+
|                      Orchestration Engine                       |
|           (4-Stage: Observe -> Hypothesize -> Probe -> Verify)  |
+----------------------------------------------------------------+
|  +-------------+  +--------------+  +------------------+        |
|  |    Multi-   |  |  Reasoning   |  |   Security       |        |
|  |    Agent    |  |   Engine     |  |   Skills         |        |
|  |  Platform   |  |              |  |   Framework      |        |
|  |  10 agents  |  |  Goals -> AI |  |  41 skills       |        |
|  |  Event Bus  |  |  -> Validate |  |  Registry        |        |
|  |  Workflow   |  |  -> Consensus|  |  Marketplace     |        |
|  |  Scheduler  |  |  -> Result   |  |  Telemetry       |        |
|  +-------------+  +--------------+  +------------------+        |
+----------------------------------------------------------------+
|  +-----------+ +----------+ +-----------+ +-------------+       |
|  |  Payload  | |  AI      | |Knowledge  | | Intelligence |      |
|  |Intelligence| | Provider | | Graph     | | Risk Engine  |      |
|  | Index     | | Ollama   | | Threat    | | Attack Chain |      |
|  | Search    | | OpenAI   | | Model     | | MITRE        |      |
|  | Mutation  | | Cache    | | Memory    | | Purple       |      |
|  | Feedback  | | Metrics  | | Browser   | | Explain      |      |
|  +-----------+ +----------+ +-----------+ +-------------+       |
+----------------------------------------------------------------+
|  Session  |  Config  |  Profiles  |  Auth  |  Plugins          |
|  Manager  |  System  |  3 types   |  4      |  auto-detect     |
+----------+----------+------------+--------+--------------------+
|                   Reporter (MD, JSON, SARIF, HTML)              |
+----------------------------------------------------------------+
```

---

## 3. Component Responsibilities

### CLI / REST API / Docker
Entry points to the system. The CLI provides interactive and scriptable access. The REST API enables programmatic integration. Docker images package the platform for containerized deployment. Authentication and rate limiting are enforced at this boundary.

### Orchestration Engine
Coordinates the 4-stage investigative pipeline: Observe (passive intelligence gathering), Hypothesize (generate candidate hypotheses), Probe (execute targeted checks), Verify (confirm or refute findings). Each stage is pluggable and can be extended with custom logic.

### Multi-Agent Platform
Manages the full agent lifecycle (load, activate, deactivate, dispose). Ten specialized agents communicate via an internal event bus and message bus. The Workflow Scheduler constructs and executes directed acyclic graphs (DAGs) of agent tasks, enabling parallel and sequential execution paths.

### Reasoning Engine
Converts agent-expressed Goals into structured AI prompts, dispatches them through the AI Provider layer, validates raw outputs against schemas, aggregates multiple responses via consensus, scores confidence, and returns a validated ReasoningResult. This is the decision-making core of the platform.

### Security Skills Framework
Encapsulates security operations (scanning, enumeration, exploitation, detection) into discrete, versioned Skills. The framework manages skill lifecycle (install, register, execute, update, remove). Skills are discovered through a registry, distributed via a marketplace, and instrumented with telemetry for performance and reliability tracking.

### Payload Intelligence
Provides payload indexing, semantic search, mutation generation, and feedback-driven refinement. Payload data is sourced from the community-maintained [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) knowledge base: `hunterx payload sync` synchronizes upstream content (shallow git clone or latest GitHub release archive) and `hunterx payload index` builds a local SQLite + FTS5 index. Each payload records provenance (source repository, commit hash, release tag, checksum) for auditability. Includes a payload graph that maps relationships between payloads, techniques, and observed outcomes. Enables rapid payload adaptation based on environmental feedback.

### AI Provider Layer
An abstracted interface to large language models. Supports multiple backends (Ollama, OpenAI, and others) through a consistent contract. Implements response caching, request/response metrics, middleware pipelines (logging, transformation, validation), and a routing layer that selects the optimal provider per request.

### Knowledge Platform
Maintains the threat knowledge graph, threat model definitions, risk scoring, MITRE ATT&CK mapping, purple team exercise support, and explainability modules. Serves as the authoritative source of contextual intelligence for agents and skills.

### Session / Config / Profiles / Auth
Base infrastructure layer. Session Manager tracks user and tool session state. Config System loads, merges, and validates configuration from multiple sources (file, env, remote). Profiles provide three role-based configurations. Auth supports four authentication modes. Plugins are auto-detected at startup.

### Reporter
Produces multi-format output artifacts: Markdown reports, JSON data dumps, SARIF (Static Analysis Results Interchange Format) for IDE integration, and HTML dashboards. Each format is generated by a dedicated renderer with a common data interface.

---

## 4. Dependency Graph

- All external AI communication passes exclusively through the AI Provider Abstraction Layer. Agents NEVER interact with LLMs directly.
- Agents express Goals to the Reasoning Engine, which converts Goals into AI Tasks and returns Validated Results.
- Skills perform security operations; Agents coordinate skill execution; the Reasoning Engine decides which skills to invoke and in what order.
- Skills are fully isolated from both AI providers and agents. They receive a SkillContext with runtime data and return a SkillResult with evidence.
- The Reporter depends only on normalized result data and has no knowledge of agents, skills, or AI providers.

```
CLI/API -> Orchestration -> Agents -> Reasoning -> AI Provider
                                          \-> Skills
Agents -> Skills
Skills -/-> AI Provider (isolated)
```

---

## 5. Execution Flow

1. **Entry:** CLI or REST API receives a target specification.
2. **Initialization:** Orchestration Engine loads the applicable session, config, and profile.
3. **4-Stage Pipeline:**
   - **Observe:** Passive intelligence gathering (WHOIS, DNS, certificates, search engines).
   - **Hypothesize:** Agent team generates candidate hypotheses about the target.
   - **Probe:** Skills execute targeted security checks against each hypothesis.
   - **Verify:** Results are cross-validated and confidence is scored.
4. **Intelligence Enrichment:** Raw findings are enriched through the Knowledge Platform (threat model matching, MITRE mapping, risk scoring).
5. **Reporting:** Reporter generates output in the requested format (MD, JSON, SARIF, HTML).

---

## 6. Reasoning Flow

```
Agent creates Goal
  -> ReasoningOrchestrator plans resolution strategy
    -> PromptManager builds structured prompt
      -> AIProvider executes prompt against LLM
        -> OutputValidator validates structure and content
          -> ConsensusEngine aggregates multi-sample results
            -> ConfidenceScorer assigns confidence level
              -> ReasoningResult returned to Agent
```

Each stage includes error handling, fallback strategies, and telemetry emission. The ConsensusEngine can be configured for strict (unanimous) or relaxed (majority) agreement.

---

## 7. Agent Flow

```
AgentOrchestrator loads agents from registry
  -> AgentPlanner maps goal to capable agents
    -> AgentScheduler queues tasks with priorities
      -> WorkflowEngine executes task DAG
        -> EventBus publishes state changes (start, progress, complete, fail)
          -> Results propagate back through observer chain
```

Agents operate asynchronously where possible. The EventBus allows any component to subscribe to agent lifecycle events for monitoring, logging, or triggering cross-cutting concerns.

---

## 8. Skill Flow

```
SkillPlanner recommends skills based on agent goal and target profile
  -> SkillExecutor checks cache for identical prior executions
    -> SkillContext assembled with runtime data (target, config, credentials)
      -> Skill executes security operation
        -> SkillResult returned with evidence artifacts
          -> SkillTelemetry records duration, exit code, output size, errors
```

Skills are executed in sandboxed environments where possible. Cache hits short-circuit execution entirely, returning the prior result with a cache indicator.

---

## 9. AI Provider Flow

```
AIManager receives request with model, prompt, and parameters
  -> AICache checks for exact or semantic match
    -> MiddlewarePipeline applies transforms (logging, masking, augmentation)
      -> ProviderRegistry selects and routes to correct backend (Ollama, OpenAI, etc.)
        -> RetryHandler retries on transient failures (configurable policy)
          -> CircuitBreaker opens on sustained failure threshold
            -> Response cached (keyed by prompt + model + params)
              -> Response returned to caller
```

The MiddlewarePipeline supports custom middleware registration. The CircuitBreaker prevents cascading failures when a provider is degraded. Cache invalidation follows TTL and capacity policies.
