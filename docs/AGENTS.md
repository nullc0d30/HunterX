---
layout: default
title: Autonomous Multi-Agent Platform — HunterX v6.0.0
description: >-
  Multi-agent platform for HunterX red team framework. 10 specialized
  AI-powered agents for automated vulnerability assessment, penetration testing,
  reconnaissance, and offensive security orchestration.
permalink: /agents/
---

## Autonomous Multi-Agent Platform

## Overview

HunterX v6.0.0 employs a multi-agent architecture where specialized agents collaborate through message passing and event-driven communication to perform autonomous security testing. Agents express goals that are converted into AI tasks by the Reasoning Engine, and results are validated before being consumed. Agents never communicate directly with AI providers.

---

## Architecture Components

All components are implemented under `core/agents/`.

### base.py — SecurityAgent Abstract Class

The foundational abstract class for all agents. Defines 18 methods that every agent must implement:

| Method | Purpose |
|---|---|
| `initialize()` | Set up agent resources and dependencies |
| `execute()` | Primary execution entry point |
| `create_goals()` | Generate goals based on current context |
| `consume_reasoning()` | Process reasoning results from the Reasoning Engine |
| `verify()` | Validate results before acceptance |
| `learn()` | Update internal knowledge from outcomes |
| `health()` | Return agent health status |
| `shutdown()` | Cleanly release agent resources |
| `get_capabilities()` | Return the set of capabilities this agent provides |
| `get_state()` | Return serializable agent state |
| `get_goal_queue()` | Return pending goals |
| `add_goal()` | Enqueue a new goal |
| `complete_goal()` | Mark a goal as completed |
| `fail_goal()` | Mark a goal as failed |
| `get_memory()` | Return the agent's memory store |
| `store_memory()` | Persist a key-value pair in agent memory |
| `recall_memory()` | Retrieve a value from agent memory |
| `clear_memory()` | Wipe the agent's memory store |

### orchestrator.py — AgentOrchestrator

Central coordinator responsible for loading agents, delegating goals to capable agents, and executing workflows. The orchestrator is the entry point for all multi-agent operations.

**Key responsibilities:**
- Load and initialize agents from the plugin registry
- Delegate incoming goals to the appropriate agent(s)
- Execute workflows (DAG-based) through the WorkflowEngine
- Monitor agent health and manage lifecycle

### registry.py — AgentRegistry

A singleton registry that maintains the catalog of all available agents. Supports plugin discovery for dynamic agent loading.

**Methods:**
- `register(agent)` — Register an agent instance
- `unregister(agent_id)` — Remove an agent from the registry
- `list()` — List all registered agents
- `find_by_capability(capability)` — Find agents that provide a specific capability
- Plugin discovery — Auto-detect and register agents from plugin directories

### coordinator.py — AgentCoordinator

Routes goals to capable agents and facilitates multi-provider consensus when multiple agents can satisfy a goal. The coordinator consults the AgentRegistry to identify suitable agents and manages the delegation lifecycle.

### capabilities.py — Capability System

Defines 17 `AgentCapability` enum values representing discrete capabilities that agents can advertise. The `CapabilityRegistry` manages capability-to-agent mappings for efficient goal routing.

### events.py — EventBus

A singleton event bus supporting publish/subscribe messaging with 25 distinct event types. Features include wildcard subscription patterns and event history retrieval for audit and debugging.

### messaging.py — MessageBus

A singleton message bus providing four communication patterns:
- **Request/Response** — Direct agent-to-agent queries
- **Broadcast** — One-to-many notifications
- **Notification** — One-to-one targeted messages
- **Cancellation** — Abort in-flight operations

### state.py — StateManager

Manages three categories of state:
- **Agent state** — Per-agent operational state
- **Workflow state** — State of in-progress and completed workflows
- **Task state** — State of individual tasks

Supports **snapshots** (full state capture) and **checkpoints** (point-in-time saves for recovery).

### task.py — AgentTask

Represents a unit of work with a full status lifecycle. Key properties include priority, dependencies (for ordering), and retry configuration. Tasks transition through defined states as they are processed.

### scheduler.py — AgentScheduler

Manages task execution using a priority queue. Features include dependency resolution (tasks execute only after their dependencies complete), concurrent execution, and automatic retry on failure.

### workflow.py — WorkflowEngine

Executes DAG-based workflows composed of steps. Supports five step types:

| Step Type | Behavior |
|---|---|
| `condition` | Branch execution based on a conditional expression |
| `parallel` | Execute child steps concurrently |
| `loop` | Repeat child steps until a condition is met |
| `wait` | Pause execution for a specified duration or until a condition |
| (default/sequential) | Execute steps in order |

Supports **checkpoint/resume** — workflows can be paused at checkpoints and resumed later.

### planner.py — AgentPlanner

Maps high-level goals to capable agents by consulting the CapabilityRegistry. Produces execution plans that the orchestrator and scheduler carry out.

### memory.py — AgentMemory

Per-agent key-value store with configurable TTL (time-to-live) and LRU (least-recently-used) eviction. Each agent maintains its own isolated memory partition.

### context.py — AgentContext

A unified context object that aggregates information from multiple sources:
- Knowledge Graph
- Threat Model
- Payloads
- Risk assessment data
- Session state
- Browser automation state

---

## Default Agents

All default agents reside in `core/agents/plugins/`. Each agent inherits from `SecurityAgent` and registers its capabilities with the AgentRegistry.

### 1. ReconAgent

Performs reconnaissance and information gathering. Capabilities include technology fingerprinting (web servers, frameworks, libraries) and WAF (Web Application Firewall) detection.

### 2. ThreatModelingAgent

Conducts threat modeling and attack surface analysis. Maps trust boundaries within the target environment and identifies potential attack vectors.

### 3. PlanningAgent

Responsible for scan planning and strategy selection. Allocates resources across the agent fleet based on the target profile and available capabilities.

### 4. PayloadAgent

Manages payload selection, mutation, and delivery optimization. Generates and adapts payloads to maximize effectiveness against target defenses.

### 5. VerificationAgent

Performs result verification and false positive analysis. Assigns confidence scores to findings to filter out unreliable results.

### 6. RiskAgent

Assigns risk scores to findings. Handles severity classification and priority assignment to ensure critical issues are surfaced first.

### 7. ReportingAgent

Generates structured reports from aggregated findings. Produces executive summaries and detailed technical findings.

### 8. PurpleTeamAgent

Generates purple team rules for defensive validation. Analyzes detection gaps and proposes improvements to monitoring and detection coverage.

### 9. LearningAgent

Implements adaptive learning from past engagements. Performs pattern recognition across findings and accumulates knowledge for future operations.

### 10. CoordinatorAgent

Handles inter-agent coordination, goal delegation, and conflict resolution. Acts as a mediator when multiple agents produce conflicting results or require sequenced execution.

---

## Key Principles

- **No direct AI provider communication** — Agents express goals only; the Reasoning Engine converts goals into AI tasks and returns validated results.
- **Event-driven communication** — Agents communicate exclusively through the EventBus and MessageBus.
- **DAG-based workflows** — All workflows are directed acyclic graphs supporting conditional branching, parallel execution, looping, and wait steps.
- **Isolated memory** — Each agent maintains its own memory store with configurable TTL and LRU eviction policy.
- **State persistence** — Agent, workflow, and task state can be snapshotted and checkpointed for recovery and audit.

---

## CLI

```
hunterx agents list
hunterx agents status
hunterx agents enable <id>
hunterx agents disable <id>
```

---

## REST API

| Method | Endpoint | Description |
|---|---|---|
| GET | `/agents` | List all registered agents |
| GET | `/agents/{id}` | Get details for a specific agent |
| GET | `/workflows` | List all workflows |
| GET | `/workflows/{id}` | Inspect a specific workflow |
| POST | `/workflows/{id}/run` | Execute a workflow |
| GET | `/tasks` | List scheduled tasks |
| POST | `/goals` | Create a goal for the system |
| GET | `/events` | List system events |
| GET | `/state` | System state snapshot |
| GET | `/orchestrator/health` | Orchestrator health check |

---

## Examples

### Creating a Goal via REST API

```json
POST /goals
{
  "type": "reconnaissance",
  "target": "https://example.com",
  "parameters": {
    "depth": "full",
    "fingerprinting": true,
    "waf_detection": true
  }
}
```

### Workflow Definition (DAG with Conditional and Parallel Steps)

```json
{
  "id": "scan-workflow-1",
  "steps": [
    {
      "id": "recon",
      "type": "agent",
      "agent": "ReconAgent",
      "input": {"target": "https://example.com"}
    },
    {
      "id": "threat-model",
      "type": "agent",
      "agent": "ThreatModelingAgent",
      "depends_on": ["recon"]
    },
    {
      "id": "plan",
      "type": "agent",
      "agent": "PlanningAgent",
      "depends_on": ["recon", "threat-model"]
    },
    {
      "id": "payload-gen",
      "type": "agent",
      "agent": "PayloadAgent",
      "depends_on": ["plan"]
    },
    {
      "id": "parallel-exec",
      "type": "parallel",
      "depends_on": ["payload-gen"],
      "steps": [
        {"id": "verify", "type": "agent", "agent": "VerificationAgent"},
        {"id": "risk", "type": "agent", "agent": "RiskAgent"}
      ]
    },
    {
      "id": "high-severity-check",
      "type": "condition",
      "depends_on": ["parallel-exec"],
      "condition": "output.risk.max_severity == 'critical'",
      "true_step": "purple-team",
      "false_step": "report"
    },
    {
      "id": "purple-team",
      "type": "agent",
      "agent": "PurpleTeamAgent"
    },
    {
      "id": "report",
      "type": "agent",
      "agent": "ReportingAgent",
      "depends_on": ["purple-team", "parallel-exec"]
    }
  ]
}
```

### Agent Registration (Plugin Discovery)

```python
# Agents are auto-discovered from core/agents/plugins/
# Manual registration example:
from core.agents.registry import AgentRegistry
from core.agents.plugins.recon_agent import ReconAgent

registry = AgentRegistry()
registry.register(ReconAgent())
```

### Event Subscription

```python
from core.agents.events import EventBus

bus = EventBus()

# Subscribe to all agent-related events
bus.subscribe("agent.*", my_handler)

# Subscribe to a specific event
bus.subscribe("agent.goal.completed", completion_handler)

# Publish an event
bus.publish("agent.goal.created", {"agent_id": "recon-1", "goal": {...}})
```

### Inter-Agent Messaging

```python
from core.agents.messaging import MessageBus

bus = MessageBus()

# Send a request and await a response
response = bus.request("ReconAgent", {"action": "fingerprint", "target": url})

# Broadcast a notification to all agents
bus.broadcast("system.shutdown", {"reason": "maintenance"})
```

---

## State Lifecycle

### Task States

```
PENDING -> QUEUED -> RUNNING -> SUCCEEDED
                              -> FAILED -> RETRYING -> RUNNING
                              -> CANCELLED
```

### Workflow States

```
PENDING -> RUNNING -> COMPLETED
                   -> FAILED
                   -> PAUSED (checkpoint) -> RUNNING
```

### Agent States

```
INITIALIZING -> IDLE -> BUSY -> SHUTDOWN
                -> ERROR -> IDLE
```
