---
layout: default
title: Reasoning Engine — HunterX v6.0.0
description: >-
  AI reasoning engine for HunterX v6.0.0 vulnerability scanner. Goal
  decomposition, task generation, and validated result processing for
  AI-assisted penetration testing, threat intelligence analysis, and
  offensive security automation.
permalink: /reasoning-engine/
---

## Reasoning Engine

## Architecture

All components are implemented in `core/reasoning/`.

### 1. `engine.py` — ReasoningOrchestrator

Single entry point for all AI operations. Processes goals through the pipeline: goal -> plan -> prompt -> AI -> validate -> result. Provides `inspect_reasoning(goal_id)` to retrieve cached results.

### 2. `goals.py` — Goal System

**GoalType** (18 enums):
`threat_modeling`, `payload_selection`, `verification`, `risk_assessment`, `planning`, `executive_report`, `technical_report`, `mitigation_recommendation`, `classification`, `summarization`, `purple_team`, `recon`, `fingerprint`, `exploit_dev`, `coverage_analysis`, `gap_analysis`, `custom`, `learning`

**GoalPriority** (5 levels):
`critical`, `high`, `medium`, `low`, `info`

**GoalStatus** lifecycle:
`PENDING` -> `PLANNING` -> `PROCESSING` -> `COMPLETED` | `FAILED` | `CANCELLED`

**Goal dataclass** fields:
`id`, `type`, `priority`, `status`, `objective`, `context`, `reasoning_result`, `created_at`, `completed_at`, `error`

### 3. `planner.py` — ReasoningPlanner

- `plan(goal)` estimates cost, duration, safety level, and model requirements
- Prioritizes goals based on priority level
- Estimates token usage and cost

### 4. `prompts.py` — ReasoningPromptManager

- 11 default prompt templates: `threat_modeling`, `payload_selection`, `verification`, `risk_assessment`, `planning`, `executive_report`, `technical_report`, `mitigation_recommendation`, `classification`, `summarization`, `purple_team`
- Builds prompts from goal + context
- Supports parameter substitution in templates

### 5. `validator.py` — OutputValidator

- Hallucination detection using 16 regex patterns
- JSON schema validation
- Confidence estimation based on specificity, hedging language, and contradiction detection
- Safety policy compliance checking

### 6. `formatter.py` — ReasoningResult

Structured result containing:
`content`, `goal_type`, `confidence`, `evidence`, `consensus`, `decision_trace`, `provider`, `model`, `latency_ms`, `token_usage`, `cost_estimate`

Supports `to_dict()` and `from_dict()` serialization.

### 7. `policies.py` — PolicyManager & ReasoningSafetyLevel

**Safety levels** (5):
`SAFEST`, `SAFE`, `BALANCED`, `ADVENTUROUS`, `RESEARCH`

Each level defines:
`allowed_topics`, `max_confidence_threshold`, `require_citation`, `require_human_review`, `allowed_providers`, `max_tokens`, `max_cost`

Uses `PRESET_POLICIES` for each level.

### 8. `consensus.py` — ConsensusEngine

- Multi-provider result aggregation
- Voting strategies: `majority_vote`, `weighted_vote`
- Confidence-based aggregation
- Conflict detection across provider responses

### 9. `confidence.py` — ConfidenceScorer

**Confidence levels** (7):
`NONE`, `VERY_LOW`, `LOW`, `MEDIUM`, `HIGH`, `VERY_HIGH`, `CERTAIN`

**Aggregation strategies**: `mean`, `median`, `max`, `min`, `weighted`

Method: `combine(results, strategy)` returns aggregated confidence score.

### 10. `memory.py` — ReasoningMemory

- TTL-based cache for reasoning results
- Search by goal type or keywords
- LRU eviction when cache is full
- Hit/miss tracking

---

## Flow

1. Agent creates a `Goal`
2. `ReasoningOrchestrator` receives the goal
3. `ReasoningPlanner` creates a plan
4. `ReasoningPromptManager` builds the prompt
5. `AIProvider` executes the request
6. `OutputValidator` validates the response
7. *(Optional)* `ConsensusEngine` aggregates multi-provider results
8. `ConfidenceScorer` scores the result
9. `ReasoningResult` is returned
10. Agent consumes the result

---

## Safety

- `PolicyManager` enforces 5 safety levels
- `OutputValidator` detects hallucinations before results reach agents
- `ConsensusEngine` can cross-validate across multiple providers
- No raw AI output ever reaches the user without validation

---

## CLI

```
hunterx reasoning inspect <goal_id>
hunterx reasoning validate --output "..."
```

---

## REST API

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/goals` | Create a goal |
| GET | `/reasoning/{goal_id}` | Get reasoning result |
| POST | `/reasoning/validate` | Validate output |
