---
layout: default
title: Security Skills Framework (SSF) — HunterX v6.0.0
description: >-
  Security Skills Framework (SSF) for HunterX v6.0.0 vulnerability scanner.
  41 built-in security skills for web, API, cloud, and infrastructure
  vulnerability detection. Architecture, components, and SDK for skill
  development in the open-source red team framework.
permalink: /security-skills-framework/
---

## Security Skills Framework (SSF)

> HunterX v6.0.0 — Architecture, Components, and SDK

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Core Components](#core-components)
   - [Base Skill (base.py)](#1-basepy--securityskill)
   - [Skill Registry (registry.py)](#2-registrypy--skillregistry)
   - [Skill Loader (loader.py)](#3-loaderpy--skillloader)
   - [Skill Metadata (metadata.py)](#4-metadatapy--skillmetadata)
   - [Skill Capability (capability.py)](#5-capabilitypy--skillcapability)
   - [Skill Executor (executor.py)](#6-executorpy--skillexecutor)
   - [Skill Planner (planner.py)](#7-plannerpy--skillplanner)
   - [Skill Validator (validator.py)](#8-validatorpy--skillvalidator)
   - [Skill Context (context.py)](#9-contextpy--skillcontext)
   - [Skill Result (result.py)](#10-resultpy--skillresult)
   - [Skill Policy (policy.py)](#11-policypy--skillpolicy--safetylevel)
   - [Skill Cache (cache.py)](#12-cachepy--skillcache)
   - [Skill Telemetry (telemetry.py)](#13-telemetrypy--skilltelemetry)
   - [Skill Marketplace (marketplace.py)](#14-marketplacepy--skillmarketplace)
4. [Built-in Default Skills](#built-in-default-skills)
5. [CLI Reference](#cli-reference)
6. [REST API Reference](#rest-api-reference)
7. [SDK — Creating a Custom Skill](#sdk--creating-a-custom-skill)

---

## Overview

The Security Skills Framework (SSF) is the modular skill execution engine powering HunterX v6.0.0. All components are implemented under `core/skills/`. The framework provides a pluggable architecture for security assessment capabilities — from reconnaissance and analysis to exploitation and reporting — governed by a safety policy system, telemetry, caching, and a full lifecycle management layer.

---

## Architecture

```
core/skills/
  base.py          — Abstract base class for all skills
  registry.py      — Central singleton registry
  loader.py        — Skill discovery and loading
  metadata.py      — Skill metadata model
  capability.py    — Capability enum (45 values)
  executor.py      — Central execution engine
  planner.py       — Goal/objective-based skill planning
  validator.py     — Safety and result validation
  context.py       — Runtime execution context
  result.py        — Standardized skill result model
  policy.py        — Safety policies (5 levels)
  cache.py         — Result caching (SHA256, LRU, TTL)
  telemetry.py     — Per-skill execution telemetry
  marketplace.py   — Install/export/verify skill packages
  plugins/         — 41 built-in default skills
```

---

## Core Components

### 1. `base.py` — SecuritySkill

**Abstract class** that every skill must implement.

#### Abstract / Overridable Methods

| Method | Description |
|---|---|
| `initialize(context)` | One-time setup before execution |
| `execute(context, params)` | Main skill logic (async) |
| `validate(context, result)` | Post-execution validation |
| `verify(context)` | Integrity / health check |
| `cleanup(context)` | Resource teardown |
| `explain()` | Human-readable description of what the skill does |
| `estimate_cost()` | Estimated execution cost (credits / tokens) |
| `estimate_duration()` | Estimated execution time |
| `risk_level()` | Pre-computed risk level for this skill |
| `get_capabilities()` | List of capabilities this skill provides |
| `to_dict()` | Serialize skill metadata to dictionary |

#### SkillState Enum

| Value | Description |
|---|---|
| `UNINITIALIZED` | Skill has not been initialized |
| `READY` | Skill is ready for execution |
| `EXECUTING` | Skill is currently running |
| `COMPLETED` | Execution finished successfully |
| `FAILED` | Execution encountered an error |
| `DISABLED` | Skill is disabled and cannot be executed |

---

### 2. `registry.py` — SkillRegistry

**Singleton** that maintains the global catalog of registered skills.

| Method | Description |
|---|---|
| `register(skill)` | Register a skill instance |
| `unregister(skill_id)` | Remove a skill from the registry |
| `get(skill_id)` | Retrieve a skill by ID |
| `list()` | List all registered skills |
| `search(query)` | Search skills by name/description/tags |
| `filter_by_risk(level)` | Filter skills by risk level |
| `filter_by_capability(cap)` | Filter skills by capability |
| `enable(id)` | Enable a disabled skill |
| `disable(id)` | Disable an enabled skill |
| `health()` | Health check across all registered skills |
| `count()` | Total number of registered skills |

---

### 3. `loader.py` — SkillLoader

Discovers and loads skill definitions from disk.

| Method | Description |
|---|---|
| `discover_builtin()` | Loads skills from the `plugins/` directory |
| `discover_plugins(dirs)` | Loads skills from external directories |
| `load_from_path(path)` | Loads a single skill file from a given path |

---

### 4. `metadata.py` — SkillMetadata

Data model describing a skill's identity, constraints, and security posture.

| Field | Type / Values |
|---|---|
| `skill_id` | `str` — unique identifier |
| `name` | `str` — human-readable name |
| `description` | `str` — detailed description |
| `version` | `str` — semver |
| `author` | `str` |
| `license` | `str` |
| `tags` | `list[str]` |
| `categories` | `list[str]` |
| `required_capabilities` | `list[SkillCapability]` |
| `supported_protocols` | `list[str]` |
| `supported_technologies` | `list[str]` |
| `supported_languages` | `list[str]` |
| `risk_level` | `RiskLevel` — `NONE`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |
| `noise_level` | `NoiseLevel` — `SILENT`, `LOW`, `MEDIUM`, `HIGH`, `AGGRESSIVE` |
| `safety_policy` | `str` or policy reference |
| `dependencies` | `list[str]` |
| `mitre_techniques` | `list[str]` — MITRE ATT&CK technique IDs |
| `owasp_categories` | `list[str]` — OWASP Top 10 / ASVS categories |
| `cwe_ids` | `list[str]` — CWE identifiers |
| `capec_ids` | `list[str]` — CAPEC identifiers |
| `cvss_reference` | `str` — CVSS vector or reference |
| `required_permissions` | `list[str]` |
| `expected_artifacts` | `list[str]` |
| `timeout_seconds` | `int` |
| `retry_allowed` | `bool` |
| `max_retries` | `int` |
| `created_at` | `datetime` |
| `updated_at` | `datetime` |

---

### 5. `capability.py` — SkillCapability

Enumeration of **45 capability values** organized into categories.

#### Categories

| Category | Capabilities |
|---|---|
| **RECON** | `DNS_INTELLIGENCE`, `SUBDOMAIN_ENUMERATION`, `WAF_FINGERPRINTING`, `FINGERPRINT_CORRELATION`, `SECRETS_DETECTION` |
| **ANALYSIS** | `TECHNOLOGY_DETECTION`, `HTTP_ANALYSIS`, `TLS_ANALYSIS`, `COOKIE_ANALYSIS`, `AUTH_ANALYSIS`, `JWT_ANALYSIS`, `OAUTH_ANALYSIS`, `CORS_ANALYSIS`, `CSP_ANALYSIS` |
| **VERIFICATION** | `DIRECTORY_ENUMERATION`, `FILE_UPLOAD` |
| **EXPLOITATION** | `CSRF`, `CLICKJACKING`, `OPEN_REDIRECT`, `LFI`, `RFI`, `SSRF`, `XXE`, `SSTI`, `SQL_INJECTION`, `NOSQL_INJECTION`, `COMMAND_INJECTION`, `PATH_TRAVERSAL`, `DESERIALIZATION` |
| **DETECTION** | `GRAPHQL`, `WEBSOCKET`, `REST_API`, `OPENAPI`, `GRPC` |
| **REPORTING** | *(capabilities integrated across all skills)* |
| **SOCIAL** | *(capabilities integrated across all skills)* |
| **INFRASTRUCTURE** | `CLOUD_METADATA`, `S3`, `AZURE_BLOB`, `GCP_STORAGE`, `KUBERNETES`, `DOCKER`, `CI_CD_SECRETS` |
| **CLOUD** | *(same as INFRASTRUCTURE cloud-specific capabilities)* |

**Full list of 45 values:**
`TECHNOLOGY_DETECTION`, `HTTP_ANALYSIS`, `TLS_ANALYSIS`, `COOKIE_ANALYSIS`, `AUTH_ANALYSIS`, `JWT_ANALYSIS`, `OAUTH_ANALYSIS`, `CORS_ANALYSIS`, `CSP_ANALYSIS`, `CSRF`, `CLICKJACKING`, `OPEN_REDIRECT`, `DIRECTORY_ENUMERATION`, `FILE_UPLOAD`, `LFI`, `RFI`, `SSRF`, `XXE`, `SSTI`, `SQL_INJECTION`, `NOSQL_INJECTION`, `COMMAND_INJECTION`, `PATH_TRAVERSAL`, `DESERIALIZATION`, `GRAPHQL`, `WEBSOCKET`, `REST_API`, `OPENAPI`, `GRPC`, `DNS_INTELLIGENCE`, `SUBDOMAIN_ENUMERATION`, `WAF_FINGERPRINTING`, `FINGERPRINT_CORRELATION`, `SECRETS_DETECTION`, `CLOUD_METADATA`, `S3`, `AZURE_BLOB`, `GCP_STORAGE`, `KUBERNETES`, `DOCKER`, `CI_CD_SECRETS`

---

### 6. `executor.py` — SkillExecutor

Central execution engine responsible for running skills with caching, telemetry, and concurrency controls.

| Feature | Description |
|---|---|
| `execute(skill_id, context, params, use_cache)` | Execute a skill by ID |
| Cache integration | SHA256-derived cache key from skill + params + target |
| TTL | Configurable time-to-live for cached results |
| LRU eviction | Least-recently-used eviction policy |
| Telemetry | Per-skill: avg time, success rate, confidence, retries |
| Concurrent execution limits | Configurable max concurrent skill executions |
| Pre/post execution hooks | Hook system for before/after execution logic |

---

### 7. `planner.py` — SkillPlanner

Recommends and sequences skills based on goals or objectives.

| Method | Description |
|---|---|
| `plan_for_goal(goal_type, context)` | Returns recommended skills for a given goal type |
| `plan_for_objective(objective, technologies, protocols)` | Returns a sequenced list of skills for a specific objective |

Uses a **keyword-to-capability mapping** to match natural-language objectives to skill capabilities.

---

### 8. `validator.py` — SkillValidator

Multi-layered validation for targets, policies, results, evidence, and safety.

| Method | Description |
|---|---|
| `validate_target(target, policy)` | Checks whether a target is within scope per policy |
| `validate_policy(skill, policy)` | Checks whether a skill complies with the active safety policy |
| `validate_result(result, schema)` | Validates that a result matches the expected schema |
| `validate_evidence(result, min_confidence)` | Checks whether evidence meets the minimum confidence threshold |
| `validate_safety(skill, policy, target)` | Comprehensive safety check combining target, policy, and skill validation |

---

### 9. `context.py` — SkillContext

Rich runtime context provided to every skill during execution.

| Attribute | Description |
|---|---|
| `knowledge_graph` | In-memory knowledge graph of discovered entities |
| `threat_model` | Current threat model for the target |
| `payloads` | Payload generator / manager |
| `risk_engine` | Risk scoring engine |
| `browser` | Browser automation instance |
| `session` | HTTP session |
| `policy` | Active safety policy |
| `target_url` | Target under assessment |
| `technologies` | Detected technologies for the target |
| `evidence_level` | Required evidence rigor level |

---

### 10. `result.py` — SkillResult

Standardized output model for all skill executions.

| Field | Type / Values |
|---|---|
| `skill_id` | `str` |
| `status` | `PASS`, `FAIL`, `ERROR`, `UNKNOWN` |
| `confidence` | `float` (0.0–1.0) |
| `summary` | `str` |
| `details` | `str` or structured data |
| `evidence` | `list[dict]` |
| `artifacts` | `list[str]` — file paths or references |
| `purple_team_rules` | `dict` — detection rules for purple team exercises |
| `mitre_mappings` | `list[str]` — MITRE ATT&CK technique IDs |
| `cwe_mappings` | `list[str]` — CWE identifiers |
| `capec_mappings` | `list[str]` — CAPEC identifiers |
| `risk_score` | `float` |
| `severity` | `str` — severity label |
| `duration_ms` | `int` — execution time in milliseconds |
| `error` | `str` or `None` — error message if status is ERROR |
| `metadata` | `dict` — additional metadata |

---

### 11. `policy.py` — SkillPolicy & SafetyLevel

Five safety levels governing skill behavior and constraints.

#### SafetyLevel

| Level | Description |
|---|---|
| `SAFE` | Maximum safety — no destructive actions, strict evidence requirements |
| `BALANCED` | Moderate — allows low-risk destructive actions |
| `AGGRESSIVE` | Permissive — allows medium-risk actions |
| `RESEARCH` | Highly permissive — allows high/critical risk actions with minimal constraints |
| `PARANOID` | Extreme caution — maximum restrictions, everything requires explicit approval |

#### Per-Level Configuration

Each level defines:

| Setting | Description |
|---|---|
| `max_risk` | Maximum allowed `RiskLevel` |
| `max_noise` | Maximum allowed `NoiseLevel` |
| `allow_destructive` | Whether destructive techniques are permitted |
| `require_evidence` | Whether evidence collection is mandatory |
| `max_concurrent` | Maximum concurrent skill executions |
| `require_auth` | Whether authentication is required |
| `allowed_targets` | Target scope restrictions |
| `rate_limit` | Request rate limiting configuration |

---

### 12. `cache.py` — SkillCache

Result cache to avoid redundant skill executions.

| Feature | Description |
|---|---|
| **Key derivation** | SHA256 of skill ID + serialized parameters + target identifier |
| **TTL** | 300 seconds (default) |
| **Eviction** | LRU — maximum 1000 entries |
| **Tracking** | Hit/miss counters |

---

### 13. `telemetry.py` — SkillTelemetry

Tracks per-skill execution statistics.

| Metric | Description |
|---|---|
| `executions` | Total execution count |
| `avg_time` | Average execution time (ms) |
| `min_time` | Minimum execution time (ms) |
| `max_time` | Maximum execution time (ms) |
| `success_count` | Number of successful executions |
| `fail_count` | Number of failed executions |
| `success_rate` | Success ratio (0.0–1.0) |
| `avg_confidence` | Average confidence across all results |
| `avg_retries` | Average number of retries |
| `last_executed` | Timestamp of last execution |

| Method | Description |
|---|---|
| `get_summary()` | Aggregate telemetry across all skills |

---

### 14. `marketplace.py` — SkillMarketplace

Manages the lifecycle of skill packages (install, uninstall, verify, export).

| Method | Description |
|---|---|
| `install(path)` | Install a skill from a zip file or directory |
| `uninstall(skill_id)` | Remove an installed skill |
| `enable(id)` | Enable a skill |
| `disable(id)` | Disable a skill |
| `verify(id)` | Check installation integrity |
| `export_package(id, output_path)` | Package a skill for distribution |

Uses a **SQLite index** to track installed skills and their metadata.

---

## Built-in Default Skills

All **41 built-in skills** reside in `core/skills/plugins/` and are discovered by `SkillLoader.discover_builtin()`.

| # | Skill |
|---|---|
| 1 | Technology Detection |
| 2 | HTTP Header Analysis |
| 3 | TLS Analysis |
| 4 | Cookie Analysis |
| 5 | Auth Analysis |
| 6 | JWT Analysis |
| 7 | OAuth Analysis |
| 8 | CORS Analysis |
| 9 | CSP Analysis |
| 10 | CSRF |
| 11 | Clickjacking |
| 12 | Open Redirect |
| 13 | Directory Enumeration |
| 14 | File Upload |
| 15 | LFI |
| 16 | RFI |
| 17 | SSRF |
| 18 | XXE |
| 19 | SSTI |
| 20 | SQL Injection |
| 21 | NoSQL Injection |
| 22 | Command Injection |
| 23 | Path Traversal |
| 24 | Deserialization |
| 25 | GraphQL |
| 26 | WebSocket |
| 27 | REST API |
| 28 | OpenAPI |
| 29 | gRPC |
| 30 | DNS Intelligence |
| 31 | Subdomain Enumeration |
| 32 | WAF Fingerprinting |
| 33 | Fingerprint Correlation |
| 34 | Secrets Detection |
| 35 | Cloud Metadata |
| 36 | S3 |
| 37 | Azure Blob |
| 38 | GCP Storage |
| 39 | Kubernetes |
| 40 | Docker |
| 41 | CI/CD Secrets |

---

## CLI Reference

All skill management commands are under the `hunterx skills` namespace.

| Command | Description |
|---|---|
| `hunterx skills list` | List all registered skills |
| `hunterx skills info <id>` | Show detailed metadata for a skill |
| `hunterx skills search <query>` | Search skills by query string |
| `hunterx skills install <path>` | Install a skill from a zip file or directory |
| `hunterx skills uninstall <id>` | Uninstall a skill |
| `hunterx skills enable <id>` | Enable a disabled skill |
| `hunterx skills disable <id>` | Disable an enabled skill |
| `hunterx skills verify <id>` | Verify skill installation integrity |
| `hunterx skills doctor --skill-id <id>` | Run diagnostics on a specific skill |
| `hunterx skills export <id> --output <path>` | Export a skill as a distributable package |
| `hunterx skills stats --skill-id <id>` | Show execution telemetry for a skill |

---

## REST API Reference

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/skills` | List all skills |
| `GET` | `/skills/{id}` | Get skill metadata |
| `GET` | `/skills/search?q=` | Search skills |
| `POST` | `/skills/install` | Install a skill package |
| `POST` | `/skills/{id}/enable` | Enable a skill |
| `POST` | `/skills/{id}/disable` | Disable a skill |
| `GET` | `/skills/{id}/verify` | Verify a skill |
| `GET` | `/skills/stats` | Telemetry summary across all skills |

---

## SDK — Creating a Custom Skill

Skills are implemented by subclassing `SecuritySkill` and implementing the required abstract methods. Below is a minimal template.

```python
from core.skills.base import SecuritySkill
from core.skills.metadata import SkillMetadata, RiskLevel, NoiseLevel
from core.skills.capability import SkillCapability


class MySkill(SecuritySkill):
    @property
    def metadata(self) -> SkillMetadata:
        return SkillMetadata(
            skill_id="my_skill",
            name="My Custom Skill",
            description="Does something useful",
            version="1.0.0",
            risk_level=RiskLevel.LOW,
            noise_level=NoiseLevel.LOW,
        )

    @property
    def capabilities(self) -> list[SkillCapability]:
        return [SkillCapability.HTTP_ANALYSIS]

    async def execute(self, context, params=None):
        # Implementation goes here
        return self._success("Done", confidence=0.9)
```

### Key points

- **`metadata` property** — must return a fully populated `SkillMetadata` instance.
- **`capabilities` property** — must return a list of `SkillCapability` values the skill provides.
- **`execute` method** — receives a `SkillContext` and optional parameters; returns a `SkillResult`.
- Helper methods (`_success`, `_fail`, `_error`) on `SecuritySkill` simplify result construction.
- Skills can override `initialize`, `validate`, `verify`, `cleanup`, and other lifecycle methods as needed.
