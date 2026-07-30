---
layout: default
title: Reference Guide — HunterX v6.0.0
description: >-
  Complete CLI and REST API reference for HunterX v6.0.0 vulnerability
  scanner. All commands, arguments, endpoints, and examples for the
  open-source Linux security tool for penetration testing, red team
  operations, and cybersecurity automation.
permalink: /reference-guide/
---

## Reference Guide

## Table of Contents

- [CLI Reference](#cli-reference)
  - [Usage](#usage)
  - [Core Options](#core-options)
  - [Profile & Mode](#profile--mode)
  - [Auth](#auth)
  - [OOB (Out-of-Band)](#oob-out-of-band)
  - [AI/ML](#aiml)
  - [Intelligence](#intelligence)
  - [Reporting](#reporting)
  - [Plugins](#plugins)
  - [Subcommands](#subcommands)
    - [`api` — Run as API Server](#api--run-as-api-server)
    - [`payload` — Payload Intelligence Platform](#payload--payload-intelligence-platform)
    - [`agents` — Agent Management](#agents--agent-management)
    - [`workflow` — Workflow Management](#workflow--workflow-management)
    - [`reasoning` — Reasoning Engine](#reasoning--reasoning-engine)
    - [`skills` — Security Skills Framework](#skills--security-skills-framework)
    - [`ai` — AI Provider Management](#ai--ai-provider-management)
  - [Examples](#examples)
- [REST API Reference](#rest-api-reference)
  - [Health & System Info](#health--system-info)
  - [Scan Endpoints](#scan-endpoints)
  - [Payload Intelligence Endpoints](#payload-intelligence-endpoints)
  - [AI Provider Endpoints](#ai-provider-endpoints)
  - [Agent System Endpoints](#agent-system-endpoints)
  - [Skills Framework Endpoints](#skills-framework-endpoints)
  - [Query Parameters Reference](#query-parameters-reference)

---

# CLI Reference

# HunterX v6.0.0 CLI Reference

## Usage

```
hunterx [options] <command>
```

---

## Core Options

| Flag | Description | Default |
|------|-------------|---------|
| `-u, --url TEXT` | Target URL | — |
| `-f, --targets-file FILE` | File containing multiple target URLs | — |
| `-p, --payload-dir DIR` | Payload directory | `payloads` |
| `-o, --output-dir DIR` | Output directory | `reports` |
| `-c, --config FILE` | YAML config file | `hunterx.yaml` |

---

## Profile & Mode

| Flag | Description | Default |
|------|-------------|---------|
| `--profile {internal,bounty,gov}` | Operator profile | `bounty` |
| `--preset {quick,full,stealth}` | Scan preset | — |
| `--category TEXT` | Comma-separated categories | — |
| `--stealth {low,medium,high}` | Stealth level | `medium` |
| `--threads INT` | Thread count | `5` |
| `--dry-run` | Logic only, no requests | — |
| `--passive-only` | Stage 0 only | — |
| `--insecure` | Disable SSL verification | — |

---

## Auth

| Flag | Description | Default |
|------|-------------|---------|
| `--auth {none,basic,bearer,cookie,form}` | Authentication type | `none` |
| `--username TEXT` | Auth username | — |
| `--password TEXT` | Auth password | — |
| `--token TEXT` | Bearer token or session token | — |
| `--cookie-file FILE` | JSON cookie file | — |
| `--login-url TEXT` | Form login URL | — |
| `--login-data TEXT` | Form login data as key=value pairs | — |

---

## OOB (Out-of-Band)

| Flag | Description |
|------|-------------|
| `--oob` | Enable OOB detection |
| `--collaborator URL` | Collaborator URL for OOB callbacks |

---

## AI/ML

| Flag | Description | Default |
|------|-------------|---------|
| `--ai` | Enable AI/LLM analysis | — |
| `--ai-model TEXT` | Ollama model name | `llama3.2` |
| `--ai-endpoint URL` | Ollama endpoint | `http://localhost:11434` |
| `--no-cluster` | Disable finding clustering | — |

---

## Intelligence

| Flag | Description | Default |
|------|-------------|---------|
| `--graph` | Generate knowledge graph | — |
| `--attack-graph` | Generate visual attack graph | `True` |
| `--threat-model` | Generate threat model | — |
| `--risk` | Run risk analysis | — |
| `--purple` | Generate purple team detection rules | — |
| `--explain` | Generate AI explanations | `True` |
| `--browser` | Enable browser intelligence (requires Playwright) | — |
| `--risk-profile {default,pentest,bug_bounty,compliance}` | Risk profile | `default` |
| `--memory-db` | Use SQLite for adaptive memory | `True` |

---

## Reporting

| Flag | Description | Default |
|------|-------------|---------|
| `--visual {cli,web,off}` | Visualization mode | `cli` |
| `--evidence-level {low,medium,high}` | Evidence detail level | `medium` |
| `--min-confidence FLOAT` | Minimum confidence threshold | `0.0` |
| `--sarif` | Generate SARIF 2.1 report | — |

---

## Plugins

| Flag | Description | Default |
|------|-------------|---------|
| `--plugin-dirs DIRS` | Comma-separated plugin directories | `plugins/detectors,plugins/reporters,plugins/hooks` |

---

## Subcommands

### `api` — Run as API Server

| Flag | Description | Default |
|------|-------------|---------|
| `--port INT` | Port | `8443` |
| `--host TEXT` | Host | `0.0.0.0` |

---

### `payload` — Payload Intelligence Platform

| Subcommand | Arguments | Description |
|------------|-----------|-------------|
| `sync` | `[--force] [--release]` | Sync payloads from upstream |
| `index` | `[--force] [--categories]` | Index payloads |
| `search` | `[query] [--category] [--limit] [--json]` | Search payloads |
| `info` | `<payload_id> [--target]` | Show payload details |
| `stats` | — | Show index statistics |
| `graph build` | `[--max]` | Build knowledge graph |
| `graph search` | `<query> [--type] [--json]` | Search knowledge graph |
| `graph stats` | — | Graph statistics |
| `feedback` | `[--category] [--json]` | Show payload feedback |
| `policy` | `[--level] [--json]` | Show policy recommendations |
| `provenance` | `[query] [--json]` | Show payload provenance |
| `top` | `[--category] [--limit] [--json]` | Top-rated payloads |

---

### `agents` — Agent Management

| Subcommand | Arguments | Description |
|------------|-----------|-------------|
| `list` | `[--json]` | List registered agents |
| `status` | `[--json]` | Show agent status |
| `enable` | `<agent_id>` | Enable an agent |
| `disable` | `<agent_id>` | Disable an agent |

---

### `workflow` — Workflow Management

| Subcommand | Arguments | Description |
|------------|-----------|-------------|
| `run` | `<workflow_id>` | Execute a workflow |
| `inspect` | `<workflow_id>` | Inspect workflow details |
| `graph` | `<workflow_id>` | Visualize workflow graph |

---

### `reasoning` — Reasoning Engine

| Subcommand | Arguments | Description |
|------------|-----------|-------------|
| `inspect` | `<goal_id>` | Inspect a reasoning goal |
| `validate` | `[--output TEXT]` | Validate reasoning engine |

---

### `skills` — Security Skills Framework

| Subcommand | Arguments | Description |
|------------|-----------|-------------|
| `list` | `[--json]` | List installed skills |
| `info` | `<skill_id>` | Show skill details |
| `search` | `<query>` | Search available skills |
| `install` | `<path>` | Install a skill from path |
| `uninstall` | `<skill_id>` | Remove a skill |
| `enable` | `<skill_id>` | Enable a skill |
| `disable` | `<skill_id>` | Disable a skill |
| `verify` | `<skill_id>` | Verify skill integrity |
| `doctor` | `[--skill-id]` | Diagnose skill issues |
| `export` | `<skill_id> [--output]` | Export a skill |
| `stats` | `[--skill-id]` | Show skill statistics |

---

### `ai` — AI Provider Management

| Subcommand | Arguments | Description |
|------------|-----------|-------------|
| `providers` | `[--json]` | List AI providers |
| `health` | `[--provider] [--json]` | Check provider health |
| `config` | `[--json]` | Show AI configuration |
| `cache` | `[--json]` | Show AI cache status |
| `metrics` | `[--json]` | Show AI performance metrics |
| `test` | `[--provider] [--model] [--prompt]` | Test an AI provider |
| `models` | `[--provider] [--json]` | List available models |

---

## Examples

### Basic Scan

```bash
hunterx -u http://target.com --profile bounty
```

### Scan with Intelligence Layer

```bash
hunterx -u http://target.com --graph --threat-model --risk --purple
```

### API Server

```bash
hunterx api --port 8443
```

### AI-Powered Scan

```bash
hunterx -u http://target.com --ai --ai-model llama3.2
```

### Payload Management

```bash
hunterx payload sync
hunterx payload index
hunterx payload search "XSS" --limit 10
```

### Agent Management

```bash
hunterx agents list
hunterx agents status
```

### Skills Management

```bash
hunterx skills list
hunterx skills info sql_injection
```

### AI Provider Management

```bash
hunterx ai providers
hunterx ai health --provider ollama
hunterx ai test --prompt "Analyze this log"
```

---

# REST API Reference

# HunterX v6.0.0 REST API Reference

Base URL: `http://localhost:8443`

All endpoints are implemented via **FastAPI** in `api/server.py`. Start the server:

```bash
hunterx api --port 8443
```

Requires `fastapi` and `uvicorn`:

```bash
pip install fastapi uvicorn
```

---

## Health & System Info

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | System health — returns version, copyright, and license info |
| GET | `/info` | Full system metadata |

---

## Scan Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/scan` | Start a new scan |
| GET | `/scan/{job_id}` | Get scan status and progress |
| GET | `/scan/{job_id}/results` | Get scan results (only available when status is COMPLETED) |
| GET | `/scan/{job_id}/intelligence` | Get intelligence data (knowledge graph, attack paths, threat model, risk matrix, MITRE mappings, AI explanations) |
| GET | `/scan/{job_id}/graph` | Get knowledge graph |
| GET | `/scan/{job_id}/attack-paths` | Get attack paths |
| GET | `/scan/{job_id}/risk` | Get risk matrix |
| GET | `/scan/{job_id}/mitre` | Get MITRE mappings |
| GET | `/scan/{job_id}/reasoning` | Get AI explanations |
| GET | `/jobs` | List all scan jobs |

### Start Scan

```
POST /scan
```

**Request body (ScanRequest):**

```json
{
  "url": "http://target.com",
  "profile": "bounty",
  "threads": 5,
  "stealth": "medium",
  "intel": true,
  "risk": true,
  "purple": true
}
```

**Response:**

```json
{
  "job_id": "abc123",
  "status": "queued",
  "message": "Scan started"
}
```

---

## Payload Intelligence Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/payload/stats` | Payload index statistics |
| GET | `/payload/categories` | List all payload categories |
| GET | `/payload/search` | Search payloads (`q`, `category`, `limit`, `offset`) |
| GET | `/payload/{id}` | Get a specific payload with reasoning explanation (`target` query param) |
| POST | `/payload/sync` | Sync remote payload repository (`force`, `use_release`) |
| POST | `/payload/index` | Index payloads (`force`, `categories`) |
| GET | `/payload/policy` | Get current execution policy |
| PUT | `/payload/policy` | Set policy level (`level`: `safe`, `balanced`, `aggressive`, `research`, `paranoid`) |
| GET | `/payload/feedback` | Get feedback statistics (`category`) |
| GET | `/payload/graph/stats` | Payload knowledge graph statistics |
| GET | `/payload/graph/search` | Search graph nodes (`q`, `node_type`, `limit`) |
| POST | `/payload/graph/build` | Build graph from index (`max_payloads`) |
| GET | `/payload/provenance` | Query provenance records (`q`, `limit`) |
| GET | `/payload/sync/status` | Repository sync status |

---

## AI Provider Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/ai/providers` | List registered AI providers |
| GET | `/ai/health` | Provider health check (`provider`) |
| GET | `/ai/models` | List available models (`provider`) |
| GET | `/ai/metrics` | AI metrics and statistics |
| GET | `/ai/cache` | AI cache statistics |
| POST | `/ai/chat` | Chat completion |

### AI Chat

```
POST /ai/chat
```

**Request body:**

```json
{
  "messages": [
    {"role": "user", "content": "Analyze this finding..."}
  ],
  "model": "gpt-4",
  "temperature": 0.7,
  "max_tokens": 2048,
  "json_mode": false
}
```

**Response:**

```json
{
  "content": "...",
  "model": "gpt-4",
  "usage": {
    "prompt_tokens": 120,
    "completion_tokens": 340,
    "total_tokens": 460
  },
  "latency_ms": 1234
}
```

---

## Agent System Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/agents` | List all registered agents |
| GET | `/agents/{id}` | Get agent details and health |
| GET | `/workflows` | List all workflows |
| GET | `/workflows/{id}` | Inspect a specific workflow |
| POST | `/workflows/{id}/run` | Execute a workflow |
| GET | `/tasks` | List scheduled tasks |
| POST | `/goals` | Create a reasoning goal |
| GET | `/reasoning/{goal_id}` | Get reasoning result |
| POST | `/reasoning/validate` | Validate output text |
| GET | `/events` | List system events (`event_type`, `limit`) |
| GET | `/state` | System state snapshot |
| GET | `/orchestrator/health` | Orchestrator health check |

### Create Goal

```
POST /goals
```

**Request body:**

```json
{
  "type": "threat_modeling",
  "objective": "Map attack surface for target.com",
  "context": {
    "target": "http://target.com",
    "technologies": ["nginx", "php"]
  },
  "priority": "high"
}
```

**Response:**

```json
{
  "id": "goal_123",
  "type": "threat_modeling",
  "objective": "Map attack surface for target.com",
  "context": {
    "target": "http://target.com",
    "technologies": ["nginx", "php"]
  },
  "priority": "high",
  "status": "created",
  "created_at": "2026-07-28T12:00:00Z"
}
```

---

## Skills Framework Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/skills` | List all installed skills |
| GET | `/skills/{id}` | Get skill metadata |
| GET | `/skills/search` | Search skills (`q`) |
| POST | `/skills/install` | Install a skill package (`path`) |
| POST | `/skills/{id}/enable` | Enable a skill |
| POST | `/skills/{id}/disable` | Disable a skill |
| GET | `/skills/{id}/verify` | Verify skill installation |
| GET | `/skills/stats` | Telemetry summary |

---

## Query Parameters Reference

Common query parameters used across endpoints:

| Parameter | Type | Description |
|-----------|------|-------------|
| `q` | string | Search query |
| `category` | string | Filter by category |
| `limit` | integer | Maximum number of results |
| `offset` | integer | Result offset for pagination |
| `provider` | string | AI provider name |
| `model` | string | AI model name |
| `force` | boolean | Force operation even if already up-to-date |
| `event_type` | string | Filter events by type |
| `node_type` | string | Filter graph nodes by type |
| `target` | string | Target URL or identifier |
| `level` | string | Policy level or verbosity |
| `use_release` | boolean | Use release version when syncing |
| `max_payloads` | integer | Maximum payloads to process |
| `path` | string | Filesystem path |
| `json_mode` | boolean | Request JSON-structured response from AI |
