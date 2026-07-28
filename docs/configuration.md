---
layout: default
title: HunterX Configuration v6.0.0 — HunterX v6.0.0
description: Complete configuration reference for HunterX v6.0.0. YAML options, environment variables, profiles, and CLI overrides.
permalink: /configuration/
---

# HunterX Configuration v6.0.0

## Overview

HunterX uses a **3-layer configuration system** with the following priority order (highest to lowest):

1. **CLI arguments** -- Highest priority, overrides all other sources
2. **Environment variables** -- `HX_*` prefixed variables
3. **YAML config file** -- Default path: `hunterx.yaml`

Each layer merges with and overrides the layers below it. Values not specified at any layer retain their compiled defaults.

---

## 1. Config File (hunterx.yaml)

The primary configuration file is written in YAML. Below is the full reference:

```yaml
# HunterX Configuration
profile: bounty
stealth: medium
threads: 5
verify_ssl: true
output_dir: reports
evidence_level: medium
min_confidence: 0.0

# Intelligence Layer
intel: true
graph: true
attack_graph: true
threat_model: false
risk: false
purple: false
explain: true
browser: false
risk_profile: default
memory_db: true

# AI Configuration
ai:
  enabled: false
  model: llama3.2
  endpoint: http://localhost:11434
  provider: ollama
  cache_enabled: true
  metrics_enabled: true
  enable_streaming: false
  enable_fallback: true
  max_retries: 3
  default_provider: ollama
  default_model: llama3.2
  profiles:
    default:
      provider: ollama
      model: llama3.2
      temperature: 0.7
      max_tokens: 2048
    gpt4:
      provider: openai
      model: gpt-4
      temperature: 0.5
      max_tokens: 4096

# Auth Configuration
auth:
  type: none
  username: ""
  password: ""
  token: ""
  cookie_file: ""
  login_url: ""
  login_data: {}

# OOB Configuration
oob:
  enabled: false
  collaborator_url: ""

# Rate Limiting
rate_limit:
  max_rps: 10
  burst: 20

# Proxy
proxy:
  http: ""
  https: ""

# Presets
presets:
  quick:
    threads: 10
    stealth: low
    evidence_level: low
  full:
    threads: 20
    stealth: low
    evidence_level: high
  stealth:
    threads: 3
    stealth: high
    evidence_level: medium
```

### Top-Level Fields

| Field | Type | Default | Description |
|---|---|---|---|
| `profile` | string | `bounty` | Active preset/profile name |
| `stealth` | string | `medium` | Stealth level: `low`, `medium`, `high` |
| `threads` | integer | `5` | Maximum concurrent threads |
| `verify_ssl` | boolean | `true` | Verify TLS/SSL certificates |
| `output_dir` | string | `reports` | Directory for output and reports |
| `evidence_level` | string | `medium` | Evidence collection detail: `low`, `medium`, `high` |
| `min_confidence` | float | `0.0` | Minimum confidence threshold (0.0-1.0) |

### Intelligence Layer

| Field | Type | Default | Description |
|---|---|---|---|
| `intel` | boolean | `true` | Enable intelligence gathering |
| `graph` | boolean | `true` | Enable relationship graphing |
| `attack_graph` | boolean | `true` | Enable attack path visualization |
| `threat_model` | boolean | `false` | Enable threat modeling |
| `risk` | boolean | `false` | Enable risk assessment |
| `purple` | boolean | `false` | Enable purple team simulations |
| `explain` | boolean | `true` | Enable AI-powered explanations |
| `browser` | boolean | `false` | Enable browser-based analysis |
| `risk_profile` | string | `default` | Risk assessment profile name |
| `memory_db` | boolean | `true` | Enable in-memory database caching |

### AI Configuration (`ai`)

| Field | Type | Default | Description |
|---|---|---|---|
| `enabled` | boolean | `false` | Enable AI features |
| `model` | string | `llama3.2` | Default AI model identifier |
| `endpoint` | string | `http://localhost:11434` | AI provider endpoint URL |
| `provider` | string | `ollama` | Active AI provider |
| `cache_enabled` | boolean | `true` | Cache AI responses |
| `metrics_enabled` | boolean | `true` | Collect AI performance metrics |
| `enable_streaming` | boolean | `false` | Enable streaming responses |
| `enable_fallback` | boolean | `true` | Fall back to alternative providers on failure |
| `max_retries` | integer | `3` | Maximum retry attempts on failure |
| `default_provider` | string | `ollama` | Default provider for profile resolution |
| `default_model` | string | `llama3.2` | Default model for profile resolution |
| `profiles` | map | (see below) | Per-profile provider/model/temperature/max_tokens settings |

#### AI Profiles

Each profile entry supports the following fields:

| Field | Type | Description |
|---|---|---|
| `provider` | string | AI provider for this profile |
| `model` | string | Model identifier for this profile |
| `temperature` | float | Sampling temperature (0.0-1.0+) |
| `max_tokens` | integer | Maximum tokens per response |

**Default profiles:**

```yaml
profiles:
  default:
    provider: ollama
    model: llama3.2
    temperature: 0.7
    max_tokens: 2048
  gpt4:
    provider: openai
    model: gpt-4
    temperature: 0.5
    max_tokens: 4096
```

### Auth Configuration (`auth`)

| Field | Type | Default | Description |
|---|---|---|---|
| `type` | string | `none` | Authentication type: `none`, `basic`, `bearer`, `cookie`, `form` |
| `username` | string | `""` | Username for basic/form auth |
| `password` | string | `""` | Password for basic/form auth |
| `token` | string | `""` | Bearer token |
| `cookie_file` | string | `""` | Path to cookie jar file |
| `login_url` | string | `""` | Form-based login endpoint |
| `login_data` | map | `{}` | Additional form login fields |

### OOB Configuration (`oob`)

| Field | Type | Default | Description |
|---|---|---|---|
| `enabled` | boolean | `false` | Enable out-of-band (OOB) interaction detection |
| `collaborator_url` | string | `""` | OOB collaborator service URL (e.g., Burp Collaborator) |

### Rate Limiting (`rate_limit`)

| Field | Type | Default | Description |
|---|---|---|---|
| `max_rps` | integer | `10` | Maximum requests per second |
| `burst` | integer | `20` | Maximum burst size |

### Proxy (`proxy`)

| Field | Type | Default | Description |
|---|---|---|---|
| `http` | string | `""` | HTTP proxy URL (e.g., `http://127.0.0.1:8080`) |
| `https` | string | `""` | HTTPS proxy URL |

### Presets (`presets`)

Presets are named configuration overlays that batch-set multiple fields at once.

| Preset | threads | stealth | evidence_level |
|---|---|---|---|
| `quick` | 10 | low | low |
| `full` | 20 | low | high |
| `stealth` | 3 | high | medium |

---

## 2. Environment Variables

Every configuration value can be set via environment variables using the `HX_` prefix. Nested keys use `_` as a separator.

### General

| Variable | Maps To |
|---|---|
| `HX_PROFILE` | `profile` |
| `HX_STEALTH` | `stealth` |
| `HX_THREADS` | `threads` |
| `HX_VERIFY_SSL` | `verify_ssl` |
| `HX_OUTPUT_DIR` | `output_dir` |
| `HX_EVIDENCE_LEVEL` | `evidence_level` |
| `HX_MIN_CONFIDENCE` | `min_confidence` |

### Intelligence Layer

| Variable | Maps To |
|---|---|
| `HX_INTEL` | `intel` |
| `HX_GRAPH` | `graph` |
| `HX_ATTACK_GRAPH` | `attack_graph` |
| `HX_THREAT_MODEL` | `threat_model` |
| `HX_RISK` | `risk` |
| `HX_PURPLE` | `purple` |
| `HX_EXPLAIN` | `explain` |
| `HX_BROWSER` | `browser` |
| `HX_RISK_PROFILE` | `risk_profile` |
| `HX_MEMORY_DB` | `memory_db` |

### AI Configuration

| Variable | Maps To |
|---|---|
| `HX_AI_ENABLED` | `ai.enabled` |
| `HX_AI_MODEL` | `ai.model` |
| `HX_AI_ENDPOINT` | `ai.endpoint` |
| `HX_AI_PROVIDER` | `ai.provider` |
| `HX_AI_CACHE_ENABLED` | `ai.cache_enabled` |
| `HX_AI_METRICS_ENABLED` | `ai.metrics_enabled` |
| `HX_AI_ENABLE_STREAMING` | `ai.enable_streaming` |
| `HX_AI_ENABLE_FALLBACK` | `ai.enable_fallback` |
| `HX_AI_MAX_RETRIES` | `ai.max_retries` |
| `HX_AI_DEFAULT_PROVIDER` | `ai.default_provider` |
| `HX_AI_DEFAULT_MODEL` | `ai.default_model` |

### OOB Configuration

| Variable | Maps To |
|---|---|
| `HX_OOB_ENABLED` | `oob.enabled` |
| `HX_OOB_COLLABORATOR_URL` | `oob.collaborator_url` |

### Auth Configuration

| Variable | Maps To |
|---|---|
| `HX_AUTH_TYPE` | `auth.type` |
| `HX_AUTH_USERNAME` | `auth.username` |
| `HX_AUTH_PASSWORD` | `auth.password` |
| `HX_AUTH_TOKEN` | `auth.token` |

### Rate Limiting

| Variable | Maps To |
|---|---|
| `HX_RATE_LIMIT_MAX_RPS` | `rate_limit.max_rps` |
| `HX_RATE_LIMIT_BURST` | `rate_limit.burst` |

### Proxy

| Variable | Maps To |
|---|---|
| `HX_PROXY_HTTP` | `proxy.http` |
| `HX_PROXY_HTTPS` | `proxy.https` |

---

## 3. Payload Execution Policy

Controls the aggressiveness of payload delivery and mutation. Defined as a 5-level policy system.

| Level | Description |
|---|---|
| `safe` | Only informational payloads; no mutations allowed. |
| `balanced` | Medium risk; limited mutations. **(default)** |
| `aggressive` | High risk; heavy mutations; more concurrent payloads. |
| `research` | Experimental payloads; all mutations permitted. |
| `paranoid` | Maximum safety; maximum verification before execution. |

Configuration field: `payload_policy` (string, default: `balanced`)

---

## 4. Reasoning Safety Policy

Controls the strictness of AI reasoning and content filtering.

| Level | Description |
|---|---|
| `safest` | Extreme caution; strict topic filtering; requires citations for all claims. |
| `safe` | Conservative; requires human review for high-confidence decisions. |
| `balanced` | Moderate filtering. **(default)** |
| `adventurous` | Relaxed constraints; fewer restrictions on reasoning paths. |
| `research` | Maximum freedom; experimental reasoning modes permitted. |

Configuration field: `reasoning_policy` (string, default: `balanced`)

---

## 5. Skill Policy

Controls safety and operational limits for loadable skills. Uses the same 5-level system as payload and reasoning policies.

| Setting | Description |
|---|---|
| `max_risk` | Maximum permitted risk level for a skill execution. |
| `max_noise` | Upper bound on acceptable noise/side-effect level. |
| `allow_destructive` | Whether destructive operations are permitted. |
| `require_evidence` | Require evidence collection for all skill actions. |
| `max_concurrent` | Maximum number of concurrent skill executions. |
| `require_auth` | Whether authentication is required before skill use. |
| `allowed_targets` | List of permitted target patterns/domains for skills. |
| `rate_limit` | Per-skill request rate cap. |

Configuration field: `skill_policy` (string, default: `balanced`)

Each skill's metadata declares its requirements; HunterX resolves conflicts between skill requirements and global policy by applying the more restrictive value.

---

## Configuration Precedence (Detailed)

1. **Default values** are compiled into the binary.
2. **YAML config file** overrides defaults for any key that is present.
3. **Environment variables** (`HX_*`) override both YAML and defaults.
4. **CLI flags** override all other sources for the specified keys.

This merge is shallow per top-level key; nested maps (e.g., `ai.profiles`, `auth.login_data`) are replaced entirely rather than deep-merged.