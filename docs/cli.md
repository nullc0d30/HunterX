---
layout: default
title: CLI Reference — HunterX v6.0.0
keywords: CLI reference, hunterx commands, penetration testing CLI
description: >-
  Complete CLI reference for HunterX vulnerability scanner. All commands,
  options, flags, subcommands, and practical usage examples.
permalink: /cli/
---

## CLI Reference

HunterX ships with a unified command-line interface.

```bash
hunterx [global-options] <command> [subcommand] [options]
```

---

## Global Options

| Flag | Description |
|---|---|
| `--help` | Show help and exit |
| `--version` | Show version and exit |
| `-v`, `--verbose` | Increase verbosity (`-v` INFO, `-vv` DEBUG) |
| `-q`, `--quiet` | Suppress output (errors only) |

---

## Commands

| Command | Description |
|---|---|
| `scan` | Run a vulnerability scan against a target |
| `module` | List and search scan modules |
| `report` | View scan reports and system overview |
| `doctor` | Run system diagnostics |
| `config` | View configuration |
| `update` | Update payloads and modules |
| `api` | Run as API server |
| `payload` | Payload Intelligence Platform commands |
| `agents` | Agent management commands |
| `workflow` | Workflow management commands |
| `reasoning` | Reasoning engine commands |
| `skills` | Security Skills Framework commands |
| `ai` | AI Provider commands |

---

## Scan Options

### Target

| Argument | Description | Default |
|---|---|---|---|
| `target` | Target URL or domain | Required |
| `-p`, `--payload-dir` | Payload directory | `payloads/` |
| `-o`, `--output-dir` | Output directory | `reports/` |
| `-c`, `--config` | YAML config file | `hunterx.yaml` |

### Profiles & Presets

| Flag | Description | Default |
|---|---|---|
| `--profile` | Operator profile: `internal`, `bounty`, `gov` | `bounty` |
| `--preset` | Scan preset: `quick`, `full`, `stealth` | `full` |
| `--category` | Comma-separated skill categories | all |
| `--stealth` | Stealth level: `low`, `medium`, `high` | `low` |
| `--threads` | Concurrent threads | `5` |

### Execution

| Flag | Description |
|---|---|---|
| `--dry-run` | Logic verification only (no requests sent) |
| `--passive-only` | Stage 0 reconnaissance only |
| `--insecure` | Disable SSL verification |

### Authentication

| Flag | Description |
|---|---|
| `--auth` | Auth type: `none`, `basic`, `bearer`, `cookie`, `form` |
| `--username` | Auth username |
| `--password` | Auth password |
| `--token` | Bearer token or JWT |
| `--cookie-file` | JSON cookie file |
| `--login-url` | Form login URL |

### AI / LLM

| Flag | Description |
|---|---|
| `--ai` | Enable AI/LLM analysis |
| `--ai-model` | AI model name |
| `--ai-endpoint` | Custom AI endpoint |

### Advanced

| Flag | Description |
|---|---|
| `--oob` | Enable out-of-band detection |
| `--collaborator` | Collaborator URL for OOB callbacks |
| `--sarif` | Generate SARIF report |
| `--graph` | Generate knowledge graph |
| `--attack-graph` | Generate visual attack graph |
| `--threat-model` | Generate threat model |
| `--risk` | Run risk analysis |
| `--purple` | Generate purple team detection rules |
| `--explain` | Generate AI explanations |
| `--browser` | Enable browser intelligence |

---

## Subcommand Reference

### `hunterx scan` — Vulnerability Scanning

Run a vulnerability scan against a target. This is the primary command.

```bash
hunterx scan https://target.com --profile bounty --preset full
hunterx scan target.com --ai --ai-model llama3.2
hunterx scan https://target.com --auth bearer --token $TOKEN --oob
```

### `hunterx module` — Module Management

List and search available scan modules.

```bash
hunterx module list
hunterx module info <id>
hunterx module search <query>
```

### `hunterx report` — Report Viewer

View scan reports and system overview.

```bash
hunterx report
hunterx report -o <dir>
hunterx report --json
```

### `hunterx doctor` — Diagnostics

Run system diagnostics to verify installation and configuration.

```bash
hunterx doctor
```

### `hunterx config` — Configuration

View or validate current configuration.

```bash
hunterx config --show
```

### `hunterx update` — Updates

Update payloads and modules.

```bash
hunterx update
hunterx update --force
hunterx update --release
hunterx update --payloads
```

### `hunterx api` — REST API Server

Start the built-in REST API server.

```bash
hunterx api --port 8443
hunterx api --host 0.0.0.0 --port 8080
```

### `hunterx payload` — Payload Intelligence

```bash
hunterx payload sync
hunterx payload index
hunterx payload search <query>
hunterx payload info <id>
hunterx payload stats
hunterx payload top
hunterx payload feedback
hunterx payload policy
hunterx payload provenance <query>
```

### `hunterx agents` — Multi-Agent Platform

```bash
hunterx agents list
hunterx agents status
hunterx agents enable <id>
hunterx agents disable <id>
```

### `hunterx workflow` — Workflow Engine

```bash
hunterx workflow run <id>
hunterx workflow inspect <id>
hunterx workflow graph <id>
```

### `hunterx reasoning` — Reasoning Engine

```bash
hunterx reasoning inspect <goal_id>
hunterx reasoning validate <goal_id>
```

### `hunterx skills` — Security Skills Framework

```bash
hunterx skills list
hunterx skills info <id>
hunterx skills search <query>
hunterx skills install <path>
hunterx skills uninstall <id>
hunterx skills enable <id>
hunterx skills disable <id>
hunterx skills verify <id>
hunterx skills doctor <id>
hunterx skills export <id>
hunterx skills stats
```

### `hunterx ai` — AI Provider Management

```bash
hunterx ai providers
hunterx ai health
hunterx ai config
hunterx ai cache
hunterx ai metrics
hunterx ai test
hunterx ai models
```

---

## Examples

### Basic Scans

```bash
# Quick scan
hunterx scan https://example.com --preset quick

# Full scan with report
hunterx scan https://example.com --preset full -o ./results

# Stealth scan
hunterx scan https://example.com --stealth high --threads 2
```

### Authenticated Bounty Scan

```bash
hunterx scan https://target.com --profile bounty \
    --auth bearer --token eyJhbGciOiJIUzI1NiIs... \
    --proxy http://127.0.0.1:8080 \
    -o ./bounty-results
```

### Stealth Scan with AI

```bash
hunterx scan https://target.com --preset stealth \
    --ai --ai-model gpt-4 \
    --threads 2 --timeout 60
```

### Full Scan with All Options

```bash
hunterx scan target.com \
    --profile internal --preset full \
    --auth form --login-url https://app.target.com/login \
    --ai --ai-model llama3.2 \
    --insecure \
    -o ./full-results
```

### Payload Search and Mutation

```bash
hunterx payload search sqli
hunterx payload stats
```

### AI Provider Health

```bash
hunterx ai health
hunterx ai providers
hunterx ai models
```
