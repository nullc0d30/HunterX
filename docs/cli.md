---
layout: default
title: CLI Reference
description: >-
  Complete CLI reference for HunterX vulnerability scanner. Documenting all commands,
  options, flags, subcommands, and practical usage examples for the hunterx command-line tool.
permalink: /cli/
---

# CLI Reference

HunterX ships with a unified command-line interface. All commands follow the pattern:

```
hunterx [global-options] <command> [subcommand] [options]
```

---

## Global Options

### Core Options

| Flag | Alias | Description |
|------|-------|-------------|
| `--url` | `-u` | Target URL(s) to scan. Accepts comma-separated list. |
| `--targets-file` | `-f` | Path to a file containing target URLs (one per line). |
| `--payload-dir` | `-p` | Directory containing custom payload files. |
| `--output-dir` | `-o` | Directory to write scan reports and results. |
| `--config` | `-c` | Path to configuration file (default: `hunterx.json` or `hunterx.yaml`). |

### Profile & Mode

| Flag | Description |
|------|-------------|
| `--profile {internal,bounty,gov}` | Scan profile: `internal` (comprehensive, slower), `bounty` (focused on high-value findings), `gov` (compliance-driven). |
| `--preset {quick,full,stealth}` | Execution preset: `quick` (fast scan), `full` (exhaustive), `stealth` (low-and-slow). |
| `--stealth {low,medium,high}` | Stealth level controlling request timing and fingerprint avoidance. |
| `--threads` | Number of concurrent threads (default: auto-detected CPU count). |
| `--dry-run` | Simulate scan without sending any requests. Useful for validation. |
| `--insecure` | Disable TLS certificate verification (skip TLS errors). |
| `--proxy` | HTTP/S proxy to route traffic through (e.g., `http://127.0.0.1:8080`). |
| `--user-agent` | Custom User-Agent header. |
| `--headers` | Additional HTTP headers to include with every request (key:value pairs). |
| `--cookies` | Cookies to include with requests (key=value;key=value). |
| `--delay` | Fixed delay in milliseconds between requests. |
| `--random-delay` | Randomized delay range between requests (min-max in ms, e.g., `500-2000`). |
| `--timeout` | Request timeout in seconds (default: 30). |
| `--retries` | Number of retry attempts on failure (default: 3). |
| `--max-depth` | Maximum crawl depth for spidering (default: 5). |

### Authentication Options

| Flag | Description |
|------|-------------|
| `--auth {none,basic,bearer,cookie,form,jwt}` | Authentication method. |
| `--token` | Bearer token or JWT token value. |
| `--username` | Username for basic/form/jwt authentication. |
| `--password` | Password for basic/form/jwt authentication. |
| `--cookie-file` | Path to a Netscape-format cookie file. |
| `--login-url` | URL to POST login form data to (form auth). |
| `--username-field` | Username form field name (default: `username`). |
| `--password-field` | Password form field name (default: `password`). |

### AI Options

| Flag | Description |
|------|-------------|
| `--ai` | Enable AI-assisted analysis. |
| `--ai-model` | AI model to use (e.g., `gpt-4`, `claude-3-opus`). |
| `--ai-provider` | AI provider to use (e.g., `openai`, `anthropic`, `local`). |
| `--ai-temperature` | AI temperature setting (0.0–1.0, default: 0.2). |
| `--ai-max-retries` | Maximum retries for AI requests (default: 3). |
| `--ai-timeout` | Timeout in seconds for AI requests (default: 60). |

---

## Subcommands

### `hunterx api` — REST API Server

Start the built-in REST API server.

| Flag | Alias | Description |
|------|-------|-------------|
| `--port` | `-p` | Port to bind (default: 8000). |
| `--host` | `-H` | Host to bind (default: `127.0.0.1`). |
| `--debug` | `-d` | Enable debug mode (auto-reload, verbose logging). |

### `hunterx payload` — Payload Management

Manage the payload database.

| Subcommand | Description |
|------------|-------------|
| `stats` | Display payload database statistics. |
| `search <query>` | Search payloads by keyword or category. |
| `mutate <payload>` | Generate mutations of a given payload. |
| `feedback` | Submit feedback on payload effectiveness. |
| `sync` | Synchronize payload database with remote source. |
| `index` | Rebuild the payload search index. |

### `hunterx skills` — Security Skills Framework

Manage AI-security skills.

| Subcommand | Description |
|------------|-------------|
| `list` | List all installed skills. |
| `info <name>` | Show detailed information about a skill. |
| `install <name>` | Install a skill from the registry. |
| `uninstall <name>` | Remove an installed skill. |
| `search <query>` | Search the skill registry. |
| `categories` | List all available skill categories. |
| `mitre` | Browse MITRE ATT&CK technique mappings. |
| `execute <name> [args]` | Execute a skill directly. |

### `hunterx agents` — Multi-Agent Platform

Manage the autonomous agent fleet.

| Subcommand | Description |
|------------|-------------|
| `list` | List all registered agents and their status. |
| `status <id>` | Show status and health of a specific agent. |
| `enable <id>` | Enable a disabled agent. |
| `disable <id>` | Disable a running agent. |

### `hunterx workflow` — Workflow Engine

Manage and execute scan workflows.

| Subcommand | Description |
|------------|-------------|
| `list` | List all available workflows. |
| `create <file>` | Create a new workflow from a definition file. |
| `execute <id>` | Execute a workflow by ID. |
| `status <id>` | Check workflow execution status. |

### `hunterx reasoning` — Reasoning Engine

Manage reasoning tasks and requests.

| Subcommand | Description |
|------------|-------------|
| `create <goal>` | Create a new reasoning task from a goal description. |
| `status <id>` | Check reasoning task status. |
| `list` | List all reasoning tasks. |
| `sessions` | List active reasoning sessions. |

### `hunterx ai` — AI Provider Management

Manage AI provider connections and models.

| Subcommand | Description |
|------------|-------------|
| `providers` | List configured AI providers. |
| `health` | Check AI provider health/connectivity. |
| `test <provider>` | Run a connectivity test against a provider. |
| `models [provider]` | List available models for a provider. |
| `sessions` | List active AI sessions. |

### `hunterx config` — Configuration

View or validate configuration.

| Subcommand | Description |
|------------|-------------|
| `show` | Display current configuration. |
| `schema` | Output the configuration JSON schema. |

---

## Examples

### 1. Basic Quick Scan

```bash
hunterx -u https://example.com --preset quick -o ./results
```

### 2. Authenticated Bounty Scan with Proxy

```bash
hunterx -u https://target.com --profile bounty --auth bearer \
  --token eyJhbGciOiJIUzI1NiIs... \
  --proxy http://127.0.0.1:8080 \
  --delay 1000 --random-delay 500-1500 \
  -o ./bounty-results
```

### 3. Stealth Scan with AI Analysis

```bash
hunterx -u https://target.com --preset stealth --stealth high \
  --ai --ai-provider openai --ai-model gpt-4 \
  --threads 2 --timeout 60 --retries 2 \
  -o ./stealth-scan
```

### 4. Start API Server with Custom Configuration

```bash
hunterx api --port 9000 --host 0.0.0.0 --debug
```

### 5. List Agents and Execute a Workflow

```bash
hunterx agents list
hunterx workflow list
hunterx workflow execute scan-workflow-1
```

### 6. Payload Search and Mutation

```bash
hunterx payload search sqli
hunterx payload mutate "SELECT * FROM users"
hunterx payload stats
```

### 7. Full Scan with All Options

```bash
hunterx -f targets.txt \
  --profile internal --preset full \
  --auth form --login-url https://app.target.com/login \
  --username admin --password s3cret \
  --headers "X-API-Key: abc123" --cookies "session=xyz" \
  --ai --ai-model claude-3-opus --ai-temperature 0.1 \
  --insecure --proxy http://127.0.0.1:8080 \
  --delay 500 --timeout 30 --retries 3 --max-depth 10 \
  --threads 8 \
  -o ./full-scan-results
```

### 8. Check AI Provider Health

```bash
hunterx ai health
hunterx ai providers
hunterx ai models openai
```
