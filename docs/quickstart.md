---
layout: default
title: Quickstart Guide — HunterX v6.0.0
keywords: Quickstart, penetration testing, bug bounty, vulnerability scanner
description: >-
  Install and run HunterX v6.0.0 in 5 minutes. Covers pip installation, Docker
  deployment, basic scanning, AI-assisted scanning, authentication, profiles,
  presets, and API server mode.
---

## Quickstart Guide

Install and run HunterX in 5 minutes.

---

## Prerequisites

- Python 3.11+
- pip or pipx
- (Optional) Docker
- (Optional for AI features) [Ollama](https://ollama.ai) or OpenAI API key

---

## Installation

### pip (Recommended)

```bash
pip install hunterx
```

### Docker

```bash
docker pull nullc0d30/hunterx:latest
docker run --rm nullc0d30/hunterx:latest --help
```

See the full [Installation Guide](installation) for all methods (pipx, install.sh, source).

---

## Your First Scan

```bash
# One-shot scan
hunterx target.com

# Explicit scan command
hunterx scan https://example.com
```

This runs a standard scan with all 41 security skills, response differential analysis, and WAF detection.

### Scan Presets

```bash
# Quick preset (common vectors only)
hunterx scan https://example.com --preset quick

# Full preset (all skills, maximum coverage)
hunterx scan https://example.com --preset full --threads 10

# Stealth preset (low noise, production-safe)
hunterx scan https://example.com --preset stealth
```

---

## Profiles

```bash
# Bounty profile — balanced, bug-bounty-oriented skills
hunterx scan https://example.com --profile bounty

# Internal profile — comprehensive, all skills
hunterx scan https://example.com --profile internal

# Government profile — strict compliance, detailed reporting
hunterx scan https://example.com --profile gov
```

---

## Authentication Scanning

```bash
# Basic authentication
hunterx scan https://example.com --auth basic --username admin --password secret

# Bearer token
hunterx scan https://example.com --auth bearer --token eyJhbGciOiJIUzI1NiIs...

# Cookie-based session
hunterx scan https://example.com --auth cookie --cookie-file cookies.json

# Form login
hunterx scan https://example.com --auth form --username admin \
    --login-url https://example.com/login

```

---

## AI-Assisted Scanning

```bash
# Local model with Ollama
hunterx scan https://example.com --ai --ai-model llama3.2

# OpenAI
hunterx scan https://example.com --ai --ai-model gpt-4

# Custom AI settings
hunterx scan https://example.com --ai --ai-model gpt-4 --ai-endpoint https://my-proxy.example.com
```

---

## Multi-Target Scanning

```bash
# Targets file (one URL per line)
hunterx scan target.com -f targets.txt

# Dry run (logic check only, no requests sent)
hunterx scan target.com --dry-run
```

---

## API Server Mode

```bash
# Start the API server
hunterx api --port 8443
```

Submit scan jobs via REST API:

```bash
curl -X POST http://localhost:8443/scan \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com", "profile": "bounty"}'
```

See the [REST API reference](api) for all 40+ endpoints.

---

## Docker Usage

```bash
# Basic scan with reports volume
docker run --rm \
  -v $(pwd)/reports:/data \
  nullc0d30/hunterx:latest \
  scan target.com -o /data

# AI-assisted scan
docker run --rm \
  -v $(pwd)/reports:/data \
  -e OPENAI_API_KEY=sk-... \
  nullc0d30/hunterx:latest \
  scan target.com --ai --ai-model gpt-4 -o /data

# API server
docker run --rm -p 8443:8443 nullc0d30/hunterx:latest api --port 8443
```

See the [Docker Guide](Docker_Guide) for production deployment.

---

## Output

Reports are generated in the output directory:

| Format | Use Case |
|---|---|
| **Markdown** | Human-readable summary |
| **JSON** | Machine-parsable findings |
| **SARIF 2.1** | VS Code / GitHub CodeQL |
| **HTML** | Interactive dashboard |
| **Attack Graph** | Visual path analysis |
| **ZIP** | Evidence package |

---

## What's Next

- [Installation Guide](installation) — All install methods
- [CLI Reference](cli) — All commands and arguments
- [REST API](api) — All endpoints and examples
- [Security Skills Framework](security-skills-framework) — 41 skills
- [Docker Guide](Docker_Guide) — Production deployment
- [Plugin Development](plugin-development) — Extend HunterX
- [Contributing](contributing) — How to contribute
