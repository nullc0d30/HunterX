---
layout: default
title: Quickstart Guide — HunterX v6.0.0
description: >-
  Install and run HunterX v6.0.0 in 5 minutes. Covers source installation, Docker
  deployment, basic scanning, AI-assisted scanning, authentication, profiles,
  presets, and API server mode.
---

# Quickstart Guide

Install and run HunterX in 5 minutes.

---

## Prerequisites

- Python 3.11+
- pip
- (Optional) Docker
- (Optional for AI features) [Ollama](https://ollama.ai) or OpenAI API key

---

## Installation

### From Source

```bash
git clone https://github.com/nullc0d30/HunterX.git
cd HunterX
pip install -r requirements.txt
python setup.py
python hunterx.py --help
```

### Docker

```bash
docker pull nullc0d30/hunterx:latest
docker run --rm nullc0d30/hunterx:latest --help
```

---

## Your First Scan

### Basic Vulnerability Scan

```bash
python hunterx.py -u https://example.com --profile bounty
```

This runs a standard bug-bounty profile scan with medium stealth, 41 security skills, response differential analysis, and WAF detection.

### Full Scan

```bash
python hunterx.py -u https://example.com --preset full --threads 10
```

Enables all available skills and runs with maximum coverage.

### Stealth Scan

```bash
python hunterx.py -u https://example.com --stealth high --threads 2 --delay 3
```

Low-noise mode with long delays, minimal threads, and conservative probing.

---

## Profiles

```bash
# Bounty profile — balanced, bug-bounty-oriented skills
python hunterx.py -u https://example.com --profile bounty

# Internal profile — comprehensive, all skills
python hunterx.py -u https://example.com --profile internal

# Government profile — strict compliance, detailed reporting
python hunterx.py -u https://example.com --profile gov
```

---

## Authentication Scanning

```bash
# Basic authentication
python hunterx.py -u https://example.com --auth basic --username admin --password secret

# Bearer token
python hunterx.py -u https://example.com --auth bearer --token eyJhbGciOiJIUzI1NiIs...

# Cookie-based session
python hunterx.py -u https://example.com --auth cookie --cookie-file cookies.json

# Form login
python hunterx.py -u https://example.com --auth form --username admin --password secret \
    --login-url https://example.com/login --username-field user --password-field pass

# JWT analysis
python hunterx.py -u https://example.com --auth jwt --token eyJhbGciOiJIUzI1NiIs...
```

---

## AI-Assisted Scanning

```bash
# Local model with Ollama
python hunterx.py -u https://example.com --ai --ai-model llama3.2 --ai-provider ollama

# OpenAI
python hunterx.py -u https://example.com --ai --ai-model gpt-4 --ai-provider openai

# Custom AI settings
python hunterx.py -u https://example.com --ai --ai-model gpt-4 --ai-temperature 0.3
```

---

## Multi-Target Scanning

```bash
# Targets file (one URL per line)
python hunterx.py -f targets.txt --profile bounty

# Dry run (logic check only, no requests sent)
python hunterx.py -f targets.txt --profile bounty --dry-run
```

---

## API Server Mode

```bash
# Start the API server
python hunterx.py api --port 8443
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
  -u https://example.com --profile bounty -o /data

# AI-assisted scan
docker run --rm \
  -v $(pwd)/reports:/data \
  -e OPENAI_API_KEY=sk-... \
  nullc0d30/hunterx:latest \
  -u https://example.com --ai --ai-model gpt-4 -o /data

# API server
docker run --rm -p 8443:8443 nullc0d30/hunterx:latest api --port 8443
```

See the [Docker Guide](docker) for production deployment.

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

- [Features & Architecture](features) — Full capability breakdown
- [CLI Reference](cli) — All commands and arguments
- [REST API](api) — All endpoints and examples
- [Security Skills Framework](security-skills-framework) — 41 skills
- [Docker Guide](docker) — Production deployment
- [Plugin Development](plugin-development) — Extend HunterX
