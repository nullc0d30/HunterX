<div align="center">

# ⚔️ HunterX

**AI-Assisted Vulnerability Hunter — Observe · Hypothesize · Probe · Verify**

[![GitHub Release](https://img.shields.io/github/v/release/nullc0d30/HunterX?style=flat-square&logo=github)](https://github.com/nullc0d30/HunterX/releases)
[![PyPI Version](https://img.shields.io/pypi/v/hunterx?style=flat-square&logo=pypi)](https://pypi.org/project/hunterx/)
[![Python Version](https://img.shields.io/pypi/pyversions/hunterx?style=flat-square&logo=python)](https://python.org)
[![License](https://img.shields.io/badge/license-Apache%202.0-green?style=flat-square)](https://www.apache.org/licenses/LICENSE-2.0)
[![Tests](https://img.shields.io/github/actions/workflow/status/nullc0d30/HunterX/test.yml?style=flat-square&label=tests)](https://github.com/nullc0d30/HunterX/actions)
[![Ruff](https://img.shields.io/badge/ruff-0%20errors-brightgreen?style=flat-square)](https://github.com/astral-sh/ruff)
[![Docker](https://img.shields.io/badge/docker-multi--stage-2496ED?style=flat-square&logo=docker)](https://hub.docker.com/r/nullc0d30/hunterx)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macOS%20%7C%20windows-lightgrey?style=flat-square)](https://github.com/nullc0d30/HunterX)
[![Downloads](https://img.shields.io/pypi/dm/hunterx?style=flat-square&logo=pypi)](https://pypi.org/project/hunterx/)
[![DOI](https://img.shields.io/badge/DOI-10.5281/zenodo.xxxxxxx-blue?style=flat-square)](https://zenodo.org)

```bash
# One-shot scan
hunterx target.com

# Full scan with AI analysis
hunterx scan https://target.com --ai --ai-model llama3.2

# List modules, run diagnostics, view reports
hunterx module list
hunterx doctor
hunterx report

# Start the API server
hunterx api --port 8443
```

[Install](#installation) •
[Quick Start](#quick-start) •
[CLI Reference](#cli-reference) •
[Examples](#examples) •
[Configuration](#configuration) •
[Contributing](#contributing)

</div>

---

## Features

### 🔍 Intelligent Scanning Engine

HunterX follows a structured four-stage pipeline — **Observe → Hypothesize → Probe → Verify** — rather than blind payload spraying. Each phase is backed by dedicated components that coordinate through an event bus.

| Stage | What It Does |
|---|---|
| **Observe** | Fingerprint technologies, enumerate endpoints, detect WAFs, gather context |
| **Hypothesize** | Form security hypotheses based on observed attack surface |
| **Probe** | Execute targeted tests via 41 security skills with intelligent payload selection |
| **Verify** | Validate findings, eliminate false positives, assign confidence scores |

### 🧠 AI Reasoning Engine

18 goal types flow through a planner → prompt builder → AI provider → validator → consensus pipeline. Every decision produces structured output with confidence scores, evidence citations, and decision traces.

### 🛡️ 41 Security Skills

Plugin-based skills covering web, API, cloud, network, authentication, and infrastructure security. Each skill carries MITRE ATT&CK, OWASP, CWE, and CAPEC metadata — independently installable, cacheable, policy-driven, and telemetry-tracked.

### 🤖 Multi-Agent Platform

10 specialized agents communicate through concurrent event and message buses, executing DAG-based workflows with state persistence, checkpoint, and resume.

### 🔗 Knowledge Graph

Graph-based entity-relationship store for security findings, attack paths, targets, and contextual data — enabling cross-scan correlation and path inference.

### 📦 Payload Intelligence

SQLite + FTS5 indexed payload repository with a 5-level safety policy, 10-family mutation engine, provenance tracking, user feedback loop, and context-aware selection.

### 📊 Enterprise Reporting

JSON, Markdown, SARIF 2.1 (VS Code / GitHub CodeQL), standalone HTML, attack graph visualization, purple team detection rules, and ZIP evidence packages.

### 🔌 REST API

FastAPI server with 40+ endpoints covering scanning, payload management, agent coordination, reasoning, skills, AI provider management, and system health.

---

## Comparison

HunterX stands apart from traditional security scanners by unifying AI-assisted reasoning, multi-agent orchestration, and enterprise reporting into a single platform.

| Tool | Scanning | AI | Multi-Agent | Payload Intelligence | Reporting | Architecture |
|---|---|---|---|---|---|---|
| **HunterX** | Observe → Hypothesize → Probe → Verify | ✅ LLM-native (multi-provider) | ✅ 10 agents, DAG workflows | ✅ FTS5-indexed, 5-level policy | ✅ SARIF, HTML, graph, purple team | Unified Python framework |
| **Nmap** | Port scan + service detection | ❌ | ❌ | ❌ | ❌ XML/Grepable | C, single-purpose |
| **Metasploit** | Exploit delivery + post-exploit | ❌ | ❌ | ❌ | ❌ Console-only | Ruby, framework |
| **Nuclei** | YAML template matching | ❌ | ❌ | ❌ | ❌ JSON/STDOUT | Go, template engine |
| **Amass** | Subdomain + ASN enumeration | ❌ | ❌ | ❌ | ❌ JSON/graph | Go, single-purpose |
| **Sliver** | C2 + implant framework | ❌ | ❌ | ❌ | ❌ CLI/console | Go, C2-focused |
| **ffuf** | Fuzzing / wordlist brute-force | ❌ | ❌ | ❌ | ❌ JSON/CSV | Go, single-purpose |

### Key Differentiators

- **Reasoning-driven** — HunterX hypothesizes what vulnerabilities *might* exist before probing, then verifies. Other tools spray payloads blindly.
- **AI-native** — LLMs aren't bolted on. The reasoning engine, skill planner, report generator, and detection pipeline all consume structured AI output natively.
- **Multi-agent orchestration** — 10 specialized agents collaborate via event bus for coordinated scanning. DAG-based workflows with checkpoint/resume.
- **Payload Intelligence Platform** — FTS5-searchable payload repository with provenance tracking, mutation engine, user feedback loop, and safety policy.
- **Single codebase** — Python monorepo. No juggling 6 different tools and piping output between them.

---

## Installation

### Linux (All Distributions)

The recommended way to install HunterX on Linux:

```bash
curl -sSL https://raw.githubusercontent.com/nullc0d30/HunterX/main/install.sh | sudo bash
```

The installer automatically detects your distribution and installs all dependencies:

<details>
<summary><b>Per-distribution package details</b></summary>

| Distribution | System Packages | Command |
|---|---|---|
| **Ubuntu / Debian** | `python3 python3-pip python3-venv` | `sudo apt-get install -y python3 python3-pip python3-venv` |
| **Fedora / RHEL** | `python3 python3-pip python3-venv` | `sudo dnf install -y python3 python3-pip python3-venv` |
| **Arch** | `python python-pip` | `sudo pacman -S --noconfirm python python-pip` |
| **Alpine** | `python3 py3-pip` | `sudo apk add python3 py3-pip` |
| **openSUSE** | `python3 python3-pip python3-venv` | `sudo zypper install -y python3 python3-pip python3-venv` |

</details>

After installation, the `hunterx` command (and case-variant symlinks `HunterX`, `Hunterx`, `hunterX`, `HUNTERX`) are available globally.

### pip

```bash
pip install hunterx
```

### pipx

```bash
pipx install hunterx
```

### From Source

```bash
git clone https://github.com/nullc0d30/HunterX.git
cd HunterX
pip install .
```

### Optional Extras

```bash
# API server support (FastAPI + Uvicorn)
pip install hunterx[api]

# Browser intelligence (Playwright)
pip install hunterx[browser]

# Graph visualization (Graphviz)
pip install hunterx[graphviz]

# ML clustering (scikit-learn)
pip install hunterx[ml]

# All extras
pip install hunterx[all]
```

### Docker

```bash
# Pull the latest image
docker pull nullc0d30/hunterx:latest

# Run a scan
docker run --rm -v $(pwd)/reports:/data nullc0d30/hunterx:latest scan target.com

# API mode
docker run --rm -p 8443:8443 nullc0d30/hunterx:latest api --port 8443

# With AI analysis
docker run --rm -v $(pwd)/reports:/data \
    -e OPENAI_API_KEY=sk-... \
    nullc0d30/hunterx:latest \
    scan target.com --ai --ai-model gpt-4
```

---

## Quick Start

```bash
# Scan a target with default settings
hunterx example.com

# Explicit scan command
hunterx scan https://target.com

# List available scan modules
hunterx module list

# View scan reports
hunterx report

# Run system diagnostics
hunterx doctor

# View configuration
hunterx config --show

# Update payloads and modules
hunterx update
```

<details>
<summary><b>Profiles & Presets</b></summary>

```bash
# Internal profile (comprehensive)
hunterx scan target.com --profile internal

# Bounty profile (balanced, bug-bounty-oriented)
hunterx scan target.com --profile bounty

# Government profile (strict compliance)
hunterx scan target.com --profile gov

# Quick preset (common vectors only)
hunterx scan target.com --preset quick

# Full preset (all skills)
hunterx scan target.com --preset full

# Stealth preset (low noise)
hunterx scan target.com --preset stealth
```

</details>

<details>
<summary><b>Authentication Scanning</b></summary>

```bash
# Basic auth
hunterx scan target.com --auth basic --username admin --password secret

# Bearer token
hunterx scan target.com --auth bearer --token eyJhbGciOiJIUzI1NiIs...

# Cookie-based session
hunterx scan target.com --auth cookie --cookie-file cookies.json

# Form login
hunterx scan target.com --auth form --username admin \
    --login-url https://target.com/login

```

</details>

<details>
<summary><b>AI-Assisted Scanning</b></summary>

```bash
# Local Ollama
hunterx scan target.com --ai --ai-model llama3.2

# OpenAI
hunterx scan target.com --ai --ai-model gpt-4

# AI reasoning goal
hunterx reasoning create --goal "Assess authentication security" --target target.com
```

</details>

---

## CLI Reference

### Global Options

```
hunterx [--help] [--version] [-v] [-q] <command> [options]
```

| Flag | Description |
|---|---|
| `--help` | Show help and exit |
| `--version` | Show version and exit |
| `-v`, `--verbose` | Increase verbosity (`-v` INFO, `-vv` DEBUG) |
| `-q`, `--quiet` | Suppress output (errors only) |

### Commands

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

### Scan Options

#### Target

| Argument | Description | Default |
|---|---|---|
| `target` | Target URL or domain | Required |
| `-p`, `--payload-dir` | Payload directory | `payloads/` |
| `-o`, `--output-dir` | Output directory | `reports/` |
| `-c`, `--config` | YAML config file | `hunterx.yaml` |

#### Profiles & Presets

| Argument | Description | Default |
|---|---|---|
| `--profile` | Operator profile: `internal`, `bounty`, `gov` | `bounty` |
| `--preset` | Scan preset: `quick`, `full`, `stealth` | `full` |
| `--category` | Comma-separated skill categories | all |
| `--stealth` | Stealth level: `low`, `medium`, `high` | `low` |
| `--threads` | Concurrent threads | `5` |

#### Execution

| Argument | Description |
|---|---|
| `--dry-run` | Logic verification only (no requests sent) |
| `--passive-only` | Stage 0 reconnaissance only |
| `--insecure` | Disable SSL verification |

#### Authentication

| Argument | Description |
|---|---|
| `--auth` | Auth type: `none`, `basic`, `bearer`, `cookie`, `form` |
| `--username` | Auth username |
| `--password` | Auth password |
| `--token` | Bearer token or JWT |
| `--cookie-file` | JSON cookie file |
| `--login-url` | Form login URL |
| `--login-data` | Form login data as `key=value,key2=value2` |

#### AI / LLM

| Argument | Description |
|---|---|
| `--ai` | Enable AI/LLM analysis |
| `--ai-model` | AI model name |
| `--ai-endpoint` | Custom AI endpoint |

#### Advanced

| Argument | Description |
|---|---|
| `--oob` | Enable out-of-band detection |
| `--collaborator` | Collaborator URL for OOB callbacks |
| `--visual` | Visualization mode: `cli`, `web`, `off` |
| `--sarif` | Generate SARIF report |
| `--graph` | Generate knowledge graph |
| `--attack-graph` | Generate visual attack graph |
| `--threat-model` | Generate threat model |
| `--risk` | Run risk analysis |
| `--purple` | Generate purple team detection rules |
| `--explain` | Generate AI explanations |
| `--browser` | Enable browser intelligence |
| `--risk-profile` | Risk scoring profile |
| `--memory-db` | Use SQLite for adaptive memory |
| `--plugin-dirs` | Plugin directories |

### Subcommand Reference

<details>
<summary><b>module</b> — List and search scan modules</summary>

```bash
hunterx module list            # List all modules
hunterx module info <id>       # Show module details
hunterx module search <query>  # Search modules
```

</details>

<details>
<summary><b>report</b> — View scan reports</summary>

```bash
hunterx report                          # Overview
hunterx report -o <dir>                 # Custom output directory
hunterx report --json                   # Raw JSON output
```

</details>

<details>
<summary><b>config</b> — View configuration</summary>

```bash
hunterx config --show                   # Show current config
```

</details>

<details>
<summary><b>update</b> — Update payloads and modules</summary>

```bash
hunterx update                          # Update everything
hunterx update --force                  # Force re-download
hunterx update --release                # Download release
hunterx update --payloads               # Payloads only
```

</details>

<details>
<summary><b>payload</b> — Payload Intelligence</summary>

```bash
hunterx payload sync                    # Sync payloads
hunterx payload index                   # Index into search DB
hunterx payload search <query>          # Search payloads
hunterx payload info <id>               # Payload reasoning
hunterx payload stats                   # Repository stats
hunterx payload top                     # Top performers
hunterx payload feedback                # Feedback stats
hunterx payload policy                  # Execution policy
hunterx payload provenance <query>      # Provenance records
```

</details>

<details>
<summary><b>agents</b> — Agent management</summary>

```bash
hunterx agents list                     # List registered agents
hunterx agents status                   # Agent status
hunterx agents enable <id>              # Enable agent
hunterx agents disable <id>             # Disable agent
```

</details>

<details>
<summary><b>workflow</b> — Workflow management</summary>

```bash
hunterx workflow run <id>               # Run a workflow
hunterx workflow inspect <id>           # Inspect a workflow
hunterx workflow graph <id>             # Show dependency graph
```

</details>

<details>
<summary><b>reasoning</b> — Reasoning engine</summary>

```bash
hunterx reasoning inspect <goal_id>     # Inspect reasoning result
hunterx reasoning validate <goal_id>    # Validate reasoning output
```

</details>

<details>
<summary><b>skills</b> — Security Skills Framework</summary>

```bash
hunterx skills list                     # List all skills
hunterx skills info <id>                # Skill details
hunterx skills search <query>           # Search skills
hunterx skills install <path>           # Install skill
hunterx skills uninstall <id>           # Uninstall skill
hunterx skills enable <id>              # Enable skill
hunterx skills disable <id>             # Disable skill
hunterx skills verify <id>              # Verify installation
hunterx skills doctor <id>              # Run diagnostics
hunterx skills export <id>              # Export skill
hunterx skills stats                    # Telemetry stats
```

</details>

<details>
<summary><b>ai</b> — AI Provider commands</summary>

```bash
hunterx ai providers                    # List providers
hunterx ai health                       # Check provider health
hunterx ai config                       # View AI configuration
hunterx ai cache                        # Cache statistics
hunterx ai metrics                      # AI metrics
hunterx ai test                         # Test a provider
hunterx ai models                       # List models
```

</details>

<details>
<summary><b>api</b> — Start the API server</summary>

```bash
hunterx api --port 8443                 # Start on port 8443
hunterx api --host 0.0.0.0 --port 8080  # Custom host/port
```

</details>

---

## Examples

### Basic Reconnaissance

```bash
# Passive recon only
hunterx scan target.com --passive-only

# Stealth scan for production
hunterx scan target.com --stealth high --threads 2

# Dry run (verify logic, no requests)
hunterx scan target.com --dry-run
```

### Advanced Scanning

```bash
# Full internal assessment
hunterx scan https://internal.target.com --profile internal --preset full \
    --auth bearer --token $TOKEN --oob --collaborator http://burpcollab.net

# Bug bounty quick check
hunterx scan target.com --profile bounty --preset quick \
    --category injection,authentication

# API security assessment
hunterx scan api.target.com --category api,cloud \
    --evidence-level high --sarif
```

### AI-Powered Analysis

```bash
# AI analysis with local Ollama
hunterx scan target.com --ai --ai-model llama3.2

# With custom endpoint
hunterx scan target.com --ai --ai-model gpt-4 --ai-endpoint https://my-openai-proxy.example.com

# Generate AI explanations for findings
hunterx scan target.com --ai --explain
```

### Reporting

```bash
# Generate SARIF for CodeQL integration
hunterx scan target.com --sarif

# Generate visual attack graph
hunterx scan target.com --attack-graph

# Generate threat model
hunterx scan target.com --threat-model

# Generate purple team detection rules
hunterx scan target.com --purple

# Generate knowledge graph
hunterx scan target.com --graph
```

### Bulk Scanning

```bash
# Using targets file (one URL per line)
hunterx scan target.com -f targets.txt

# With dry run first
hunterx scan target.com --dry-run -f targets.txt
```

---

## Project Structure

```
hunterx/
├── __init__.py           # Package root, exports main
├── __main__.py           # python -m hunterx entry point
├── cli.py                # CLI entry point (argparse, 13 commands)
├── api/                  # FastAPI REST server
├── core/                 # Core engine subsystems
│   ├── agents/           # 10-agent platform
│   ├── ai/               # AI provider abstraction layer
│   ├── auth/             # Authentication providers
│   ├── protocols/        # Protocol testers (WebSocket, GraphQL)
│   ├── reasoning/        # Reasoning engine (18 goal types)
│   ├── skills/           # 41 security skills framework
│   ├── classifier.py     # Payload classifier
│   ├── detector.py       # Core detector engine
│   ├── fingerprint.py    # Technology fingerprinting
│   ├── mutation_engine.py# Payload mutation (10 families)
│   ├── oob.py            # Out-of-band detection
│   ├── passive.py        # Passive intelligence
│   ├── profiles.py       # Operator profiles
│   ├── session.py        # HTTP session management
│   └── waf.py            # WAF fingerprinting (50+ signatures)
├── engines/              # Orchestration engine
├── modules/              # Pluggable modules
│   ├── intelligence/     # Knowledge graph, threat modeling
│   └── payloads/         # Payload Intelligence Platform
├── plugins/              # User-extensible plugins
│   ├── detectors/        # Detector plugin example
│   ├── hooks/            # Lifecycle hook plugin example
│   └── reporters/        # Reporter plugin example
├── reporting/            # Report generation (JSON, SARIF, HTML, etc.)
├── utils/                # Shared utilities (logging, plugin loader)
└── config/               # Configuration (hunterx.yaml)
```

---

## Configuration

HunterX reads `hunterx.yaml` from the current directory by default. Key sections:

| Section | Purpose |
|---|---|
| `ai.providers` | AI provider settings, API keys, model selection |
| `scan.profiles` | Operator profiles (internal, bounty, gov) |
| `scan.presets` | Scan presets (quick, full, stealth) |
| `scan.stealth` | Stealth level timing and delay controls |
| `payload.policy` | Execution safety policy (safe → paranoid) |
| `payload.mutation` | Mutation engine configuration |
| `agents` | Agent registration and configuration |
| `skills` | Skill policy, caching, and registry |
| `report.format` | Output format configuration |
| `api` | REST API server settings |

Override with `hunterx scan target.com -c /path/to/config.yaml`.

---

## Updating

```bash
# Update everything (payloads + modules)
hunterx update

# Force full re-download
hunterx update --force

# Download release instead of git clone
hunterx update --release

# Payloads only
hunterx update --payloads
```

For the installed package itself:

```bash
pip install --upgrade hunterx
```

---

## Uninstall

```bash
# If installed via pip / pipx
pip uninstall hunterx
pipx uninstall hunterx

# If installed via install.sh
sudo rm -rf /opt/hunterx
sudo rm -f /usr/local/bin/hunterx
sudo rm -f /usr/local/bin/{HunterX,Hunterx,hunterX,HUNTERX}
```

---

## Troubleshooting

<details>
<summary><b>Command not found after installation</b></summary>

Ensure `/usr/local/bin` is in your PATH:
```bash
export PATH="$PATH:/usr/local/bin"
```
Add to `~/.bashrc` or `~/.zshrc` to make permanent.

</details>

<details>
<summary><b>Python 3.11+ not found</b></summary>

```bash
# Ubuntu / Debian
sudo apt-get install -y python3 python3-pip python3-venv

# Fedora
sudo dnf install -y python3 python3-pip python3-venv

# Arch
sudo pacman -S python python-pip
```

</details>

<details>
<summary><b>pip install fails</b></summary>

Ensure you have a recent version of pip:
```bash
python3 -m pip install --upgrade pip
```

If you see `externally-managed-environment` errors, use a virtual environment:
```bash
python3 -m venv venv
source venv/bin/activate
pip install hunterx
```

</details>

<details>
<summary><b>Permission denied</b></summary>

If the `hunterx` command is not executable:
```bash
chmod +x $(which hunterx)
```

</details>

<details>
<summary><b>AI provider errors</b></summary>

```bash
# Check AI provider health
hunterx ai health

# View configured providers
hunterx ai providers

# Test a specific provider
hunterx ai test --provider openai
```

</details>

---

## FAQ

<details>
<summary><b>What makes HunterX different from other scanners?</b></summary>

HunterX uses a reasoning-driven pipeline (Observe → Hypothesize → Probe → Verify) rather than blind payload spraying. It integrates AI-assisted analysis, a multi-agent platform, a security skills framework, knowledge graph, and enterprise reporting into a single unified platform.

</details>

<details>
<summary><b>Do I need an AI provider?</b></summary>

No. AI analysis is optional. HunterX runs all 41 skills without AI. Enable it with `--ai` when you want LLM-assisted analysis, explanation, or reasoning.

</details>

<details>
<summary><b>Is HunterX free?</b></summary>

Yes. HunterX is open-source under the Apache 2.0 license. Free to use, modify, and distribute.

</details>

<details>
<summary><b>Can I add custom skills?</b></summary>

Yes. HunterX has a plugin system for detectors, reporters, hooks, and skills. See `docs/SKILL_SDK.md` and `docs/PLUGIN_DEVELOPMENT.md`.

</details>

<details>
<summary><b>Does HunterX work on Windows?</b></summary>

HunterX is primarily a Linux-native CLI application. It can run on Windows via WSL, or using `python -m hunterx` in a native Python environment.

</details>

<details>
<summary><b>How do I report a vulnerability in HunterX itself?</b></summary>

Use GitHub Private Vulnerability Reporting: `https://github.com/nullc0d30/HunterX/security/advisories/new`

</details>

---

## Roadmap

### Short-Term (v6.x)

- Community skill repository with versioning
- Anthropic Claude, Google Gemini, AWS Bedrock providers
- Automatic provider failover with health checking
- A/B model comparison

### Medium-Term (v7.x)

- Native CI/CD integrations (GitHub Actions, GitLab CI, Jenkins)
- SIEM connectors (Splunk, Elasticsearch, QRadar)
- Ticketing integration (Jira, ServiceNow)
- Collaborative multi-user scanning

### Long-Term

- Public skill marketplace with ratings and reviews
- Community detection rules
- Interactive in-app tutorials
- Enterprise features (RBAC, audit logging, SSO)

---

## Contributing

HunterX is Apache 2.0 licensed and welcomes contributions of all forms.

```bash
# Fork and clone
git clone https://github.com/YOUR_USERNAME/HunterX.git
cd HunterX

# Create a virtual environment
python -m venv venv
source venv/bin/activate
pip install -e ".[all]"

# Create a feature branch
git checkout -b feat/your-feature

# Run tests
pytest tests/ -v

# Check code style
ruff check .

# Commit with DCO sign-off
git commit -s -m "feat(area): concise description"

# Push and open a pull request
git push origin feat/your-feature
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full contribution guide.

---

## License

```
Copyright 2026 Ahmed Awad (NullC0d3)

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

---

<div align="center">

**HunterX** — *Observe. Hypothesize. Probe. Verify.*

[GitHub](https://github.com/nullc0d30/HunterX) ·
[Docker Hub](https://hub.docker.com/u/nullc0d30) ·
[Issues](https://github.com/nullc0d30/HunterX/issues) ·
[Discussions](https://github.com/nullc0d30/HunterX/discussions)

</div>
