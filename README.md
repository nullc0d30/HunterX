# HunterX — AI-Assisted Vulnerability Hunter

<div align="center">

[![GitHub Release](https://img.shields.io/github/v/release/nullc0d30/HunterX?style=flat-square&logo=github)](https://github.com/nullc0d30/HunterX/releases)
[![License](https://img.shields.io/badge/license-Apache%202.0-green?style=flat-square)](https://www.apache.org/licenses/LICENSE-2.0)
[![Python Version](https://img.shields.io/badge/python-3.11%2B-blue?style=flat-square&logo=python)](https://python.org)
[![Tests](https://img.shields.io/badge/tests-623%20passing-brightgreen?style=flat-square)](https://github.com/nullc0d30/HunterX/actions)
[![Ruff](https://img.shields.io/badge/ruff-0%20errors-brightgreen?style=flat-square)](https://github.com/astral-sh/ruff)
[![Docker](https://img.shields.io/badge/docker-multi--stage-2496ED?style=flat-square&logo=docker)](https://hub.docker.com/u/nullc0d30)
[![CI](https://img.shields.io/github/actions/workflow/status/nullc0d30/HunterX/test.yml?branch=main&style=flat-square&logo=github)](https://github.com/nullc0d30/HunterX/actions)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macOS%20%7C%20windows-lightgrey?style=flat-square)](https://github.com/nullc0d30/HunterX)
[![DOI](https://zenodo.org/badge/DOI/10.6084/m9.figshare.33102290.svg)](https://doi.org/10.6084/m9.figshare.33102290)

**HunterX** is an open-source platform for AI-assisted security assessment. It combines automated vulnerability scanning, a plugin-based security skills framework, multi-agent coordination, a reasoning engine with AI provider abstraction, knowledge graph analysis, threat modeling, and MITRE ATT&CK mapping into a single extensible platform.

![HunterX Screenshot](Screenshot%202026-07-28%20234114.png)

[Getting Started](#quick-start) •
[Documentation](#documentation-hub) •
[Installation](#installation) •
[Contributing](#contributing) •
[Report a Bug](https://github.com/nullc0d30/HunterX/issues)

---

## Table of Contents

- [Why HunterX?](#why-hunterx)
- [Feature Matrix](#feature-matrix)
- [Architecture Overview](#architecture-overview)
- [Installation](#installation)
  - [From Source](#from-source)
  - [Docker](#docker)
  - [Configuration](#configuration)
- [Quick Start](#quick-start)
  - [Basic Scan](#basic-scan)
  - [Profiles & Presets](#profiles--presets)
  - [Authentication Scanning](#authentication-scanning)
  - [AI-Assisted Scanning](#ai-assisted-scanning)
  - [Scanning Multiple Targets](#scanning-multiple-targets)
  - [API Server Mode](#api-server-mode)
- [CLI Reference](#cli-reference)
- [REST API Reference](#rest-api-reference)
  - [Scan Endpoints](#scan-endpoints)
  - [AI Provider Endpoints](#ai-provider-endpoints)
  - [Agent & Reasoning Endpoints](#agent--reasoning-endpoints)
  - [Skills Endpoints](#skills-endpoints)
  - [Payload Endpoints](#payload-endpoints)
  - [System Endpoints](#system-endpoints)
- [Capabilities](#capabilities)
  - [Reconnaissance & Fingerprinting](#reconnaissance--fingerprinting)
  - [Web Security Analysis](#web-security-analysis)
  - [API Security Analysis](#api-security-analysis)
  - [Cloud Security Analysis](#cloud-security-analysis)
  - [Authentication & Authorization](#authentication--authorization)
  - [Exploitation & Verification](#exploitation--verification)
  - [Target Profiling](#target-profiling)
- [Security Skills Framework](#security-skills-framework)
- [Reasoning Engine](#reasoning-engine)
- [Multi-Agent Architecture](#multi-agent-architecture)
- [Payload Intelligence](#payload-intelligence)
- [AI Provider Abstraction](#ai-provider-abstraction)
- [Knowledge Graph](#knowledge-graph)
- [Threat Modeling & Attack Chains](#threat-modeling--attack-chains)
- [Reporting](#reporting)
- [Safety & Security](#safety--security)
- [Contributing](#contributing)
- [Project Roadmap](#project-roadmap)
- [About the Author](#about-the-author)
- [Citation](#citation)
- [Responsible Use & Legal Notice](#responsible-use--legal-notice)
- [License](#license)
- [Acknowledgements](#acknowledgements)
- [Community](#community)

---

## Why HunterX?

Traditional vulnerability scanners operate on payload volume and signature matching. HunterX was designed around a structured reasoning pipeline: **observe, hypothesize, probe, and verify**. Each phase is backed by dedicated components that work together through a coordinated event bus.

| Capability | Description |
|---|---|
| **AI-Assisted Reasoning** | Goals flow through a reasoning engine that plans, prompts, validates, and reaches consensus before returning results. Agents never talk directly to AI providers. |
| **Security Skills Framework (41 skills)** | Plugin-based skills covering web, API, cloud, network, and infrastructure security. Each skill carries MITRE ATT&CK, OWASP, CWE, and CAPEC metadata. Skills are independently installable, cacheable, policy-driven, and telemetry-tracked. |
| **Knowledge Graph** | Graph-based storage for security relationships, findings, attack paths, and contextual data across scan targets. Enables cross-scan correlation and attack path inference. |
| **Threat Modeling & Attack Chains** | Automated threat modeling with STRIDE/LINDDUN categorization, attack chain decomposition, trust boundary mapping, and automated chain inference from scan findings. |
| **Payload Intelligence** | SQLite-indexed payload repository with FTS5 full-text search, 5-level execution policy, mutation engine (10 technique families), provenance tracking, user feedback loop, graph-based payload relationships, and context-aware selection. |
| **Explainable AI** | Every AI-driven decision produces a structured result with confidence scores, evidence citations, consensus data, decision traces, and provider metadata. |
| **Multi-Agent Architecture** | 10 specialized agents coordinate through concurrent event and message buses, executing DAG-based workflows with state persistence, checkpoint, and resume capabilities. |
| **Enterprise-Ready API** | FastAPI server with 40+ endpoints covering scanning, payload management, agent coordination, reasoning, skills, AI provider management, configuration, and system health. |
| **MITRE ATT&CK + OWASP Mapping** | All skills, findings, and recommendations carry MITRE ATT&CK techniques (Enterprise, Mobile, ICS), OWASP Top 10 categories, CWE IDs, CAPEC IDs, and CVSS v3.1 scoring for standardized reporting. |
| **WAF Detection** | 50+ WAF signature patterns with confidence scoring and auto-abort on detection. Supported WAFs include Cloudflare, AWS WAF, ModSecurity, F5, Imperva, Barracuda, and 45+ more. |
| **Payload Mutation Engine** | 10 technique families: case variation, encoding (URL, Base64, Unicode, hex, mixed), comment injection, parameter pollution, null byte injection, whitespace obfuscation, unicode normalization, double encoding, chunked encoding, and format-based mutation. |

---

## Feature Matrix

| Area | Coverage |
|---|---|
| **Web Security** | LFI, RFI, SQLi, NoSQLi, XSS (reflected, stored, DOM), SSTI, SSRF, XXE, Command Injection, Path Traversal, Deserialization, Open Redirect, LDAP Injection, XPath Injection, Header Injection, CRLF Injection, Server-Side Include |
| **API Security** | REST API fuzzing (path, parameter, body), GraphQL introspection, WebSocket message analysis, gRPC service inspection, OpenAPI/Swagger validation, API version detection, rate limit testing |
| **Cloud Security** | Secrets detection (AWS keys, GCP service accounts, Azure shared keys, generic API tokens), Cloud Metadata Service abuse (IMDSv1/v2), S3 bucket enumeration, Azure Blob discovery, GCP Storage bucket inspection, Kubernetes API assessment, Docker daemon analysis, CI/CD secrets leakage |
| **Authentication** | Basic, Bearer token, Cookie Jar (session replay), Form Login (credential-based), JWT analysis (claims, signature, algorithm confusion), OAuth2 flow analysis, Session management assessment |
| **Network** | Port scanning, service fingerprinting, TLS analysis, SSL certificate validation, DNS enumeration, subdomain discovery |
| **Reporting** | JSON, Markdown, SARIF 2.1 (VS Code / GitHub CodeQL integration), HTML (standalone), visual attack graph (HTML + Graphviz), purple team detection rules, ZIP evidence packages with raw requests/responses |
| **Protocols** | HTTP/HTTPS, WebSocket (text and binary frames), GraphQL (queries, mutations, subscriptions), gRPC (unary and streaming), DNS (A, AAAA, MX, TXT, CNAME, NS) |
| **WAF Evasion** | 50+ WAF signatures with confidence scoring, auto-abort on detection, payload mutation engine with 10 technique families, configurable evasion levels |
| **Plugin System** | Detector plugins (respond to findings), reporter plugins (custom output), hook plugins (lifecycle hooks), agent plugins (custom agent behaviors), skill plugins (new security skills) |
| **Ops** | Docker multi-stage builds (slim and full images), GitHub Actions CI (3.11/3.12/3.13), pre-commit hooks for Ruff and pytest, Makefile for common operations |

---

## Architecture Overview

HunterX follows a layered architecture where each component has clear responsibilities and communicates through defined interfaces.

```
                    +---------------------------+
                    |    CLI / API / Docker      |
                    +-------------+-------------+
                                  |
                    +-------------+-------------+
                    | Orchestration Engine       |
                    | (Observe -> Hypothesize -> |
                    |  Probe -> Verify)          |
                    +--+--------+--------+------+
                       |        |        |
              +--------+  +----+----+  +--------+
              | Agents   | Reasoning |  Skills  |
              | Platform | Engine    | Registry |
              | 10 agents| 18 goals  | 41 skills|
              | Event/Msg| Planner   | Executor |
              | Bus      | Validator | Policy   |
              | Workflow | Consensus | Cache    |
              | Scheduler| Confidence| Telemetry|
              +----+-----+-----+----+-----+----+
                   |           |            |
              +----+-----+-----+----+-----+----+
              | Payload  | Knowledge | Threat   |
              | Intel    | Graph     | Modeling |
              | FTS5 idx | Neo4j-like| STRIDE   |
              | Mutation | Relations | Attack   |
              | Feedback | Paths     | Chains   |
              | Prov.    | Context   | Trust    |
              +----+-----+-----------+----------+
                   |
              +----+------+
              | AI Provider|
              | OpenAI     |
              | Ollama     |
              | Sessions   |
              | Config     |
              | Caching    |
              | Metrics    |
              +----+------+
                   |
              +----+------+
              | Reporter  |
              | JSON      |
              | Markdown  |
              | SARIF     |
              | HTML      |
              | Graph     |
              +-----------+
```

The platform is organized into these core subsystems:

| Subsystem | Responsibility |
|---|---|
| **Orchestration Engine** | Drives the 4-stage execution loop: Observe (collect context), Hypothesize (form hypotheses), Probe (execute tests), Verify (validate findings) |
| **Multi-Agent Platform** | 10 specialized agents communicate through concurrent event and message buses; supports DAG-based workflows with state persistence, checkpoint, and resume |
| **Reasoning Engine** | Accepts goals, creates plans, generates AI prompts, validates responses, and reaches consensus across multiple AI calls; supports 18 goal types |
| **Security Skills Framework** | Registry of 41 skills; executor with policy, caching, and telemetry; independent skill installation and version management |
| **Payload Intelligence** | SQLite with FTS5; 5-level execution policy; 10 mutation families; feedback loop for payload effectiveness tracking; provenance tracking |
| **Knowledge Graph** | Entity-relationship store for findings, targets, and contextual data; supports cross-scan correlation and path analysis |
| **AI Provider Layer** | Provider abstraction with session management, caching (SHA256 + TTL + LRU), metrics, middleware, retry (exponential backoff), and circuit breaker |
| **Reporter** | Multi-format output with evidence collection, attack graphs, and evidence packages |

---

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/nullc0d30/HunterX.git
cd HunterX

# Create and activate a virtual environment
python -m venv venv
source venv/bin/activate   # Linux/macOS
venv\Scripts\activate      # Windows

# Install dependencies
pip install -r requirements.txt

# Run the post-install setup
python setup.py

# Verify installation
python hunterx.py --help
```

### Docker

```bash
# Pull the latest image
docker pull nullc0d30/hunterx:latest

# Run a basic scan
docker run --rm -v $(pwd)/reports:/data nullc0d30/hunterx:latest \
    -u http://target.com -o /data

# Run with AI analysis
docker run --rm \
    -v $(pwd)/reports:/data \
    -e OPENAI_API_KEY=sk-... \
    nullc0d30/hunterx:latest \
    -u http://target.com --ai --ai-model gpt-4 -o /data

# API mode with persistent reports
docker run --rm -p 8443:8443 -v $(pwd)/reports:/data \
    nullc0d30/hunterx:latest api --port 8443
```

See [docs/Docker_Guide.md](docs/Docker_Guide.md) for detailed Docker configuration, including environment variables, volume mounts, security profiles, and production deployment.

### Configuration

HunterX reads configuration from `hunterx.yaml` by default. Key configuration sections:

- `ai.providers` — AI provider settings, API keys, model selection
- `ai.sessions` — Conversation management and persistence
- `scan.profiles` — Operator profiles (internal, bounty, gov)
- `scan.presets` — Scan presets (quick, full, stealth)
- `scan.stealth` — Stealth levels with timing and delay controls
- `payload.policy` — Execution safety policy (safe, balanced, aggressive, research, paranoid)
- `payload.mutation` — Mutation engine configuration
- `agents` — Agent registration and configuration
- `skills` — Skill policy, caching, and registry settings
- `report.format` — Output format configuration
- `api` — REST API server settings

Full configuration reference: [docs/CONFIGURATION.md](docs/CONFIGURATION.md)

---

## Quick Start

### Basic Scan

```bash
# Quick scan with default settings
python hunterx.py -u http://testphp.vulnweb.com --profile bounty

# Full scan with all skills enabled
python hunterx.py -u http://testphp.vulnweb.com --preset full -p payloads

# Stealth scan for production targets
python hunterx.py -u https://target.com --stealth high --threads 2
```

### Profiles & Presets

```bash
# Internal profile (comprehensive, all skills, default thread count)
python hunterx.py -u http://target.com --profile internal

# Bounty profile (balanced, bug-bounty-oriented skills)
python hunterx.py -u http://target.com --profile bounty

# Government profile (strict compliance, detailed reporting)
python hunterx.py -u http://target.com --profile gov

# Quick preset (common vectors only)
python hunterx.py -u http://target.com --preset quick

# Full preset (all skills and payloads)
python hunterx.py -u http://target.com --preset full

# Stealth preset (slow, low-noise)
python hunterx.py -u http://target.com --preset stealth
```

### Authentication Scanning

```bash
# Basic authentication
python hunterx.py -u http://target.com --auth basic --username admin --password secret

# Bearer token
python hunterx.py -u http://target.com --auth bearer --token eyJhbGciOiJIUzI1NiIs...

# Cookie-based session
python hunterx.py -u http://target.com --auth cookie --cookie-file cookies.json

# Form login
python hunterx.py -u http://target.com --auth form --username admin --password secret \
    --login-url http://target.com/login --username-field user --password-field pass

# JWT analysis
python hunterx.py -u http://target.com --auth jwt --token eyJhbGciOiJIUzI1NiIs...
```

### AI-Assisted Scanning

```bash
# AI analysis with local Ollama
python hunterx.py -u http://target.com --ai --ai-model llama3.2 --ai-provider ollama

# AI analysis with OpenAI
python hunterx.py -u http://target.com --ai --ai-model gpt-4 --ai-provider openai

# AI analysis with custom temperature and retry settings
python hunterx.py -u http://target.com --ai --ai-model gpt-4 \
    --ai-temperature 0.3 --ai-max-retries 3

# AI-powered reasoning goal
python hunterx.py reasoning create --goal "Assess authentication security" \
    --target http://target.com --ai
```

### Scanning Multiple Targets

```bash
# Targets file (one URL per line)
python hunterx.py -f targets.txt --profile bounty

# Targets file with dry run (logic check only, no requests)
python hunterx.py -f targets.txt --profile bounty --dry-run
```

### API Server Mode

```bash
# Start the API server on default port (8443)
python hunterx.py api

# Start on custom port with debug logging
python hunterx.py api --port 8080 --debug

# API server with AI provider pre-configured
python hunterx.py api --port 8443 --ai-provider openai --ai-model gpt-4
```

---

## CLI Reference

| Argument | Description | Default |
|---|---|---|
| `-u, --url` | Target URL | Required |
| `-f, --targets-file` | Multi-target file (one URL per line) | None |
| `-p, --payload-dir` | Payload directory path | `payloads/` |
| `-o, --output-dir` | Reports output directory | `reports/` |
| `-c, --config` | YAML configuration file | `hunterx.yaml` |
| `--profile` | Operator profile: `internal`, `bounty`, `gov` | `bounty` |
| `--preset` | Scan preset: `quick`, `full`, `stealth` | `full` |
| `--stealth` | Stealth level: `low`, `medium`, `high` | `low` |
| `--threads` | Concurrent thread count | `5` |
| `--timeout` | Request timeout in seconds | `30` |
| `--retries` | Request retry count | `3` |
| `--max-depth` | Maximum crawl depth | `3` |
| `--dry-run` | Logic verification only (no requests sent) | `false` |
| `--insecure` | Disable SSL certificate verification | `false` |
| `--proxy` | HTTP/HTTPS proxy URL | None |
| `--user-agent` | Custom User-Agent header | Random per request |
| `--headers` | Additional HTTP headers (JSON) | None |
| `--cookies` | Request cookies (JSON) | None |
| `--delay` | Delay between requests in seconds | `0.5` |
| `--random-delay` | Random delay jitter in seconds | `0.5` |
| `--ai` | Enable AI-assisted analysis | `false` |
| `--ai-model` | AI model name | `gpt-4` |
| `--ai-provider` | AI provider name | `openai` |
| `--ai-temperature` | AI temperature setting | `0.7` |
| `--ai-max-retries` | AI max retry attempts | `3` |
| `--ai-timeout` | AI request timeout | `60` |
| `--auth` | Authentication mode | `none` |
| `--token` | Bearer token or JWT | None |
| `--username` | Username for auth | None |
| `--password` | Password for auth | None |
| `--cookie-file` | Cookie file path | None |
| `--login-url` | Login form submission URL | None |
| `--username-field` | Username form field name | `username` |
| `--password-field` | Password form field name | `password` |
| `--verbose`, `-v` | Verbose logging | `false` |
| `--debug` | Debug logging | `false` |
| `--quiet` | Suppress output except results | `false` |

### Subcommands

```
python hunterx.py api [options]            Start the REST API server
python hunterx.py payload [command]        Payload Intelligence Platform commands
python hunterx.py agents [command]         Agent management commands
python hunterx.py workflow [command]       Workflow management commands
python hunterx.py reasoning [command]      Reasoning engine commands
python hunterx.py skills [command]         Security Skills Framework commands
python hunterx.py ai [command]             AI Provider management commands
```

---

## REST API Reference

The API server (started via `python hunterx.py api`) exposes 40+ endpoints organized into functional groups.

### Scan Endpoints

| Method | Path | Description |
|---|---|---|
| `POST` | `/scan` | Start an asynchronous scan job |
| `GET` | `/scan/{id}` | Poll scan status and results |
| `DELETE` | `/scan/{id}` | Cancel a running scan |
| `GET` | `/scan/{id}/status` | Get scan status only |
| `GET` | `/scans` | List all scan jobs (with filtering and pagination) |
| `POST` | `/scan/{id}/pause` | Pause a running scan |
| `POST` | `/scan/{id}/resume` | Resume a paused scan |

### AI Provider Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/ai/providers` | List configured AI providers |
| `POST` | `/ai/chat` | Send a chat completion request |
| `POST` | `/ai/chat/stream` | Stream a chat completion response |
| `GET` | `/ai/sessions` | List AI conversation sessions |
| `POST` | `/ai/sessions` | Create a new conversation session |
| `GET` | `/ai/sessions/{id}` | Get session history |
| `DELETE` | `/ai/sessions/{id}` | Clear session history |
| `GET` | `/ai/metrics` | Get AI provider usage metrics |
| `GET` | `/ai/models` | List available models for a provider |

### Agent & Reasoning Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/agents` | List registered agents |
| `GET` | `/agents/{id}` | Get agent details and status |
| `POST` | `/agents/{id}/start` | Start an agent |
| `POST` | `/agents/{id}/stop` | Stop an agent |
| `POST` | `/goals` | Create a new reasoning goal |
| `GET` | `/goals/{id}` | Get goal status and results |
| `GET` | `/workflows` | List defined workflows |
| `POST` | `/workflows` | Create a workflow |
| `POST` | `/workflows/{id}/execute` | Execute a workflow |
| `GET` | `/workflows/{id}/status` | Get workflow execution status |

### Skills Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/skills` | List all registered security skills |
| `GET` | `/skills/{id}` | Get skill details (parameters, metadata, MITRE mapping) |
| `GET` | `/skills/search` | Search skills by name, category, or MITRE technique |
| `POST` | `/skills/execute/{id}` | Execute a specific skill against a target |
| `POST` | `/skills/install` | Install a skill from a package or registry |
| `DELETE` | `/skills/{id}` | Uninstall a skill |
| `GET` | `/skills/categories` | List skill categories |
| `GET` | `/skills/mitre` | List skills mapped to MITRE ATT&CK techniques |

### Payload Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/payload/search` | Search indexed payloads with FTS5 |
| `GET` | `/payload/stats` | Get payload repository statistics |
| `POST` | `/payload/mutate` | Mutate a payload using specified techniques |
| `GET` | `/payload/techniques` | List available mutation techniques |
| `POST` | `/payload/feedback` | Submit feedback on payload effectiveness |

### System Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/health` | System health check |
| `GET` | `/config` | Get current configuration (sanitized) |
| `PUT` | `/config` | Update configuration at runtime |
| `GET` | `/config/schema` | Get configuration schema |
| `GET` | `/version` | Get platform version |

Full API reference including request/response schemas and examples: [docs/Reference_Guide.md](docs/Reference_Guide.md)

---

## Capabilities

### Reconnaissance & Fingerprinting

- **Technology Detection** — Framework, CMS, web server, and library identification from response headers, HTML patterns, and URL structures
- **HTTP Header Analysis** — Security header audit (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, etc.)
- **TLS Analysis** — Protocol version negotiation (TLS 1.0/1.1/1.2/1.3), cipher suite analysis, certificate chain validation, weak key detection
- **Cookie Analysis** — Secure flag, HttpOnly flag, SameSite attribute, expiration review, domain scope
- **DNS Intelligence** — Record enumeration (A, AAAA, MX, TXT, CNAME, NS, SOA), subdomain discovery via common patterns
- **WAF Fingerprinting** — 50+ WAF signatures with confidence scoring; supported WAFs include Cloudflare, AWS WAF, ModSecurity, F5 BIG-IP ASM, Imperva, Barracuda, Akamai, Sucuri, StackPath, Fortinet, Radware, and 40+ more
- **WAF Auto-Abort** — Automatic scan abort when WAF detection confidence exceeds threshold (configurable per profile)
- **Fingerprint Correlation** — Cross-referencing technology fingerprints against known vulnerabilities via CVE database
- **Response Analysis** — Status code analysis, response time profiling, content length analysis, error page fingerprinting

### Web Security Analysis

- **LFI (Local File Inclusion)** — Path traversal payloads, null byte injection, PHP wrapper testing, log file inclusion, /proc/self/environ testing
- **RFI (Remote File Inclusion)** — Remote URL inclusion, data URL injection, allow_url_include bypass
- **SQL Injection** — Error-based, boolean-based blind, time-based blind, UNION-based, stacked queries, out-of-band (DNS/HTTP exfiltration), second-order injection
- **NoSQL Injection** — MongoDB operator injection ($ne, $gt, $regex, $where), JSON parameter tampering, REST API parameter pollution
- **XSS (Cross-Site Scripting)** — Reflected (GET/POST/headers), stored (database/file), DOM-based (client-side sinks), polyglot payloads, CSP bypass techniques, mXSS
- **SSTI (Server-Side Template Injection)** — Jinja2, Twig, Freemarker, Velocity, Jade/Pug, ERB, Mako detection and exploitation
- **SSRF (Server-Side Request Forgery)** — Internal IP range scanning, cloud metadata access, port scanning via SSRF, protocol smuggling (file://, gopher://, dict://)
- **XXE (XML External Entity)** — In-band XXE, blind XXE (out-of-band), parameter entities, XInclude attacks, SVG upload XXE
- **Command Injection** — OS command injection (Linux/Windows), blind command injection (time-based/out-of-band), pipeline injection, argument injection
- **Path Traversal** — Directory traversal, file inclusion, file read, file write (via path traversal)
- **Deserialization** — PHP deserialization, Python pickle, Java deserialization, Ruby MARSHAL detection
- **Open Redirect** — URL redirect testing, protocol-based redirects, javascript: URI redirects, double-encoded redirects
- **LDAP Injection** — Filter injection, blind LDAP injection, attribute value injection
- **XPath Injection** — XPath query injection, blind XPath injection, boolean-based extraction
- **Header Injection** — CRLF injection, host header injection, X-Forwarded-For spoofing, content-type manipulation
- **SSI (Server-Side Include)** — SSI directive injection, command execution via SSI
- **CORS Analysis** — Origin reflection testing, wildcard origin detection, pre-flight analysis, credentials exposure
- **CSP Analysis** — Policy parsing, weakness detection, missing directives, unsafe-inline/unsafe-eval detection
- **CSRF Detection** — Missing anti-CSRF tokens, token validation bypass, SameSite cookie bypass
- **Clickjacking** — X-Frame-Options missing/incorrect, CSP frame-ancestors analysis, framebusting script detection

### API Security Analysis

- **REST API Fuzzing** — Path fuzzing (endpoint discovery), parameter fuzzing (names and values), body fuzzing (JSON/XML/content-type), HTTP method fuzzing
- **GraphQL Introspection** — Schema extraction via introspection query, query depth analysis, batching attack testing, field suggestion brute-force
- **WebSocket Analysis** — Connection upgrade testing, message injection, origin validation, proxy through WebSocket
- **gRPC Inspection** — Service reflection detection, message interception, unary and streaming RPC testing
- **OpenAPI/Swagger Validation** — Endpoint verification from OpenAPI spec, parameter validation, response schema validation
- **API Version Detection** — Endpoint convention analysis (v1, v2, /api/, /rest/, etc.), version header fingerprinting
- **Rate Limit Testing** — Burst detection, rate limit threshold identification, rate limit bypass (IP rotation, header manipulation)
- **API Authentication Testing** — API key exposure, token scope analysis, OAuth2 flow validation

### Cloud Security Analysis

- **Secrets Detection** — AWS Access Key / Secret Key pattern matching, GCP service account key detection, Azure shared key detection, generic API tokens and bearer tokens, private key detection (RSA, EC, DSA, Ed25519), connection string detection
- **Cloud Metadata Service** — IMDSv1 (no token required) probe, IMDSv2 (PUT token) probe, instance metadata enumeration, IAM role credential extraction
- **S3 Bucket Enumeration** — Public bucket detection, bucket listing, object enumeration, bucket policy analysis, bucket ACL review
- **Azure Blob Discovery** — Storage account enumeration, container discovery, public access detection, blob listing
- **GCP Storage Buckets** — GCS bucket discovery, uniform/bucket-level ACL detection, object listing permissions
- **Kubernetes Assessment** — API server exposure detection, unauthenticated API access, pod listing, secrets enumeration, RBAC analysis
- **Docker Daemon Analysis** — Docker socket exposure, unauthenticated API access, container listing, image enumeration
- **CI/CD Secrets Leakage** — Jenkins credentials, Travis CI tokens, CircleCI tokens, GitLab CI tokens, GitHub Actions secrets, npm/gem/pip publish credentials

### Authentication & Authorization

- **Basic Authentication** — Credential brute-force (with lockout awareness), credential stuffing detection
- **Bearer Token Analysis** — Token decoding (JWT, opaque), token revocation testing, token scope verification
- **Cookie-Based Sessions** — Cookie replay, session fixation testing, cookie attribute analysis
- **Form Login Testing** — Credential brute-force, username enumeration, lockout policy detection, MFA bypass testing
- **JWT Analysis** — Algorithm confusion attack (RS256 -> HS256), no-algorithm attack, token expiration enforcement, signature verification bypass, claim tampering, JWK injection
- **OAuth2 Flow Analysis** — Authorization code flow testing, implicit flow testing, redirect URI validation, state parameter validation, token leakage detection
- **Session Management** — Session ID entropy analysis, session fixation, concurrent session handling, session timeout enforcement

### Exploitation & Verification

- **File Upload Testing** — Content-Type bypass, extension bypass, magic byte manipulation, filename injection, size limit testing
- **Directory Enumeration** — Common directory brute-force, file extension discovery, backup file detection (.bak, .old, .swp)
- **Fingerprint-Based Verification** — CVE lookup from fingerprint, version-specific vulnerability matching, known-exploit verification
- **Logic Verification** — Business logic tests, workflow bypass, privilege escalation testing, IDOR (Insecure Direct Object Reference)

### Target Profiling

- **Response Analysis** — Status code pattern analysis, response time profiling, content-length distribution, error page fingerprinting
- **Technology Stack Detection** — Server header, X-Powered-By, generator meta tag, URL structure patterns, cookie naming conventions
- **Entry Point Discovery** — Form field identification, URL parameter discovery, header-based entry points, file upload endpoints
- **Attack Surface Mapping** — Open ports, exposed services, admin panels, API endpoints, debug endpoints, configuration files

---

## Security Skills Framework

The Security Skills Framework is the plugin system that powers HunterX's scanning capabilities. It includes 41 built-in skills organized into categories:

| Category | Skills |
|---|---|
| **Web** | LFI, RFI, SQLi, NoSQLi, XSS, SSTI, SSRF, XXE, Command Injection, Path Traversal, Deserialization, Open Redirect, Header Injection, LDAP Injection, XPath Injection, SSI |
| **API** | REST Fuzzing, GraphQL, WebSocket, gRPC, OpenAPI Validation |
| **Cloud** | Secrets Detection, Cloud Metadata, S3 Enumeration, Azure Blob, GCP Storage, Kubernetes, Docker |
| **Network** | Port Scanning, Service Fingerprinting, DNS Enumeration, Subdomain Discovery, TLS Analysis |
| **Authentication** | Basic Auth, Bearer Token, Cookie Session, Form Login, JWT Analysis, OAuth Analysis |
| **Utility** | Directory Enumeration, Technology Detection, WAF Detection, File Upload Testing |

Each skill carries:
- **Metadata** — Name, version, description, author, license
- **MITRE ATT&CK Mapping** — Technique ID, name, tactic (e.g., T1190: Exploit Public-Facing Application)
- **OWASP Mapping** — Category (e.g., A1: Injection)
- **CWE Mapping** — CWE ID and description (e.g., CWE-89: SQL Injection)
- **CAPEC Mapping** — CAPEC ID and description (e.g., CAPEC-66: SQL Injection)

Full framework documentation: [docs/SECURITY_SKILLS_FRAMEWORK.md](docs/SECURITY_SKILLS_FRAMEWORK.md)
Skill SDK for custom skills: [docs/SKILL_SDK.md](docs/SKILL_SDK.md)
Plugin development guide: [docs/PLUGIN_DEVELOPMENT.md](docs/PLUGIN_DEVELOPMENT.md)

---

## Reasoning Engine

The Reasoning Engine is the part of HunterX that plans, prompts, validates, and reaches consensus when goals require AI. It accepts goals (structured tasks), creates execution plans, generates AI prompts, sends them through the provider layer, validates responses, and assembles results with confidence scores and decision traces.

### Goal Types (18 supported)

The engine supports 18 distinct goal types, each with specialized planning and validation:

| Goal Type | Purpose |
|---|---|
| `vulnerability_detection` | Identify potential vulnerabilities from scan data |
| `risk_assessment` | Assess risk level and business impact |
| `exploit_verification` | Verify exploitability of identified vulnerabilities |
| `remediation_planning` | Generate remediation recommendations |
| `priority_scoring` | Score and prioritize findings |
| `pattern_discovery` | Discover patterns across multiple findings |
| `anomaly_detection` | Detect anomalous behavior or responses |
| `false_positive_analysis` | Analyze findings for false positive classification |
| `attack_path_analysis` | Analyze potential attack paths through the system |
| `threat_assessment` | Assess threat actor capabilities and intent |
| `compliance_check` | Check findings against compliance requirements |
| `mitre_mapping` | Map findings to MITRE ATT&CK framework |
| `countermeasure_suggestion` | Suggest security countermeasures |
| `vulnerability_correlation` | Correlate vulnerabilities across targets |
| `impact_analysis` | Analyze business and technical impact |
| `root_cause_analysis` | Determine root cause of vulnerabilities |
| `security_recommendation` | Generate actionable security recommendations |
| `chain_analysis` | Analyze attack chains and kill chain progression |

### Execution Pipeline

```
Goal -> Planner -> Prompt Builder -> AI Provider -> Validator -> Consensus -> Result
```

1. **Planner** — Decomposes a goal into execution steps based on goal type
2. **Prompt Builder** — Constructs structured prompts with context, findings, and instructions; supports system, user, and assistant roles; context window management with token-aware truncation
3. **AI Provider** — Routes through the provider layer with session management, caching, and retry
4. **Validator** — Validates responses against schema, confidence thresholds, and consistency checks
5. **Consensus** — Reaches consensus across multiple AI calls (when configured); supports majority, weighted, and unanimous consensus modes
6. **Result** — Returns structured output with confidence score, evidence, decision trace, and provider metadata

Full reasoning engine documentation: [docs/REASONING_ENGINE.md](docs/REASONING_ENGINE.md)

---

## Multi-Agent Architecture

HunterX uses 10 specialized agents that communicate through concurrent event and message buses. Agents can be started, stopped, and configured independently.

### Agent Types

| Agent | Responsibility |
|---|---|
| **Scan Agent** | Executes target scanning and coordinates test execution |
| **Analysis Agent** | Analyzes raw findings and produces structured results |
| **Risk Agent** | Performs risk assessment and priority scoring |
| **Exploit Agent** | Verifies exploitability of identified vulnerabilities |
| **Report Agent** | Formats and assembles reports |
| **Monitor Agent** | Monitors scan progress, detects anomalies, manages lifecycle |
| **Discover Agent** | Performs reconnaissance and entry point discovery |
| **Fingerprint Agent** | Fingerprints technologies, WAFs, and services |
| **Correlation Agent** | Correlates findings across targets and vectors |
| **Threat Agent** | Maps findings to threat models and attack chains |

### Communication Architecture

- **Event Bus** — Concurrent, topic-based pub/sub for real-time events (finding detected, scan completed, agent started/stopped, threshold reached)
- **Message Bus** — Point-to-point messaging between agents using priority queues
- **Workflow DAG** — Directed Acyclic Graph execution with state persistence, checkpoint, and resume
- **Agent Scheduler** — Configurable scheduling with dependency resolution, retry, and timeout

Full agent documentation: [docs/AGENTS.md](docs/AGENTS.md)

---

## Payload Intelligence

The Payload Intelligence subsystem manages payloads throughout their lifecycle — from storage and indexing through mutation, execution, and feedback.

### Key Features

| Feature | Description |
|---|---|
| **SQLite + FTS5** | Payloads indexed with full-text search; supports prefix, phrase, and wildcard queries |
| **5-Level Safety Policy** | `safe` — no destructive payloads, `balanced` — limited probing, `aggressive` — full set, `research` — experimental payloads, `paranoid` — minimal probing |
| **Mutation Engine** | 10 technique families for dynamic payload generation: case variation, URL encoding, Base64 encoding, Unicode normalization, comment injection, parameter pollution, null byte injection, whitespace obfuscation, double encoding, chunked encoding; techniques combinable in sequences |
| **Provenance Tracking** | Every payload has a chain of origin — source, mutation lineage, and execution history |
| **Feedback Loop** | Payload effectiveness tracking via user feedback (success/failure/partial); effectiveness scores influence payload selection |
| **Payload Graph** | Relationships between payloads (variant, supersedes, depends-on, mitigates, bypasses) stored in the knowledge graph |
| **Context-Aware Selection** | Payload selection considers target technology, WAF presence, response patterns, and past effectiveness |

### Payload Commands

```bash
# View payload repository statistics
python hunterx.py payload stats

# Search payloads
python hunterx.py payload search --query "sql injection" --limit 20

# Mutate a payload
python hunterx.py payload mutate --payload "<script>alert(1)</script>" \
    --techniques "url_encode,unicode" --count 10

# Submit feedback on payload effectiveness
python hunterx.py payload feedback --payload-id 42 --result success
```

---

## AI Provider Abstraction

HunterX provides an abstraction layer that decouples the reasoning engine and agents from specific AI providers.

### Supported Providers

| Provider | Models | Features |
|---|---|---|
| **OpenAI** | GPT-4, GPT-4o, GPT-4o-mini, GPT-3.5-turbo | Full support with streaming, function calling, system prompts |
| **Ollama** | llama3.2, mixtral, gemma2, phi3, qwen2.5, codegemma, nomic-embed-text, + any local model | Bring your own model, no API key needed, local inference |

### Provider Features

- **Session Management** — Create, list, get, delete conversation sessions; session persistence
- **Response Caching** — SHA256-based request hashing, TTL-based expiration, LRU eviction, skip-cache support
- **Metrics** — Per-provider and per-model request count, token usage, latency, cost estimation (OpenAI), error rates
- **Middleware Pipeline** — Logging, rate limiting, safety filtering, request/response transformation
- **Retry Handling** — Exponential backoff with configurable max retries, jitter, provider-specific error classification
- **Circuit Breaker** — Configurable failure thresholds, half-open recovery, provider isolation
- **Extensible Provider Interface** — Add new providers by implementing the ProviderInterface; hot-reloadable provider configuration

Full AI provider documentation: [docs/AI_PROVIDER_GUIDE.md](docs/AI_PROVIDER_GUIDE.md)

---

## Knowledge Graph

The Knowledge Graph provides graph-based storage for security data, enabling relationship-aware analysis across scan targets and findings.

### Entity Types

| Entity | Description |
|---|---|
| **Target** | A scanned entity (web application, API, server, cloud service) |
| **Finding** | A discovered vulnerability or security observation |
| **Payload** | A payload used during testing |
| **AttackPath** | An inferred or defined path from entry point to target |
| **ThreatActor** | A threat actor profile for threat modeling |
| **TrustBoundary** | A trust boundary in the system architecture |
| **DataFlow** | A data flow between components |

### Relationship Types

| Relationship | Description |
|---|---|
| `HAS_FINDING` | Target to Finding |
| `USES_PAYLOAD` | Finding to Payload |
| `EXPLOITS` | AttackPath to Vulnerability |
| `CROSSES_BOUNDARY` | AttackPath to TrustBoundary |
| `ASSOCIATED_WITH` | Finding to ThreatActor |
| `MITIGATES` | Countermeasure to Vulnerability |
| `DEPENDS_ON` | Dependencies between entities |
| `CORRELATED_WITH` | Correlation between findings |

---

## Threat Modeling & Attack Chains

HunterX supports threat modeling and attack chain decomposition as part of its analysis pipeline.

### Threat Modeling

- **STRIDE Categorization** — Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege
- **LINDDUN Categorization** — Linking, Identifying, Non-repudiation, Detection, Data Disclosure, Unawareness, Non-compliance
- **Trust Boundary Mapping** — Automatic detection of trust boundaries from architecture and scan data
- **Threat Scenario Generation** — Automated generation of threat scenarios from findings and context

### Attack Chains

- **Chain Decomposition** — Break down attacks into individual steps with preconditions and postconditions
- **Automated Chain Inference** — Infer possible attack chains from findings and knowledge graph relationships
- **Kill Chain Mapping** — Map steps to Lockheed Martin Cyber Kill Chain phases: Reconnaissance, Weaponization, Delivery, Exploitation, Installation, Command & Control, Actions on Objectives
- **Chain Visualization** — Visual attack chain graphs in HTML reports

---

## Reporting

HunterX produces reports in multiple formats suitable for different audiences:

### Format Comparison

| Format | Use Case | Content |
|---|---|---|
| **JSON** | Programmatic consumption, CI/CD integration, further analysis | Full structured data with all fields, raw requests/responses, metadata |
| **Markdown** | Quick human review, documentation, email | Summary, findings list with severity, recommendations |
| **SARIF 2.1** | IDE integration (VS Code, GitHub CodeQL), CI/CD pipelines | SARIF-compliant with rules, results, locations, code flows |
| **HTML** | Interactive review, stakeholder presentation | Standalone HTML with navigation, filtering, search, severity coloring |
| **Attack Graph (HTML)** | Visual analysis of attack paths | HTML with embedded Graphviz, interactive graph, path highlighting |
| **Purple Team Rules** | Detection rule generation from findings | YARA/Sigma-compatible detection rules for purple team exercises |
| **ZIP Evidence** | Complete evidence package for audit or legal | Raw requests/responses, scanning metadata, configuration, timestamp evidence |

### Report Commands

```bash
# Generate specific report format
python hunterx.py -u http://target.com --report-format json
python hunterx.py -u http://target.com --report-format sarif
python hunterx.py -u http://target.com --report-format html

# Generate all report formats
python hunterx.py -u http://target.com --report-format all

# Output to custom directory
python hunterx.py -u http://target.com -o /custom/report/path
```

---

## Safety & Security

HunterX implements multiple layers of protection to ensure safe operation:

### Destructive Payload Blocklist

A hard-coded, non-bypassable blocklist in `core/utils/safety.py` catches destructive payloads before any request is sent:

- File destruction commands (`rm -rf`, `del /f`, `format`, `mkfs`)
- Reverse shell payloads (`bash -i`, `nc -e`, `powershell -enc`)
- Fork bombs (`:(){:|:&};:`, `%0|%0`)
- Database write operations (`DROP TABLE`, `TRUNCATE`, `DELETE FROM`, `UPDATE`)
- System modification commands (`shutdown`, `reboot`, `init 0`, `poweroff`)
- Credential exfiltration attempts

### Safety Policy Levels

Applied independently at the reasoning, skill, and payload execution layers:

| Level | Description |
|---|---|
| **Safe** | Read-only testing; no modification payloads; no authentication bypass |
| **Balanced** | Limited probing; read-heavy with minimal write testing to non-production endpoints |
| **Aggressive** | Full testing including authentication bypass; no destructive payloads |
| **Research** | Experimental payloads enabled; sandboxed execution recommended |
| **Paranoid** | Minimal probing; extensive pre-scan verification; conservative timing |

### Additional Protections

| Protection | Description |
|---|---|
| **SSL Verification** | Enabled by default for all outbound HTTPS connections |
| **Rate Limiting** | Token-bucket algorithm with configurable max requests per second |
| **Request Timeout** | Configurable per-request timeout (default: 30s) |
| **Auto-Abort** | Automatic scan abort when WAF detection confidence exceeds threshold |
| **Thread Safety** | All shared state synchronized with threading locks |
| **Input Validation** | URL, path, and parameter validation before processing |
| **Secure Configuration** | No hard-coded credentials; API keys from environment or config file |

---

## Contributing

HunterX is Apache 2.0 licensed and welcomes contributions of all forms — bug fixes, new features, documentation improvements, skill development, translation, and testing.

### Code of Conduct

This project follows a [Code of Conduct](CODE_OF_CONDUCT.md) to foster an inclusive and respectful community.

### Quick Start for Contributors

```bash
# Fork the repository
git clone https://github.com/YOUR_USERNAME/HunterX.git
cd HunterX

# Create a virtual environment
python -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Create a feature branch
git checkout -b feat/your-feature-name

# Make changes and run tests
pytest tests/ -v
ruff check core/ tests/

# Commit with DCO sign-off
git commit -s -m "feat(area): concise description of changes"

# Push and open a pull request
git push origin feat/your-feature-name
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full contribution guide, including:

- Code style requirements (Ruff, naming conventions, documentation)
- Pull request process and review guidelines
- Commit message conventions and DCO sign-off requirements
- Testing requirements and coverage expectations
- Issue reporting templates

### Development Setup

```bash
# Install pre-commit hooks
pre-commit install

# Run tests with coverage
pytest tests/ -v --cov=core/

# Verify all Ruff checks pass
ruff check core/ tests/ --no-fix

# Build documentation locally
mkdocs build
```

---

## Project Roadmap

HunterX v6.0.0 is feature-complete with 41 skills, 10 agents, 18 goal types, and 40+ API endpoints. Future development focuses on ecosystem and community growth:

### Short-Term (v6.x)

- **Community Skill Repository** — Public registry for community-contributed skills with versioning and dependency management
- **Additional AI Providers** — Anthropic Claude, Google Gemini, AWS Bedrock, local transformers models
- **Provider Failover** — Automatic failover between providers with health checking
- **A/B Model Comparison** — Compare results from different AI providers on the same goal

### Medium-Term (v7.x)

- **CI/CD Pipeline Plugins** — Native GitHub Actions, GitLab CI, Jenkins, Azure DevOps integrations
- **SIEM Connectors** — Splunk, Elasticsearch, QRadar, Sentinel output connectors
- **Ticketing Integration** — Jira, ServiceNow, PagerDuty finding submission
- **Collaborative Scanning** — Multi-user scan coordination with shared state

### Long-Term

- **Public Skill Marketplace** — Verified and community skills with ratings, reviews, and analytics
- **Community Detection Rules** — User-contributed WAF and detection rules
- **Interactive Tutorials** — In-app guided tutorials for new users
- **Video Walkthroughs** — Official video guides for common workflows
- **Enterprise Features** — Role-based access control, audit logging, compliance reporting, SSO

Full roadmap: [docs/ROADMAP.md](docs/ROADMAP.md)

---

## Documentation Hub

| Guide | Description | File |
|---|---|---|
| **Architecture** | System architecture, component responsibilities, execution flows | [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) |
| **CLI & API Reference** | Complete CLI arguments and REST API endpoint reference | [docs/Reference_Guide.md](docs/Reference_Guide.md) |
| **Security Skills Framework** | 41 skills, registry, executor, marketplace, policy management | [docs/SECURITY_SKILLS_FRAMEWORK.md](docs/SECURITY_SKILLS_FRAMEWORK.md) |
| **Reasoning Engine** | Goal types, planner, prompt builder, validator, consensus, confidence | [docs/REASONING_ENGINE.md](docs/REASONING_ENGINE.md) |
| **Multi-Agent Platform** | 10 agents, event/message buses, workflows, scheduling | [docs/AGENTS.md](docs/AGENTS.md) |
| **AI Provider Guide** | Provider abstraction, OpenAI, Ollama, adding providers, caching, metrics | [docs/AI_PROVIDER_GUIDE.md](docs/AI_PROVIDER_GUIDE.md) |
| **Skill SDK** | Creating custom security skills with the SDK | [docs/SKILL_SDK.md](docs/SKILL_SDK.md) |
| **Plugin Development** | Detector, reporter, hook, and agent plugin development | [docs/PLUGIN_DEVELOPMENT.md](docs/PLUGIN_DEVELOPMENT.md) |
| **Configuration** | Full YAML reference, environment variables, policy levels | [docs/CONFIGURATION.md](docs/CONFIGURATION.md) |
| **Docker Guide** | Container deployment, volumes, environment variables, security | [docs/Docker_Guide.md](docs/Docker_Guide.md) |
| **Performance Guide** | Caching strategies, concurrency tuning, benchmark estimates | [docs/Performance_Guide.md](docs/Performance_Guide.md) |
| **Support Guide** | FAQ, common issues, troubleshooting steps | [docs/SUPPORT.md](docs/SUPPORT.md) |
| **Design Decisions** | Technical architecture decisions and trade-offs | [docs/Design_Decisions.md](docs/Design_Decisions.md) |
| **Governance** | Project governance, maintainer roles, decision-making | [docs/GOVERNANCE.md](docs/GOVERNANCE.md) |
| **About the Author** | Author biography, background, and community involvement | [docs/about-author.md](docs/about-author.md) |

### Root Documentation

| File | Description |
|---|---|
| [CHANGELOG.md](CHANGELOG.md) | Complete version history and changes |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Contribution guidelines and PR process |
| [SECURITY.md](SECURITY.md) | Vulnerability disclosure and security policy |
| [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) | Community code of conduct |
| [RELEASE_NOTES_v6.0.0.md](RELEASE_NOTES_v6.0.0.md) | v6.0.0 release notes and migration guide |

### Tutorials

| Tutorial | Description |
|---|---|
| [Basic Scanning](docs/_tutorials/01-basic-scanning.md) | First scan with HunterX |
| [Authenticated Scanning](docs/_tutorials/02-authenticated-scanning.md) | Scanning behind authentication |
| [API Server Usage](docs/_tutorials/03-api-server-usage.md) | Using the REST API server |

---

## About the Author

**Ahmed Awad** (known online as **NullC0d3**) is a Cybersecurity Threat Intelligence Analyst, open-source developer, and security researcher. He is the creator of HunterX, the AnubisX Framework, and RabbitHole. Ahmed has been active in the security community since 2018, with experience spanning Red Team operations, vulnerability research, bug bounty hunting (HackerOne, Bugcrowd, Intigriti), and open-source security tool development.

His work focuses on AI-assisted security assessment, threat intelligence automation, and building accessible security tools for the open-source community. He is passionate about bridging the gap between AI research and practical security testing, and believes that well-designed open-source tools can level the playing field for security professionals at all levels.

- **GitHub**: [github.com/nullc0d30](https://github.com/nullc0d30)
- **Docker Hub**: [hub.docker.com/u/nullc0d30](https://hub.docker.com/u/nullc0d30)
- **Medium**: Technical articles on vulnerability assessment, AI-assisted security testing, and Red Teaming methodologies
- **Bug Bounty Platforms**: HackerOne, Bugcrowd, Intigriti

Full biography: [docs/about-author.md](docs/about-author.md)

---

## Citation

If you use HunterX in academic research, please cite:

```bibtex
@software{HunterX,
  author = {Ahmed Awad},
  title = {HunterX: AI-Assisted Vulnerability Hunter},
  year = {2026},
  version = {6.0.0},
  license = {Apache-2.0},
  doi = {10.6084/m9.figshare.33102290},
  url = {https://github.com/nullc0d30/HunterX}
}
```

DOI: [10.6084/m9.figshare.33102290](https://doi.org/10.6084/m9.figshare.33102290)

For the full citation metadata, see [CITATION.cff](CITATION.cff).

---

## Responsible Use & Legal Notice

HunterX is provided exclusively for authorized security testing activities, including:

- Professional penetration testing conducted with written authorization
- Defensive security research and vulnerability assessment
- Red team exercises performed with explicit written permission
- Bug bounty program participation where testing is explicitly authorized
- Educational purposes in controlled, authorized environments

Users are solely responsible for ensuring they have obtained **explicit written authorization** from the owner of any target system before scanning, testing, probing, or assessing it. Unauthorized access, scanning, exploitation, or testing of computer systems may violate applicable local, national, and international laws, including but not limited to the Computer Fraud and Abuse Act (CFAA) in the United States, the Computer Misuse Act in the United Kingdom, and equivalent legislation in other jurisdictions.

**This software is provided "AS IS" under the Apache 2.0 License, without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose, and noninfringement.** The author, contributors, and maintainers are not responsible for any misuse, unauthorized activities, damages, data loss, service disruption, legal consequences, financial penalties, or violations of law resulting from the installation, use, or modification of HunterX.

By using HunterX, you acknowledge that:
1. You understand the legal implications of security testing
2. You have obtained proper authorization for your testing activities
3. You will comply with all applicable laws and regulations
4. You accept full responsibility for your actions while using this software
5. You will not use HunterX for any illegal or unauthorized purpose

If you discover a security vulnerability in HunterX itself, please report it via [GitHub Private Vulnerability Reporting](https://github.com/nullc0d30/HunterX/security/advisories/new). See [SECURITY.md](SECURITY.md) for the full disclosure policy and response timeline.

---

## License

HunterX is licensed under the [Apache License, Version 2.0](LICENSE).

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

## Acknowledgements

HunterX builds on the work of the broader security and open-source community. In particular:

- **OWASP** — For security testing methodologies, the Top 10 classification, and industry reference standards
- **PayloadsAllTheThings** — For the comprehensive payload collection used as an external reference source
- **MITRE ATT&CK** — For the adversary tactics and techniques framework that underpins HunterX's skill and finding mapping
- **FastAPI** — For the high-performance REST API framework
- **Ruff** — For lightning-fast Python linting and formatting
- **Pytest** — For the testing framework
- **The Python Community** — For robust, well-maintained libraries that make projects like this possible
- **The Security Research Community** — For continuous vulnerability discovery, disclosure, and knowledge sharing

---

## Community

- **Star** the repository on [GitHub](https://github.com/nullc0d30/HunterX)
- **Report bugs** via [GitHub Issues](https://github.com/nullc0d30/HunterX/issues)
- **Ask questions** and share ideas in [GitHub Discussions](https://github.com/nullc0d30/HunterX/discussions)
- **Contribute** — Submit pull requests, create skills, write documentation, report bugs, suggest features
- **Fork** the project to experiment, customize, or build on top of it
- **Share** — Tell others about HunterX if you find it useful

---

<div align="center">

**HunterX** — *Observe. Hypothesize. Probe. Verify.*

[GitHub](https://github.com/nullc0d30/HunterX) •
[Docker Hub](https://hub.docker.com/u/nullc0d30) •
[Issues](https://github.com/nullc0d30/HunterX/issues) •
[Discussions](https://github.com/nullc0d30/HunterX/discussions)

</div>
