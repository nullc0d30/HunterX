---
layout: default
title: Features & Architecture — HunterX v6.0.0
keywords: Security Skills Framework, Reasoning Engine, Multi-Agent Platform, offensive security
description: >-
  Complete feature breakdown of HunterX v6.0.0 open-source offensive security
  framework: Security Skills Framework (41 skills), Reasoning Engine (18 goals),
  Multi-Agent Platform (10 agents), AI Provider Layer, Knowledge Graph, Threat
  Modeling, Payload Intelligence, and MITRE ATT&CK mapping for offensive
  security, penetration testing, and bug bounty hunting.
---

## Features & Architecture

HunterX is an open-source AI-assisted vulnerability scanner and security assessment platform designed for professional Red Teams, bug bounty hunters, security researchers, and enterprise security teams.

---

## Architecture Overview

HunterX follows a layered architecture organized into core subsystems.

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
              +----+-----+-----+----+-----+----+
                   |           |            |
              +----+-----+-----+----+-----+----+
              | Payload  | Knowledge | Threat   |
              | Intel    | Graph     | Modeling |
              | FTS5 idx | Relations | STRIDE   |
              | Mutation | Paths     | Chains   |
              | Feedback | Context   | Trust    |
              +----+-----+-----------+----------+
                   |
              +----+------+
              | AI Provider|
              | OpenAI     |
              | Ollama     |
              | Sessions   |
              | Caching    |
              | Metrics    |
              +----+------+
                   |
              +----+------+
              | Reporter  |
              | JSON / MD |
              | SARIF /   |
              | HTML      |
              +-----------+
```

| Subsystem | Responsibility |
|---|---|
| **Orchestration Engine** | Drives the 4-stage execution loop: Observe (collect context), Hypothesize (form hypotheses), Probe (execute tests), Verify (validate findings) |
| **Multi-Agent Platform** | 10 specialized agents communicating through concurrent event and message buses; DAG-based workflows with state persistence and checkpoint/resume |
| **Reasoning Engine** | Accepts goals, creates plans, generates AI prompts, validates responses, reaches consensus across multiple calls. 18 goal types supported |
| **Security Skills Framework** | Registry of 41 skills with executor, policy, caching, and telemetry. Independent skill installation and version management |
| **Payload Intelligence** | SQLite + FTS5 payload repository sourced from the community-maintained [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) knowledge base, with 5-level execution policy, 10 mutation technique families, provenance tracking, feedback loop |
| **Knowledge Graph** | Entity-relationship store for findings, targets, payloads, attack paths, and threat actors; supports cross-scan correlation |
| **AI Provider Layer** | Provider abstraction with session management, caching (SHA256 + TTL + LRU), metrics, middleware, retry, and circuit breaker |
| **Reporter** | Multi-format output: JSON, Markdown, SARIF 2.1, HTML, visual attack graphs, purple team detection rules, ZIP evidence packages |

---

## Security Skills Framework

41 built-in skills organized into categories, each carrying MITRE ATT&CK, OWASP, CWE, and CAPEC metadata.

| Category | Skills |
|---|---|
| **Web Security** | LFI, RFI, SQLi, NoSQLi, XSS, SSTI, SSRF, XXE, Command Injection, Path Traversal, Deserialization, Open Redirect, Header Injection, LDAP Injection, XPath Injection, SSI |
| **API Security** | REST Fuzzing, GraphQL Introspection, WebSocket Analysis, gRPC Inspection, OpenAPI Validation |
| **Cloud Security** | Secrets Detection, Cloud Metadata, S3 Enumeration, Azure Blob, GCP Storage, Kubernetes, Docker |
| **Network** | Port Scanning, Service Fingerprinting, DNS Enumeration, Subdomain Discovery, TLS Analysis |
| **Authentication** | Basic Auth, Bearer Token, Cookie Session, Form Login, JWT Analysis, OAuth Analysis |
| **Utility** | Directory Enumeration, Technology Detection, WAF Detection, File Upload Testing |

Each skill includes:
- Name, version, description, author, license metadata
- MITRE ATT&CK technique ID and tactic
- OWASP category and CWE/CAPEC mappings
- CVSS v3.1 base score where applicable

Full reference: [Security Skills Framework](/features/security-skills-framework/)

---

## Reasoning Engine

The Reasoning Engine accepts goals (structured tasks), creates execution plans, generates AI prompts, validates responses, and assembles results with confidence scores and decision traces.

### Supported Goal Types (18)

| Goal Type | Purpose |
|---|---|
| `vulnerability_detection` | Identify potential vulnerabilities from scan data |
| `risk_assessment` | Assess risk level and business impact |
| `exploit_verification` | Verify exploitability of identified vulnerabilities |
| `remediation_planning` | Generate remediation recommendations |
| `priority_scoring` | Score and prioritize findings |
| `pattern_discovery` | Discover patterns across multiple findings |
| `anomaly_detection` | Detect anomalous behavior or responses |
| `false_positive_analysis` | Classify findings as false positives |
| `attack_path_analysis` | Analyze potential attack paths |
| `threat_assessment` | Assess threat actor capabilities |
| `compliance_check` | Check findings against compliance requirements |
| `mitre_mapping` | Map findings to MITRE ATT&CK |
| `countermeasure_suggestion` | Suggest security countermeasures |
| `vulnerability_correlation` | Correlate vulnerabilities across targets |
| `impact_analysis` | Analyze business and technical impact |
| `root_cause_analysis` | Determine root cause of vulnerabilities |
| `security_recommendation` | Generate actionable recommendations |
| `chain_analysis` | Analyze attack chains and kill chain progression |

### Execution Pipeline

```
Goal -> Planner -> Prompt Builder -> AI Provider -> Validator -> Consensus -> Result
```

1. **Planner** — Decomposes a goal into execution steps
2. **Prompt Builder** — Constructs structured prompts with context window management
3. **AI Provider** — Routes through the provider layer with caching and retry
4. **Validator** — Validates responses against schema and confidence thresholds
5. **Consensus** — Reaches agreement across multiple AI calls (majority, weighted, unanimous)
6. **Result** — Returns structured output with confidence score, evidence, and decision trace

Full reference: [Reasoning Engine](/features/reasoning-engine/)

---

## Multi-Agent Platform

10 specialized agents communicate through concurrent event and message buses.

| Agent | Responsibility |
|---|---|
| **ReconAgent** | Reconnaissance, technology fingerprinting, WAF detection |
| **ThreatModelingAgent** | Threat modeling, attack surface analysis, trust boundary mapping |
| **PlanningAgent** | Scan planning, strategy selection, resource allocation |
| **PayloadAgent** | Payload selection, mutation, delivery optimization |
| **VerificationAgent** | Result verification, false positive analysis, confidence scoring |
| **RiskAgent** | Risk scoring, severity classification, priority assignment |
| **ReportingAgent** | Report generation, executive summaries, technical findings |
| **PurpleTeamAgent** | Purple team rule generation, detection gap analysis |
| **LearningAgent** | Adaptive learning, pattern recognition, knowledge accumulation |
| **CoordinatorAgent** | Inter-agent coordination, goal delegation, conflict resolution |

Full reference: [Multi-Agent Platform](/features/agents/)

---

## AI Provider Abstraction

HunterX decouples the reasoning engine and agents from specific AI providers.

| Provider | Models | Features |
|---|---|---|
| **OpenAI** | GPT-4, GPT-4o, GPT-4o-mini, GPT-3.5-turbo | Streaming, function calling, system prompts |
| **Ollama** | llama3.2, mixtral, gemma2, phi3, qwen2.5, + any local model | No API key, local inference |

Provider features include session management, response caching (SHA256 + TTL + LRU), per-provider metrics and cost estimation, middleware pipeline (logging, rate limiting, safety), exponential backoff retry, circuit breaker pattern, and extensible provider interface.

Full reference: [AI Provider Guide](/features/ai-provider-guide/)

---

## Payload Intelligence

SQLite-indexed payload repository sourced from the community-maintained [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) knowledge base, with FTS5 full-text search, 5-level execution policy, 10 mutation technique families (case variation, URL encoding, Base64, Unicode, comment injection, parameter pollution, null byte, whitespace, double encoding, chunked encoding), provenance tracking with mutation lineage (source repository, commit, release tag, checksum), feedback loop for effectiveness scoring, graph-based payload relationships, and context-aware selection based on target technology and WAF presence.

---

## Knowledge Graph

Graph-based storage for security entities and relationships:

| Entity Type | Description |
|---|---|
| **Target** | Scanned entity (web app, API, server, cloud service) |
| **Finding** | Discovered vulnerability or security observation |
| **Payload** | Payload used during testing |
| **AttackPath** | Inferred path from entry point to target |
| **ThreatActor** | Threat actor profile for threat modeling |
| **TrustBoundary** | Trust boundary in system architecture |
| **DataFlow** | Data flow between components |

Full reference: [Architecture](/features/architecture/)

---

## Threat Modeling & Attack Chains

Automated threat modeling with STRIDE and LINDDUN categorization, trust boundary mapping, automated threat scenario generation from findings, attack chain decomposition with preconditions and postconditions, kill chain mapping (Lockheed Martin Cyber Kill Chain), and visual attack chain graphs in HTML reports.

---

## REST API

FastAPI-based REST server with 40+ endpoints:

| Group | Endpoints | Purpose |
|---|---|---|
| **Scan** | `POST /scan`, `GET /scan/{id}`, `DELETE /scan/{id}`, `GET /scans`, `POST /scan/{id}/pause`, `POST /scan/{id}/resume` | Async scan job lifecycle |
| **AI** | `GET /ai/providers`, `POST /ai/chat`, `POST /ai/chat/stream`, sessions, metrics, models | AI provider management |
| **Agents** | `GET /agents`, `GET /agents/{id}`, `POST /agents/{id}/start`, `POST /agents/{id}/stop` | Agent lifecycle |
| **Skills** | `GET /skills`, `GET /skills/{id}`, `GET /skills/search`, `POST /skills/execute/{id}`, `POST /skills/install`, `DELETE /skills/{id}` | Skill management |
| **Payload** | `GET /payload/search`, `GET /payload/stats`, `POST /payload/mutate`, `GET /payload/techniques`, `POST /payload/feedback` | Payload operations |
| **Workflows** | `GET /workflows`, `POST /workflows`, `POST /workflows/{id}/execute`, `GET /workflows/{id}/status` | Workflow management |
| **Reasoning** | `POST /goals`, `GET /goals/{id}` | Goal management |
| **System** | `GET /health`, `GET /config`, `PUT /config`, `GET /config/schema`, `GET /version` | System management |

Full reference: [REST API](/api/)

---

## CLI Interface

```bash
# Scanning
hunterx scan http://target.com --profile bounty
hunterx scan http://target.com --preset full --threads 10
hunterx scan http://target.com --ai --ai-model llama3.2
hunterx scan target.com --profile gov --stealth high

# API Server
hunterx api --port 8443

# Subcommands
hunterx skills list
hunterx agents list
hunterx payload stats
hunterx reasoning inspect <goal_id>
hunterx workflow list
hunterx ai providers
```

Full reference: [CLI Reference](/cli/)

---

## Reporting

| Format | Use Case | Content |
|---|---|---|
| **JSON** | Programmatic consumption, CI/CD | Full structured data with all fields |
| **Markdown** | Quick human review, documentation | Summary, findings list, recommendations |
| **SARIF 2.1** | VS Code, GitHub CodeQL, CI/CD | SARIF-compliant with rules and results |
| **HTML** | Interactive review, stakeholders | Standalone HTML with navigation and search |
| **Attack Graph** | Visual analysis | HTML with Graphviz, path highlighting |
| **Purple Team Rules** | Detection rule generation | YARA/Sigma-compatible rules |
| **ZIP Evidence** | Audit, legal | Raw requests/responses, metadata |

---

## Plugin System

HunterX supports five plugin types:

| Plugin Type | Purpose |
|---|---|
| **Detector** | Respond to specific findings during scan |
| **Reporter** | Custom output formats |
| **Hook** | Lifecycle hooks (before/after scan, request, etc.) |
| **Agent** | Custom agent behaviors |
| **Skill** | New security skills |

Full reference: [Plugin Development](/PLUGIN_DEVELOPMENT/) | [Skill SDK](/SKILL_SDK/)

---

## Safety & Security

- **Destructive Payload Blocklist** — Hard-coded, non-bypassable blocklist for rm -rf, reverse shells, fork bombs, SQL writes
- **5-Level Safety Policy** — Safe, Balanced, Aggressive, Research, Paranoid — applied at reasoning, skill, and payload execution layers
- **SSL Verification** — Enabled by default for all outbound connections
- **Rate Limiting** — Token-bucket algorithm with configurable max RPS
- **WAF Auto-Abort** — 50+ WAF signatures with configurable auto-abort threshold
- **Thread Safety** — All shared state synchronized with threading locks

---

## Deployment

- **Docker** — Multi-stage build, 271MB image, non-root user, OCI labels
- **CI/CD** — GitHub Actions matrix (3.11/3.12/3.13) with Ruff, pytest, and Docker smoke test
- **Python Package** — pyproject.toml-based, pip installable from source
