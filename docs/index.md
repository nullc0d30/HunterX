---
layout: default
title: HunterX — AI-Assisted Vulnerability Hunter
keywords: HunterX, Linux Security Tool, Red Team Framework, Offensive Security, vulnerability scanner, penetration testing
description: >-
  HunterX is an open-source AI-assisted vulnerability scanner and security
  assessment platform. Security Skills Framework, Reasoning Engine, Multi-Agent
  Platform, Knowledge Graph, Threat Modeling, Payload Intelligence, MITRE ATT&CK
  mapping, and REST API. Apache 2.0.
---

<div class="hero">

[![GitHub Release](https://img.shields.io/github/v/release/nullc0d30/HunterX?style=flat-square&logo=github)](https://github.com/nullc0d30/HunterX/releases)
[![License](https://img.shields.io/badge/license-Apache%202.0-green?style=flat-square)](https://www.apache.org/licenses/LICENSE-2.0)
[![Python Version](https://img.shields.io/badge/python-3.11%2B-blue?style=flat-square&logo=python)](https://python.org)
[![Tests](https://img.shields.io/badge/tests-623%20passing-brightgreen?style=flat-square)](https://github.com/nullc0d30/HunterX/actions)
[![Ruff](https://img.shields.io/badge/ruff-0%20errors-brightgreen?style=flat-square)](https://github.com/astral-sh/ruff)
[![Docker](https://img.shields.io/badge/docker-multi--stage-2496ED?style=flat-square&logo=docker)](https://hub.docker.com/u/nullc0d30)

**HunterX** is an open-source AI-assisted vulnerability scanner and security assessment platform. It combines a **Security Skills Framework** (41 plugin-based skills), a **Reasoning Engine** (18 goal types), a **Multi-Agent Platform** (10 specialized agents), **AI Provider Abstraction** (OpenAI, Ollama), **Knowledge Graph**, **Threat Modeling**, **Attack Chain Analysis**, and **Payload Intelligence** into a single extensible platform.

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

<div class="hero-actions">
  <a href="{{ '/installation' | relative_url }}" class="primary">Install HunterX</a>
  <a href="{{ '/quickstart' | relative_url }}" class="secondary">Quickstart Guide</a>
  <a href="{{ '/documentation' | relative_url }}" class="secondary">Documentation</a>
  <a href="https://github.com/nullc0d30/HunterX" class="secondary">GitHub</a>
</div>

</div>

---

## Why HunterX?

Traditional vulnerability scanners operate on payload volume and signature matching. HunterX is built around a structured reasoning pipeline: **Observe, Hypothesize, Probe, Verify**. Each phase is backed by dedicated platform components that coordinate through a concurrent event bus.

| Capability | Description |
|---|---|
| **Security Skills Framework** | 41 built-in skills covering web, API, cloud, and infrastructure security. Each skill carries MITRE ATT&CK, OWASP, CWE, and CAPEC metadata. Independently installable, policy-driven, cacheable, and telemetry-tracked. |
| **Reasoning Engine** | Accepts goals and produces validated results through planning, AI prompting, and multi-call consensus. Supports 18 goal types including vulnerability detection, risk assessment, exploit verification, and remediation planning. |
| **Multi-Agent Platform** | 10 specialized agents coordinate through concurrent event and message buses, executing DAG-based workflows with state persistence, checkpoint, and resume capabilities. |
| **AI Provider Abstraction** | Decouples reasoning from specific AI providers. Built-in support for OpenAI and Ollama with session management, caching (SHA256 + TTL + LRU), metrics, middleware, retry, and circuit breaker. |
| **Knowledge Graph** | Graph-based storage for security relationships, findings, attack paths, and contextual data. Enables cross-scan correlation and attack path inference. |
| **Threat Modeling & Attack Chains** | Automated threat modeling with STRIDE/LINDDUN categorization, trust boundary mapping, attack chain decomposition, and automated chain inference from findings. |
| **Payload Intelligence** | SQLite-indexed payload repository with FTS5 full-text search, 5-level execution policy, 10-family mutation engine, provenance tracking, feedback loop, and graph-based payload relationships. |
| **Explainable AI** | Every AI-driven decision produces structured results with confidence scores, evidence citations, consensus data, decision traces, and provider metadata. |
| **Enterprise REST API** | FastAPI server with 40+ endpoints covering scanning, payload management, agent coordination, reasoning, skills, AI providers, configuration, and system health. |
| **MITRE ATT&CK + OWASP Mapping** | All skills, findings, and recommendations carry MITRE ATT&CK techniques, OWASP categories, CWE IDs, CAPEC IDs, and CVSS v3.1 scoring. |

---

## Feature Highlights

<div class="feature-grid">

<div class="feature-card">
<h3>Web Security</h3>
<p>LFI, RFI, SQLi, NoSQLi, XSS, SSTI, SSRF, XXE, Command Injection, Path Traversal, Deserialization, Open Redirect, Header Injection, and more.</p>
</div>

<div class="feature-card">
<h3>API Security</h3>
<p>REST API fuzzing, GraphQL introspection, WebSocket analysis, gRPC inspection, OpenAPI validation, rate limit testing, and API version detection.</p>
</div>

<div class="feature-card">
<h3>Cloud Security</h3>
<p>Secrets detection, cloud metadata abuse, S3/Azure/GCP enumeration, Kubernetes assessment, Docker analysis, and CI/CD secrets leakage detection.</p>
</div>

<div class="feature-card">
<h3>Authentication</h3>
<p>Basic, Bearer, Cookie Jar, Form Login, JWT analysis (algorithm confusion, claim tampering), and OAuth2 flow analysis.</p>
</div>

<div class="feature-card">
<h3>Reconnaissance</h3>
<p>Technology fingerprinting, HTTP header analysis, TLS analysis, cookie analysis, DNS enumeration, subdomain discovery, and WAF fingerprinting (50+ signatures).</p>
</div>

<div class="feature-card">
<h3>AI Integration</h3>
<p>OpenAI and Ollama providers with conversation management, caching, metrics, middleware, retry, and circuit breaker. Extensible provider interface.</p>
</div>

<div class="feature-card">
<h3>Knowledge Graph</h3>
<p>Entity-relationship store for findings, targets, payloads, attack paths, and threat actors. Enables cross-scan correlation and relationship analysis.</p>
</div>

<div class="feature-card">
<h3>Threat Modeling</h3>
<p>STRIDE/LINDDUN categorization, trust boundary mapping, automated threat scenario generation, and kill chain progression analysis.</p>
</div>

<div class="feature-card">
<h3>Payload Intelligence</h3>
<p>FTS5-indexed repository, 5-level safety policy, 10 mutation technique families, provenance tracking, effectiveness feedback loop, and context-aware selection.</p>
</div>

<div class="feature-card">
<h3>Reporting</h3>
<p>JSON, Markdown, SARIF 2.1, HTML, visual attack graphs, purple team detection rules, and ZIP evidence packages.</p>
</div>

<div class="feature-card">
<h3>Multi-Agent Architecture</h3>
<p>10 specialized agents with DAG-based workflows, event/message buses, priority queues, state persistence, checkpoint, and resume.</p>
</div>

<div class="feature-card">
<h3>Plugin System</h3>
<p>Detector, reporter, hook, agent, and skill plugins. Independent skill installation, policy management, and telemetry.</p>
</div>

</div>

---

## Comparison

HunterX stands apart from traditional security scanners by unifying AI-assisted reasoning, multi-agent orchestration, and enterprise reporting into a single platform.

| Tool | Scanning | AI | Multi-Agent | Payload Intelligence | Reporting | Architecture |
|---|---|---|---|---|---|---|
| **HunterX** | Observe → Hypothesize → Probe → Verify | LLM-native (multi-provider) | 10 agents, DAG workflows | FTS5-indexed, 5-level policy | SARIF, HTML, graph, purple team | Unified Python framework |
| **Nmap** | Port scan + service detection | No | No | No | XML/Grepable | C, single-purpose |
| **Metasploit** | Exploit delivery + post-exploit | No | No | No | Console-only | Ruby, framework |
| **Nuclei** | YAML template matching | No | No | No | JSON/STDOUT | Go, template engine |
| **Amass** | Subdomain + ASN enumeration | No | No | No | JSON/graph | Go, single-purpose |
| **Sliver** | C2 + implant framework | No | No | No | CLI/console | Go, C2-focused |
| **ffuf** | Fuzzing / wordlist brute-force | No | No | No | JSON/CSV | Go, single-purpose |

---

## Architecture Overview

HunterX follows a layered architecture where each component has clear responsibilities and communicates through defined interfaces.

<div class="arch-diagram">
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
</div>

---

## Quick Start

```bash
# Install
pip install hunterx

# Scan a target
hunterx target.com

# Full scan with AI analysis
hunterx scan https://target.com --ai --ai-model llama3.2

# View reports
hunterx report

# System diagnostics
hunterx doctor
```

### Docker

```bash
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

## Documentation Hub

| Guide | Description |
|---|---|
| [Installation](installation) | Install via pip, pipx, install.sh, Docker, or from source |
| [Quickstart Guide](quickstart) | Run your first scan in 5 minutes |
| [CLI Reference](cli) | Full CLI command and argument reference |
| [REST API Reference](api) | All 40+ endpoints, request/response schemas |
| [Configuration Guide](configuration) | YAML reference, environment variables, policy levels |
| [Security Skills Framework](security-skills-framework) | 41 skills, registry, executor, policy management |
| [Reasoning Engine](reasoning-engine) | 18 goal types, planner, validator, consensus |
| [Multi-Agent Platform](agents) | 10 agents, event/message buses, workflows |
| [AI Provider Guide](ai-provider-guide) | Provider abstraction, adding providers, caching |
| [Skill SDK](skill-sdk) | Creating custom security skills |
| [Plugin Development](plugin-development) | Detector, reporter, hook, and agent plugins |
| [Module Reference](modules) | Available scan modules |
| [Docker Guide](Docker_Guide) | Container deployment, volumes, environment |
| [Examples](examples) | Real-world usage examples |
| [Tutorials](tutorials) | Step-by-step walkthroughs |
| [FAQ](faq) | Frequently asked questions |
| [Roadmap](roadmap) | Upcoming features and development plans |

---

## Community

- [Star on GitHub](https://github.com/nullc0d30/HunterX)
- [Report Bugs](https://github.com/nullc0d30/HunterX/issues)
- [Ask Questions](https://github.com/nullc0d30/HunterX/discussions)
- [Read the Blog](blog)
- [Fork and Contribute](https://github.com/nullc0d30/HunterX)

---

## Responsible Use

HunterX is provided exclusively for authorized security testing, including professional penetration testing with written authorization, defensive security research, bug bounty programs that explicitly authorize testing, red team exercises conducted with permission, and educational purposes. Users are solely responsible for obtaining authorization before scanning any target.

[Read the full Responsible Use policy &rarr;](responsible-use)

---

## About the Author

**Ahmed Awad** (known online as **NullC0d3**) is a Cybersecurity Threat Intelligence Analyst, open-source developer, and security researcher. He is the creator of HunterX, the AnubisX Framework, and RabbitHole.

- [About the Author](about-author)
- [GitHub](https://github.com/nullc0d30)
- [Docker Hub](https://hub.docker.com/u/nullc0d30)

---

*HunterX is licensed under the Apache License, Version 2.0. Copyright &copy; 2026 Ahmed Awad (NullC0d3).*
