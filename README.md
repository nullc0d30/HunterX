# HunterX — AI-Assisted Vulnerability Hunter

<div align="center">

[![GitHub Release](https://img.shields.io/github/v/release/nullc0d30/HunterX?style=flat-square&logo=github)](https://github.com/nullc0d30/HunterX/releases)
[![Python Version](https://img.shields.io/badge/python-3.11%2B-blue?style=flat-square&logo=python)](https://python.org)
[![License](https://img.shields.io/badge/license-Apache%202.0-green?style=flat-square)](https://www.apache.org/licenses/LICENSE-2.0)
[![Tests](https://img.shields.io/badge/tests-623%20passing-brightgreen?style=flat-square)](#testing)
[![Ruff](https://img.shields.io/badge/ruff-0%20errors-brightgreen?style=flat-square)](https://github.com/astral-sh/ruff)
[![Docker](https://img.shields.io/badge/docker-multi--stage-2496ED?style=flat-square&logo=docker)](https://www.docker.com)

</div>

---

## Introduction

HunterX is an AI-assisted vulnerability hunting platform that combines automated security scanning, intelligent payload generation, multi-agent coordination, and a reasoning engine to deliver comprehensive security assessments. Built for offensive security professionals and defensive teams alike, HunterX integrates MITRE ATT&CK mapping, threat modeling, risk scoring, and coverage across web, API, cloud, and infrastructure attack surfaces.

Version 6.0.0 introduces a horizontally-scalable architecture with a Security Intelligence Platform, an AI Provider Abstraction Layer, a Multi-Agent Platform with goal-based reasoning, a dedicated Reasoning Engine, a Security Skills Framework, and a comprehensive REST API and CLI.

---

## Architecture Overview

```
+---------------------------------------------------------------------+
|                          CLI (hunterx.py)                           |
|                API (FastAPI, port 8443, 40+ endpoints)              |
+---------------------------------------------------------------------+
|                    Orchestration Engine (engine.py)                  |
+---------------------------------------------------------------------+
|  +------------------+  +------------------+  +--------------------+ |
|  |  Multi-Agent     |  |  Reasoning       |  |  Security Skills   | |
|  |  Platform        |  |  Engine          |  |  Framework         | |
|  |  10 agents       |  |  18 GoalTypes    |  |  41 skills         | |
|  |  Event/MessageBus|  |  Planner/Output  |  |  Registry/Executor | |
|  |  State/Workflow  |  |  Validator       |  |  Cache/Telemetry   | |
|  +------------------+  +------------------+  +--------------------+ |
+---------------------------------------------------------------------+
|               AI Provider Abstraction Layer                          |
|  OpenAI  |  Ollama  |  AIManager  |  AICache  |  AIMetrics          |
|  CircuitBreaker  |  RetryHandler  |  Safety  |  ConversationManager |
+---------------------------------------------------------------------+
|  +------------------+  +------------------+  +--------------------+ |
|  |  Payload         |  |  Knowledge       |  |  Threat Model      | |
|  |  Intelligence    |  |  Graph           |  |  + Attack Chain    | |
|  |  Index/Search    |  |  Risk Engine     |  |  MITRE ATT&CK      | |
|  |  Mutation Engine |  |  Adaptive Memory |  |  Browser Intel     | |
|  |  10 techniques   |  |  Scan Planner    |  |  Purple Team       | |
|  +------------------+  +------------------+  +--------------------+ |
+---------------------------------------------------------------------+
|               Plugin System (Detectors, Reporters, Hooks)           |
+---------------------------------------------------------------------+
|                    Reporting (JSON, MD, SARIF, HTML)                |
+---------------------------------------------------------------------+
```

---

## Major Capabilities

### Reconnaissance & Fingerprinting
Technology detection, HTTP header analysis, TLS analysis, cookie analysis, DNS intelligence, subdomain enumeration, WAF fingerprinting (50+ signatures), and fingerprint correlation.

### Security Analysis
Authentication analysis, JWT analysis, OAuth analysis, CORS analysis, CSP analysis, CSRF detection, clickjacking detection, open redirect detection, GraphQL introspection, WebSocket analysis, REST API fuzzing, OpenAPI validation, and gRPC inspection.

### Vulnerability Verification
Directory enumeration, file upload testing, LFI, RFI, SSRF, XXE, SSTI, SQL injection, NoSQL injection, command injection, path traversal, and deserialization attack detection.

### Cloud Security
Secrets detection, cloud metadata service abuse, S3 bucket enumeration, Azure Blob discovery, GCP Storage inspection, Kubernetes assessment, Docker daemon analysis, and CI/CD secrets leakage detection.

### AI Integration
Two providers (OpenAI, Ollama) with conversation management, response caching, performance metrics, middleware pipeline, retry handling, and circuit breaker patterns.

### Reporting
Multi-format output: JSON, Markdown, SARIF 2.1, HTML, visual attack graph, and purple team detection rules.

---

## Security Skills Framework

The Security Skills Framework provides a standardized system for defining, registering, and executing security checks. It includes:

- **41 default skills** covering web, cloud, API, and infrastructure attack surfaces
- **SkillRegistry** for skill discovery and lifecycle management
- **SkillLoader** for dynamic skill loading
- **SkillMetadata** with MITRE ATT&CK, OWASP, CWE, and CAPEC references
- **SkillCapabilityRegistry** with 45 registered capabilities
- **SkillExecutor** with built-in caching and telemetry collection
- **SkillPlanner**, **SkillValidator**, **SkillContext**, and **SkillResult** for structured execution
- **SkillPolicy** for policy enforcement across 5 safety levels
- **SkillCache** and **SkillTelemetry** for performance tracking
- **SkillMarketplace** for skill discovery and distribution

---

## Reasoning Engine

The Reasoning Engine provides goal-driven, AI-powered analysis for the agent platform:

- **ReasoningOrchestrator** coordinating multi-step reasoning workflows
- **18 GoalTypes** covering reconnaissance, analysis, verification, reporting, and coordination
- **ReasoningPlanner** decomposing high-level goals into actionable steps
- **ReasoningPromptManager** with 11 specialized prompt templates
- **OutputValidator** with hallucination detection for AI response verification
- **ReasoningResult** for structured output
- **PolicyManager** enforcing 5 safety levels across all reasoning operations
- **ConsensusEngine** for multi-agent agreement
- **ConfidenceScorer** for result quality assessment
- **ReasoningMemory** for persistent context across reasoning sessions

---

## Multi-Agent Platform

The Multi-Agent Platform enables autonomous, coordinated security workflows:

- **10 default agents**: Recon, ThreatModeling, Planning, Payload, Verification, Risk, Reporting, PurpleTeam, Learning, Coordinator
- **AgentRegistry** for agent discovery and management
- **EventBus** and **MessageBus** for inter-agent communication
- **StateManager** for workflow state persistence
- **WorkflowEngine** supporting DAG-based execution flows
- **AgentScheduler** for timed and event-driven agent activation
- **AgentPlanner** for goal decomposition and task allocation
- **AgentMemory** and **AgentContext** for long-term and session-level state
- **CapabilityRegistry** for agent capability advertisement

---

## Payload Intelligence

The Payload Intelligence platform provides sophisticated payload generation and management:

- **Payload Index** with search capabilities
- **5-level Policy** system (Safe, Balanced, Aggressive, Research, Paranoid)
- **Feedback Loop** for continuous improvement
- **Mutation Engine** supporting 10 technique families
- **Provenance tracking** for payload lineage
- **Metadata management** and reasoning capabilities
- **Graph-based payload relationship modeling**
- **Sync** for distributed payload databases

---

## Knowledge Graph / Threat Model / Risk Engine

- **Knowledge Graph**: Graph-based storage and querying of security relationships, findings, and contextual data across scan targets.
- **Threat Model** with **Attack Chain Engine**: Automated threat modeling using attack chain decomposition and MITRE ATT&CK mapping.
- **Risk Engine**: Quantitative and qualitative risk scoring based on CVSS vectors, exploitability, business impact, and contextual factors.
- **Adaptive Memory**: Persists and recalls scan context across sessions for progressive learning.
- **Browser Intelligence**: Captures and analyzes browser-level security signals.
- **Explainable AI**: Provides human-readable rationales for AI-driven decisions.

---

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Basic scan
python hunterx.py -u http://target.com --profile bounty

# Start REST API
python hunterx.py api --port 8443

# Scan with AI assistance
python hunterx.py -u http://target.com --ai --ai-model llama3.2

# List available skills
python hunterx.py skills list

# List available agents
python hunterx.py agents list

# View payload statistics
python hunterx.py payload stats
```

---

## Docker

```bash
# Pull the latest image
docker pull nullc0d30/hunterx:latest

# Run a scan
docker run --rm -v $(pwd)/reports:/data nullc0d30/hunterx:latest \
    -u http://target.com -o /data

# Start the API server
docker run --rm -p 8443:8443 nullc0d30/hunterx:latest api --port 8443
```

The Docker image uses a multi-stage build for minimal footprint.

---

## Project Structure

```
hunterx.py                     CLI entry point (1121 lines)
api/
  server.py                    FastAPI REST server (622 lines)
  models.py                    Pydantic models
  job_queue.py                 Async job queue
core/
  agents/                      Multi-Agent Platform (15 modules + 10 agents)
  reasoning/                   Reasoning Engine (10 modules)
  skills/                      Security Skills Framework (14 modules + 41 skills)
  ai/                          AI Abstraction Layer (15+ modules)
  knowledge_graph.py           Knowledge Graph
  threat_model.py              Threat Model
  adaptive_memory.py           Adaptive Memory
  risk_engine.py               Risk Engine
  browser_intelligence.py      Browser Intelligence
  attack_chain.py              Attack Chain Engine
  explainability.py            Explainable AI
  mitre.py                     MITRE ATT&CK Mapping
  purple.py                    Purple Team Integration
  visual_graph.py              Visual Attack Graph
  planner.py                   Scan Planner
  engine.py                    Orchestration Engine
  + payload intelligence modules (13+ modules)
tests/                         623 tests
```

---

## Testing

The test suite comprises **623 passing tests** with 4 pre-existing failures limited to infrastructure-level tests. The codebase is lint-clean with **0 Ruff errors**.

```bash
# Run the full test suite
pytest tests/

# Run with coverage
pytest --cov=core tests/
```

---

## Security

HunterX implements multiple layers of security for its own operation:

- **Destructive payload blocklist**: Hard-coded, non-bypassable protection against dangerous payloads
- **5 safety levels**: Safe, Balanced, Aggressive, Research, Paranoid
- **SSL verification**: Enabled by default for all outbound connections
- **Rate limiting**: Token-bucket algorithm for responsible scanning
- **WAF detection**: 50+ WAF signatures for target awareness
- **Thread safety**: All concurrent operations are synchronized

---

## Contributing

Contributions are welcome. Please follow these guidelines:

1. Fork the repository and create a feature branch
2. Ensure all tests pass (`pytest tests/`)
3. Run Ruff linter and fix any errors (`ruff check . --fix`)
4. Maintain MITRE/OWASP/CWE/CAPEC metadata for any new skills
5. Submit a pull request with a clear description of changes

---

## Roadmap

Future development is focused on expanding the ecosystem across several dimensions:

- **Skills**: Community skill repository, skill versioning, dependency management between skills
- **AI Providers**: Additional provider support (Anthropic, Google, local models), provider failover, A/B model comparison
- **Integrations**: CI/CD pipeline plugins (GitHub Actions, GitLab CI, Jenkins), SIEM connectors, ticketing system integration
- **Community**: Public skill marketplace, contribution templates, community detection rules
- **Documentation**: Full API reference, interactive tutorials, video walkthroughs, example workflows

---

## Citation

If you use HunterX in academic research, please cite:

```bibtex
@software{HunterX,
  author = {Ahmed Awad},
  title = {HunterX: AI-Assisted Vulnerability Hunter},
  year = {2026},
  version = {6.0.0},
  url = {https://github.com/nullc0d30/HunterX}
}
```

---

## License

HunterX is licensed under the Apache License, Version 2.0. See the [LICENSE](LICENSE) file for details.

---

## Acknowledgements

- **Author**: Ahmed Awad (NullC0d3) — [https://github.com/nullc0d30](https://github.com/nullc0d30)
- Built with Python 3.11+, FastAPI, and the open-source security community

---

## Community

- **GitHub**: [https://github.com/nullc0d30/HunterX](https://github.com/nullc0d30/HunterX)
- **Issues**: Bug reports and feature requests via GitHub Issues
- **Contributions**: Pull requests and discussions are welcome
