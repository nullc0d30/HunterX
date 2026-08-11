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

```mermaid
flowchart TD
    A[CLI / API / Docker] --> B[Orchestration Engine]
    B --> C[Agents]
    B --> D[Skills]
    B --> E[Reasoning Engine]
    C --> F[Knowledge Graph]
    D --> F
    E --> F
    F --> G[Threat Modeling]
    F --> H[Payload Intelligence]
    style A fill:#f9f,stroke:#333
    style B fill:#bbf,stroke:#333
    style C fill:#bfb,stroke:#333
    style D fill:#bff,stroke:#333
    style E fill:#fb9,stroke:#333
    style F fill:#ff9,stroke:#333
    style G start:#9f9,stroke:#333
    style H end:#f99,stroke:#333
```

### Core Subsystems

| Subsystem | Components | Description |
|-----------|------------|-------------|
| **Agents** | 10 specialized agents | Autonomous entities performing reconnaissance, exploitation, and post-exploitation tasks |
| **Skills** | 41 skill modules | Atomic capabilities for specific security tasks (e.g., port scanning, vulnerability assessment) |
| **Reasoning Engine** | 18 goal types | AI-driven planning and decision-making system that orchestrates agents and skills |
| **Knowledge Graph** | Contextual intelligence | Unified threat intelligence repository linking assets, vulnerabilities, and attack patterns |
| **Threat Modeling** | Attack surface analysis | Systematic identification and prioritization of potential threats |
| **Payload Intelligence** | Exploit optimization | Context-aware payload generation and evasion techniques |
| **AI Provider Layer** | LLM abstraction | Unified interface for integrating multiple language models |
| **MITRE ATT&CK Mapping** | Framework alignment | Comprehensive mapping of capabilities to ATT&CK tactics and techniques |

## Related Resources

- [Documentation](/documentation/)
- [Tutorials](/tutorials/)
- [Comparisons](/comparisons/)
- [Reference Guide](/reference-guide/)
- [Installation](/installation/)
- [Quickstart](/quickstart/)
- [All Features](/features/)

