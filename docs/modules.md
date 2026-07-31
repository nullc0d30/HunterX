---
layout: default
title: Module Reference — HunterX v6.0.0
description: >-
  Complete reference for HunterX scan modules for vulnerability scanning,
  reconnaissance, OSINT, attack surface management, and security assessment.
  List and search available modules in this open-source Linux security tool.
permalink: /modules/
---

## Module Reference

HunterX includes a set of built-in modules organized into intelligence, payload, and scan categories. View available modules with:

```bash
hunterx module list
hunterx module info <id>
hunterx module search <query>
```

---

## Intelligence Modules

| Module | Description |
|---|---|
| **Knowledge Graph** | Entity-relationship store for findings, targets, payloads, attack paths, and threat actors. Enables cross-scan correlation and relationship analysis. |
| **Threat Modeling** | STRIDE/LINDDUN categorization, trust boundary mapping, automated threat scenario generation, and kill chain progression analysis. |
| **Attack Chain Analysis** | Automated chain inference from findings, attack path discovery, and progression tracking. |

## Payload Modules

| Module | Description |
|---|---|
| **Payload Intelligence Platform** | SQLite + FTS5 indexed payload repository backed by the community-maintained [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) knowledge base, with 5-level safety policy, 10-family mutation engine, provenance tracking, user feedback loop, and context-aware selection. |
| **Payload Search** | Full-text search across the payload database using FTS5. |
| **Payload Mutation** | 10 mutation technique families for encoding, case variation, comment injection, whitespace obfuscation, and more. |

## CLI Usage

```bash
# List all modules
hunterx module list

# Show module details
hunterx module info knowledge-graph

# Search for modules
hunterx module search payload
hunterx module search graph
```

---

## Related

- [CLI Reference](cli) — Full command reference
- [Quickstart Guide](quickstart) — Run your first scan
- [Security Skills Framework](security-skills-framework) — 41 security skills
