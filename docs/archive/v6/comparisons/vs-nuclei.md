---
layout: default
title: HunterX vs Nuclei — Comparison
description: >-
  Detailed technical comparison between HunterX (AI-assisted reasoning engine)
  and ProjectDiscovery Nuclei (template-based scanner). Architecture, detection
  methodology, performance, and use case analysis.
---

## HunterX vs Nuclei

| Dimension | HunterX | Nuclei |
|-----------|---------|--------|
| **Type** | Reasoning-driven framework | Template-based scanner |
| **Detection** | Response differential analysis + stage pipeline | YAML template matching |
| **Pipeline** | 4-stage (Passive → Probe → Confirm → Verify) | Single-pass template execution |
| **Initial Release** | 2024 | 2020 |
| **License** | Apache 2.0 | MIT |
| **Language** | Python | Go |
| **Plugin System** | Decorator-based (detector/reporter/hook) | Template + workflow |
| **Auth** | Basic, Bearer, Cookie, Form Login | Header, Cookie (limited) |
| **Operator Profiles** | Internal, Bounty, Gov, Custom | None |
| **Destructive Blocklist** | Built-in, non-bypassable | None |
| **WAF Evasion** | 50+ signatures + mutation engine | Limited mutation |
| **AI/ML** | Optional LLM + DBSCAN | None |
| **OOB Detection** | Built-in (collaborator) | Via templates |
| **Reporting** | MD, JSON, SARIF, HTML, ZIP | JSON, MD |
| **API Server** | Built-in FastAPI | None (runs as CLI) |
| **Docker Image** | 271 MB | ~50 MB |

## When to Use HunterX

- Need context-aware, reasoning-based vulnerability detection
- Operating in restricted environments (Bounty/Gov profiles)
- Want authenticated scanning with form login support
- Need SARIF reporting for CI/CD integration
- Want AI-assisted analysis of findings

## When to Use Nuclei

- Running large-scale, template-based scanning across many targets
- Need the extensive Nuclei template ecosystem (9000+ templates)
- Want a lightweight, fast Go binary
- Need complex workflow chaining across templates

## Complementary Use

HunterX and Nuclei are complementary. A typical workflow:

1. **Nuclei** for broad, fast template coverage across many subdomains
2. **HunterX** for deep, reasoning-driven analysis of high-value targets
