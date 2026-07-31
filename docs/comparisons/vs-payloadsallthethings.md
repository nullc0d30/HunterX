---
layout: default
title: HunterX vs PayloadsAllTheThings — Comparison
description: >-
  Technical comparison between HunterX (AI-assisted offensive security
  framework) and PayloadsAllTheThings (community-maintained payload knowledge
  base). Explains how HunterX integrates PayloadsAllTheThings as its payload
  source and how the two projects are complementary.
---

## HunterX vs PayloadsAllTheThings

[PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) is a community-maintained repository of payloads and techniques for web application security testing. HunterX is an AI-assisted offensive security framework. They are complementary projects: HunterX integrates PayloadsAllTheThings as a primary payload knowledge source.

| Dimension | HunterX | PayloadsAllTheThings |
|-----------|---------|----------------------|
| **Type** | AI-assisted offensive security framework | Payload and technique knowledge base |
| **Primary Function** | Reasoning-driven vulnerability assessment | Curated payload collections for manual testing and tooling |
| **Detection** | Response differential analysis + 4-stage pipeline | None (reference content) |
| **Payload Sourcing** | Synchronizes PayloadsAllTheThings content locally | Source of payload content |
| **Payload Indexing** | SQLite + FTS5 local index with provenance | Plain text files by category |
| **Provenance Tracking** | Yes (repo, commit, release tag, checksum) | N/A |
| **Safety Policy** | 5-level payload execution policy + destructive blocklist | N/A |
| **Mutation Engine** | 10 technique families | N/A |
| **AI/ML** | Optional LLM + DBSCAN | None |
| **Reporting** | MD, JSON, SARIF, HTML, ZIP | N/A |
| **API Server** | Built-in FastAPI | N/A |
| **License** | Apache 2.0 | MIT |
| **Maintained By** | Project maintainers | Community (swisskyrepo) |

## How HunterX Uses PayloadsAllTheThings

- `hunterx payload sync` synchronizes the latest PayloadsAllTheThings content (shallow git clone or latest GitHub release archive).
- `hunterx payload index` builds a local, searchable SQLite + FTS5 index over the synced payload files.
- Every indexed payload records provenance: source repository, commit hash, release tag, and checksum.
- Payload selection is context-aware, ranked by target technology, framework, language, and WAF presence.

## When to Use HunterX

- Need automated, reasoning-driven vulnerability assessment with evidence.
- Want payloads selected and delivered safely under a 5-level execution policy.
- Need provenance and auditability for the payloads being used.
- Want SARIF, HTML, or graph-based reporting for CI/CD integration.

## When to Use PayloadsAllTheThings

- Prefer to browse and copy payloads directly for manual testing.
- Need the raw, community-maintained collection as reference content.
- Want to stay up to date with the latest community techniques.

## Complementary Use

PayloadsAllTheThings is the payload knowledge base; HunterX is the assessment platform that consumes it. HunterX keeps PayloadsAllTheThings content synchronized, indexed, and safely executable — giving operators the depth of the community knowledge base with the guardrails of a security framework.
