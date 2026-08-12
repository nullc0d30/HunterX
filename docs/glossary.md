---
layout: default
title: Glossary — HunterX v7 Security Terms
keywords: security glossary, vulnerability glossary, penetration testing terms, bug bounty terms, PoC definition, proof of concept security, vulnerability validation terms
description: >-
  A glossary of security terms used by HunterX v7: findings, evidence, proof,
  PoC, reproducibility, impact, confidence, missions, target intelligence and
  more.
---

# Glossary

A glossary of terms as used by HunterX v7.

- **Assessment** — an authorized security-testing engagement run by HunterX,
  organized into missions.
- **Asset** — a discrete component of the target surface (host, endpoint,
  service, cloud resource) tracked in target intelligence.
- **Campaign** — a persistent, multi-mission security initiative against a
  target, with its own intelligence and history.
- **Canonical observation** — a normalized, structured result produced from a
  tool's raw output by a parser and normalizer. Raw tool output is never a
  verdict; observations are.
- **Confidence** — an evidence-driven value computed by a versioned, weighted
  policy over named factors (detection evidence, behavioral evidence,
  independent verification, PoC reproducibility, evidence quality, scope
  certainty, target stability).
- **Correlation** — connecting observations, findings and evidence across tools
  and missions, often through the knowledge graph.
- **Evidence** — provenance-backed data that supports or refutes a hypothesis
  or finding.
- **Finding** — a result of a security assessment. In HunterX, a finding moves
  through a lifecycle: DETECTED → SUSPECTED → VALIDATING → VALIDATED → PROVEN →
  CONFIRMED → REPORT_READY (with FALSE_POSITIVE and INCONCLUSIVE branches).
- **Hypothesis** — a testable claim about a target's behavior, formed during
  reasoning and validated with evidence.
- **Impact** — the consequence of a vulnerability classified strictly from
  captured evidence (confidentiality, integrity, availability, authorization,
  authentication, data exposure, account impact, resource access, business
  logic, cloud resource exposure).
- **Knowledge graph** — an entity-relationship store (targets, assets,
  observations, findings, evidence, proofs, attack paths) enabling correlation
  and attack-path analysis.
- **Mission** — a unit of work in HunterX v7: a full-spectrum security
  assessment that can be created, run, checkpointed, resumed and finalized.
- **PoC (Proof of Concept)** — a structured, machine-replayable artifact that
  demonstrates a vulnerability with minimum necessary interaction. PoCs are
  never arbitrary executable scripts.
- **Proof** — the reproducible technical demonstration that validates a
  specific vulnerability hypothesis.
- **Proof contract** — a deterministic, per-vulnerability-class contract
  defining preconditions, allowed and forbidden actions, required evidence,
  expected behavior, replay/impact requirements and whether confirmation is
  permitted.
- **Reproducibility** — whether a proof/PoC produces consistent results over
  repeated replays. REPRODUCIBLE requires at least two successful replays with
  no failures.
- **Report-ready finding** — a finding that satisfies the reportability
  contract (identity, affected asset, classification, evidence, proof,
  reproducible PoC, impact, confidence, scope, timestamp, provenance,
  remediation context).
- **Scope** — the authorized set of targets (domains, CIDRs, IPs, URLs) that
  HunterX is permitted to test. Scope and authorization guards are fail-closed.
- **Target** — the object of an authorized assessment (domain, host, IP,
  CIDR, URL, repository, cloud account).
- **Target intelligence** — structured, persisted knowledge about a target:
  assets, observations, findings, evidence, history, relationships, topology
  and cloud intelligence.
- **TIDB** — the v7 persistence layer: SQL storage (SQLite default, PostgreSQL
  supported) with Alembic migrations, events, audit and versioning.
- **Toolchain intelligence** — machine-readable contracts for the 92 integrated
  security tools: capabilities, versions, parsers, normalizers, chaining and
  health.

## Related

- [PoC & Validation]({{ '/poc-validation/' | relative_url }})
- [Reasoning Engine]({{ '/reasoning-engine/' | relative_url }})
- [FAQ]({{ '/faq/' | relative_url }})
- [Documentation Hub]({{ '/documentation/' | relative_url }})
