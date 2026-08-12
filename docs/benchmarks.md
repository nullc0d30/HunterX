---
layout: default
title: Benchmarks & Engineering Validation — HunterX v7
keywords: HunterX benchmarks, vulnerability scanner performance, security tool benchmarks, HunterX test suite, security platform engineering validation
description: >-
  HunterX v7 engineering validation: test suite results, quality gates and
  measured performance figures from the v7 engineering certification reports.
  Reported as engineering metrics, not marketing claims.
---

# Benchmarks & Engineering Validation

This page reports HunterX v7 engineering validation from the v7 certification
and hardening reports. Figures are engineering metrics — not marketing claims
and not guarantees of discovery or detection rates.

## Test suite

At the v7.0.0 release (Sprint 035 final hardening audit):

| Result | Count |
|---|---|
| Passed | 3479 |
| Skipped | 8 |
| Deselected | 2 |
| Failed | 0 |

The suite spans unit, component, integration, golden, security, acceptance,
performance, engineering, architecture and framework tests, plus the 92-tool
toolchain contract suite.

## Quality gates

At release, the following gates were green: **pytest, ruff, mypy (eng +
shared), bandit (Medium+), vulture, docs (7/7) and lock-file consistency**.

> **Known engineering follow-ups (P2, non-blocking).** The v7 certification
> reports record a performance-gate self-fail issue: the performance gate flags
> its own benchmark tests (>20s) as slow and cannot pass as configured, even
> though measured throughput is fine. Coverage gate reports 77% branch-adjusted
> vs an 80% line-rate target. These are internal quality-gate tuning items,
> not claims about HunterX detection performance.

## Measured performance

Measured performance figures are reported in the v7 engineering certification
reports (`docs/v7-sprint-034-final-engineering-certification.md`) from the
benchmark suite (`tests/performance`). Representative figures include
throughput on the order of >100k ops/s for correlation, >2.5M ops/s for DNS
resolution and >8M ops/s for confidence computation. Performance tests cover
mission scale (1/10/100 missions), observation scale (10k/100k/1M) and
large finding/evidence sets.

These are internal engineering measurements from the certification environment.
Real-world performance depends on your environment, target, scope and tool
selection.

## Interpreting these numbers

HunterX is an AI-assisted **discovery, validation and proof engine**, not a
race-to-fastest scanner. Its differentiator is verified findings with evidence,
reproducibility and impact — not raw detection speed. Use the figures above as
engineering context, and validate against your own workloads.

## Related

- [Quality Gates]({{ '/v7-quality-gates/' | relative_url }})
- [Final Hardening Audit]({{ '/v7-sprint-035-final-hardening-audit/' | relative_url }})
- [Engineering Certification]({{ '/v7-sprint-034-final-engineering-certification/' | relative_url }})
- [PoC & Validation]({{ '/poc-validation/' | relative_url }})
