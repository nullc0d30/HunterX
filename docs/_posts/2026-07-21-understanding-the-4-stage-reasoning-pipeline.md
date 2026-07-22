---
layout: default
title: Understanding HunterX's 4-Stage Reasoning Pipeline
description: >-
  Deep dive into the 4-stage reasoning pipeline: Passive Intelligence, Probe,
  Confirm, and Verify. How HunterX uses response differential analysis and
  evidence correlation for accurate vulnerability detection.
date: 2026-07-21
author: Ahmed Awad (NullC0d3)
categories: [technical, red-team]
---

# Understanding HunterX's 4-Stage Reasoning Pipeline

Traditional vulnerability scanners operate on a simple model: send a payload, check for a match. HunterX replaces this with a **reasoning pipeline** inspired by how human penetration testers think.

## Stage 0: Passive Intelligence

Before sending a single request, HunterX gathers context:

- **WAF detection**: 50+ WAF fingerprint signatures
- **Technology fingerprinting**: Server headers, cookies, response patterns
- **Endpoint discovery**: WebSocket, GraphQL, API paths
- **Authentication state detection**: Login forms, session patterns

This context informs all subsequent stages. If a WAF is detected, HunterX adjusts its probe strategy and may auto-abort.

## Stage 1: Probe

HunterX sends diverse probes across all enabled attack categories. Each probe targets a specific vulnerability class and includes markers for response differential analysis.

Key principle: **low confidence, broad coverage**. The goal is not to confirm vulnerabilities but to identify interesting response anomalies.

## Stage 2: Confirm

For categories that showed anomalies in Stage 1, HunterX deepens its investigation:

- More sophisticated payloads
- Multi-variant testing
- Time-based blind injection detection
- OOB (out-of-band) callback monitoring

Evidence is correlated across probes. A single anomaly is not enough — HunterX looks for consistent patterns.

## Stage 3: Verify

Confirmed vulnerabilities are verified with safe, impact-minimizing payloads. The verification stage produces the final evidence that goes into the report.

## Why This Matters

The 4-stage pipeline gives HunterX three key advantages:

1. **Safety**: By starting broad and narrowing, HunterX minimizes impact on targets that show no anomalies
2. **Accuracy**: Evidence is correlated across multiple probes before a finding is confirmed
3. **Explainability**: Every finding has a chain of evidence across stages

This is fundamentally different from brute-force payload matching. It's a reasoning engine, not a template matcher.
