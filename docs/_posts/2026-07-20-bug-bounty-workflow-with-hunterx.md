---
layout: default
title: Optimizing Your Bug Bounty Workflow with HunterX
description: >-
  A practical guide to using HunterX in bug bounty hunting. Profile selection,
  rate limiting, authenticated scanning, and integration with existing bug
  bounty toolchains.
date: 2026-07-20
author: Ahmed Awad (NullC0d3)
categories: [bug-bounty, technical]
---

# Optimizing Your Bug Bounty Workflow with HunterX

Bug bounty hunting requires a careful balance between coverage and safety. HunterX's **Bounty profile** is specifically designed for this.

## The Bounty Profile

```
Max Requests: 500
Rate Limit:   10 req/s
Destructive:  false
```

This profile ensures you stay within program limits while maximizing coverage.

## Workflow

### 1. Recon Phase

```bash
# Gather intelligence without sending probes
hunterx scan -u http://target.com --passive-only
```

### 2. Focused Scanning

```bash
# Scan with Bounty profile, JSON output for analysis
hunterx scan -u http://target.com \
  -p bounty \
  --format json \
  -o findings.json \
  --include-category sqli,xss
```

### 3. Authenticated Testing

```bash
hunterx scan -u http://target.com \
  -a form \
  --auth-user user@example.com \
  --auth-pass s3cret \
  -p bounty
```

### 4. Results Analysis

```bash
# Convert to SARIF for VS Code
hunterx scan -u http://target.com \
  -p bounty \
  --format sarif \
  -o report.sarif
```

## Tips

- Always use the **Bounty profile** on third-party programs
- Combine with Nuclei for broad template coverage
- Use Docker for consistent environments
- Enable OOB detection for SSRF/blind XXE

## Safety First

Remember: the Bounty profile blocks destructive payloads. If you need to disable a category, use `--exclude-category`. Never bypass safety constraints on third-party targets.
