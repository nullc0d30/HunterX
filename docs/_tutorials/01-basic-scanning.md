---
layout: default
title: Basic Scanning with HunterX
description: >-
  Learn how to perform basic vulnerability scans with HunterX. Single-target,
  multi-target, and passive-only scanning modes with practical examples.
---

## Tutorial: Basic Scanning with HunterX

## Prerequisites

- Python 3.11+ or Docker
- HunterX installed (`pip install hunterx` or Docker)

## Single-Target Scan

```bash
hunterx scan http://example.com
```

This runs all 4 stages against the target and produces a Markdown report.

## Multi-Target Scan

Create a file `targets.txt`:

```
http://target1.com
http://target2.com
http://target3.com
```

Run:

```bash
for url in $(cat targets.txt); do hunterx scan "$url" --output-dir "./results/$url"; done
```

## Passive-Only Mode

Gather information without sending probes:

```bash
hunterx scan http://example.com --passive-only
```

This runs Stage 0 (passive intel) and exits.

## Understanding Output

The default report includes:

- **Summary**: Scan duration, requests sent, vulnerabilities found
- **Findings**: Categorized by severity (critical, high, medium, low, info)
- **Evidence**: Request/response pairs for confirmed vulnerabilities
- **Recommendations**: Remediation suggestions (when LLM enabled)
