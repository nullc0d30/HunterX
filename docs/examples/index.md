---
layout: default
title: Examples — HunterX Usage
description: >-
  Real-world usage examples for HunterX vulnerability scanner. Basic scans,
  authenticated testing, AI analysis, API server, Docker deployment,
  reporting, and plugin development examples.
---

## Examples

## Basic Reconnaissance

```bash
# Passive recon only
hunterx scan target.com --passive-only

# Stealth scan for production
hunterx scan target.com --stealth high --threads 2

# Dry run (verify logic, no requests)
hunterx scan target.com --dry-run
```

## Basic Scan

```bash
hunterx target.com
hunterx scan https://example.com --preset quick
```

## Multi-Target Scan

```bash
hunterx scan target.com -f targets.txt -o ./results
```

## Bounty Profile

```bash
hunterx scan https://example.com --profile bounty --preset quick \
    --category injection,authentication
```

## Authenticated Scan (Bearer Token)

```bash
hunterx scan https://example.com --auth bearer --token eyJhbG...
```

## Form Login

```bash
hunterx scan https://example.com --auth form --username admin --password s3cret \
    --login-url https://example.com/login
```

## AI-Powered Analysis

```bash
# Local Ollama
hunterx scan target.com --ai --ai-model llama3.2

# OpenAI
hunterx scan target.com --ai --ai-model gpt-4

# Generate AI explanations
hunterx scan target.com --ai --explain
```

## API Server

```bash
# Start server
hunterx api --port 8443

# Submit scan
curl -X POST http://localhost:8443/scan \
  -H "Content-Type: application/json" \
  -d '{"url": "http://example.com", "profile": "bounty"}'

# Poll results
curl http://localhost:8443/scan/{scan_id}

# Health check
curl http://localhost:8443/health
```

## Docker

```bash
docker run --rm -v $(pwd)/reports:/data nullc0d30/hunterx:latest \
    scan target.com -o /data
```

## Reporting

```bash
# Generate SARIF for CodeQL integration
hunterx scan target.com --sarif

# Generate visual attack graph
hunterx scan target.com --attack-graph

# Generate threat model
hunterx scan target.com --threat-model

# Generate purple team detection rules
hunterx scan target.com --purple

# Generate knowledge graph
hunterx scan target.com --graph
```

## Python SDK

```python
from hunterx import HunterX

client = HunterX(target="http://example.com", profile="bounty")
results = client.run()
print(results.to_dict())
```

## CI/CD (GitHub Actions)

```yaml
- name: Run HunterX Scan
  run: |
    docker run --rm nullc0d30/hunterx:latest \
      scan ${{ secrets.TARGET_URL }} -o /reports/report.sarif
```

## Custom Plugin

```python
from hunterx.plugin import detector

@detector("my_custom_check")
class MyDetector:
    def detect(self, response, context):
        if "custom_error" in response.text:
            return {
                "name": "Custom Error Exposure",
                "category": "info",
                "severity": "medium"
            }
        return None
```
