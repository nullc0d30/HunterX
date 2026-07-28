---
layout: default
title: Examples — HunterX Usage
description: >-
  Real-world usage examples for HunterX vulnerability scanner. Basic scans,
  authenticated testing, API server, CI/CD integration, Docker deployment,
  and plugin development examples.
---

# Examples

## Basic Scan

```bash
python hunterx.py -u http://example.com
```

## Multi-Target Scan

```bash
python hunterx.py -f targets.txt --format json -o results.json
```

## Bounty Profile

```bash
python hunterx.py -u http://example.com -p bounty --max-rps 10
```

## Authenticated Scan (Bearer Token)

```bash
python hunterx.py -u http://example.com -a bearer --token eyJhbG...
```

## Form Login

```bash
python hunterx.py -u http://example.com -a form --username admin --password s3cret
```

## API Server

```bash
# Start server
python hunterx.py api --port 8443

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
docker run -v $(pwd)/reports:/reports nullc0d30/hunterx \
  scan -u http://example.com -o /reports/report.md
```

## Python SDK

```python
from hunterx.scanner import Scanner

scanner = Scanner(
    url="http://example.com",
    profile="bounty",
    max_rps=10,
    format="json"
)
results = scanner.run()
print(results.to_dict())
```

## CI/CD (GitHub Actions)

```yaml
- name: Run HunterX Scan
  run: |
    docker run nullc0d30/hunterx scan -u {% raw %}${{ secrets.TARGET_URL }}{% endraw %} \
      -o /reports/report.sarif --format sarif
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
