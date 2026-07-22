---
layout: default
title: Using HunterX as an API Server
description: >-
  Tutorial on running HunterX as a REST API server. Scan job submission,
  status polling, result retrieval, health checks, and programmatic usage
  from Python.
---

# Tutorial: Using HunterX as an API Server

## Starting the Server

```bash
python hunterx.py api --port 8443 --host 0.0.0.0
```

## Health Check

```bash
curl http://localhost:8443/health
```

Response:
```json
{"status": "healthy", "version": "4.0.1"}
```

## Submit a Scan

```bash
curl -X POST http://localhost:8443/scan \
  -H "Content-Type: application/json" \
  -d '{
    "url": "http://example.com",
    "profile": "bounty",
    "format": "json"
  }'
```

Response:
```json
{
  "scan_id": "abc123",
  "status": "pending",
  "created_at": "2026-07-22T12:00:00Z"
}
```

## Poll Results

```bash
curl http://localhost:8443/scan/abc123
```

Completed response:
```json
{
  "scan_id": "abc123",
  "status": "completed",
  "findings": [...],
  "summary": {
    "total": 5,
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 2
  },
  "duration_seconds": 45
}
```

## Python SDK

```python
import requests

api = "http://localhost:8443"

# Submit
resp = requests.post(f"{api}/scan", json={
    "url": "http://example.com",
    "profile": "bounty"
})
scan_id = resp.json()["scan_id"]

# Poll
while True:
    result = requests.get(f"{api}/scan/{scan_id}").json()
    if result["status"] in ("completed", "failed"):
        break
    time.sleep(2)

print(result)
```
