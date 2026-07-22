---
layout: default
title: REST API — HunterX Scan Framework
description: >-
  Complete REST API reference for HunterX vulnerability scanner. Endpoints for
  submitting scan jobs, polling status, health checks, and legal metadata.
  FastAPI-based with async job queue.
---

# REST API Reference

HunterX includes a built-in REST API server built with [FastAPI](https://fastapi.tiangolo.com/). It allows submitting scan jobs asynchronously, polling for results, and integrating HunterX into larger automation pipelines.

---

## Starting the Server

```bash
# Default port 8443
python hunterx.py api --port 8443

# Docker
docker run --rm -p 8443:8443 nullc0d30/hunterx:latest api --port 8443
```

---

## Endpoints

### `POST /scan`

Submit a new scan job.

**Request Body:**

```json
{
  "url": "https://example.com",
  "profile": "bounty",
  "options": {
    "stealth": "medium",
    "ai_enabled": false,
    "time_based": true
  }
}
```

**Response:**

```json
{
  "job_id": "abc123",
  "status": "queued",
  "message": "Scan job submitted"
}
```

---

### `GET /scan/{job_id}`

Poll job status and retrieve results.

**Response (in progress):**

```json
{
  "job_id": "abc123",
  "status": "scanning",
  "progress": 45,
  "results": []
}
```

**Response (complete):**

```json
{
  "job_id": "abc123",
  "status": "completed",
  "progress": 100,
  "results": [
    {
      "payload_category": "LFI",
      "diff_score": 85,
      "findings": ["High - LFI (win.ini)"],
      "impact": "Medium",
      "stage": 3
    }
  ]
}
```

---

### `GET /health`

Server health check.

```json
{
  "status": "healthy",
  "version": "4.0.1",
  "copyright": "Copyright (c) 2026 Ahmed Awad (NullC0d3)",
  "license": "Apache License 2.0",
  "author": "Ahmed Awad (NullC0d3)"
}
```

---

### `GET /info`

Full legal and version metadata.

```json
{
  "tool": "HunterX",
  "author": "Ahmed Awad (NullC0d3)",
  "version": "4.0.1",
  "license": "Apache License 2.0",
  "repository": "https://github.com/nullc0d30/HunterX"
}
```

---

## Job Statuses

| Status | Description |
|--------|-------------|
| `queued` | Waiting for worker |
| `scanning` | Scan in progress |
| `completed` | Scan finished successfully |
| `failed` | Scan encountered an error |

---

## Python SDK Example

```python
import requests

BASE = "http://localhost:8443"

# Submit scan
resp = requests.post(f"{BASE}/scan", json={
    "url": "https://example.com",
    "profile": "bounty",
})
job = resp.json()

# Poll until complete
while True:
    status = requests.get(f"{BASE}/scan/{job['job_id']}").json()
    if status["status"] in ("completed", "failed"):
        break
    time.sleep(2)

# Print findings
for result in status["results"]:
    print(f"{result['payload_category']}: {result['diff_score']}")
```

---

## Environment Variables

| Variable | Config Path | Default |
|----------|-------------|---------|
| `HX_API_PORT` | api.port | 8443 |
| `HX_API_HOST` | api.host | 0.0.0.0 |
| `HX_TIMEOUT` | timeout | 15 |
| `HX_THREADS` | threads | 5 |
| `HX_MAX_RPS` | max_rps | 10.0 |
| `HX_AI_ENABLED` | ai.enabled | false |
| `HX_AI_MODEL` | ai.model | llama3.2 |
| `HX_OOB_URL` | oob.collaborator_url | null |
