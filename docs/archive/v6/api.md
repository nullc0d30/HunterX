---
layout: default
title: REST API Reference — HunterX v6.0.0
description: >-
  Complete REST API reference for HunterX v6.0.0 vulnerability scanner. 40+
  endpoints covering scan management, AI providers, agents, skills, payloads,
  workflows, reasoning, and system health. Automate penetration testing and
  security assessment pipelines.
  configuration, and system health. FastAPI-based.
---

## REST API Reference

HunterX includes a built-in REST API server built with [FastAPI](https://fastapi.tiangolo.com/). It provides 40+ endpoints for integrating HunterX into automation pipelines, CI/CD workflows, and custom toolchains.

---

## Starting the Server

```bash
# Default port 8443
hunterx api --port 8443

# Custom host and port
hunterx api --port 8080 --host 0.0.0.0

# With debug logging
hunterx api --port 8443 --debug

# Docker
docker run --rm -p 8443:8443 nullc0d30/hunterx:latest api --port 8443
```

---

## Scan Endpoints

### `POST /scan`
Submit a new asynchronous scan job.

**Request Body:**
```json
{
  "url": "https://example.com",
  "profile": "bounty",
  "options": {
    "stealth": "medium",
    "ai_enabled": false,
    "threads": 5,
    "timeout": 30
  }
}
```

**Response (201):**
```json
{
  "job_id": "abc123",
  "status": "queued",
  "message": "Scan job submitted"
}
```

### `GET /scan/{job_id}`
Poll scan job status and retrieve results.

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
      "type": "lfi",
      "severity": "high",
      "url": "https://example.com/page?file=/etc/passwd",
      "evidence": "root:x:0:0:root:/root:/bin/bash",
      "confidence": 0.95,
      "mitre_id": "T1190",
      "cwe_id": "CWE-22",
      "description": "Local File Inclusion detected"
    }
  ]
}
```

### `DELETE /scan/{job_id}`
Cancel a running scan job.

### `GET /scans`
List all scan jobs with optional filtering and pagination.

### `POST /scan/{job_id}/pause`
Pause a running scan.

### `POST /scan/{job_id}/resume`
Resume a paused scan.

---

## AI Provider Endpoints

### `GET /ai/providers`
List configured AI providers and their status.

### `POST /ai/chat`
Send a chat completion request to an AI provider.

**Request Body:**
```json
{
  "provider": "openai",
  "model": "gpt-4",
  "messages": [
    {"role": "system", "content": "You are a security analyst."},
    {"role": "user", "content": "Analyze this finding..."}
  ],
  "temperature": 0.3
}
```

### `POST /ai/chat/stream`
Stream a chat completion response (Server-Sent Events).

### `GET /ai/sessions`
List AI conversation sessions.

### `POST /ai/sessions`
Create a new conversation session.

### `GET /ai/sessions/{id}`
Get session conversation history.

### `DELETE /ai/sessions/{id}`
Clear session history.

### `GET /ai/metrics`
Get AI provider usage metrics (requests, tokens, latency, cost).

### `GET /ai/models`
List available models for a provider.

---

## Agent Endpoints

### `GET /agents`
List all registered agents with their status and capabilities.

### `GET /agents/{id}`
Get detailed information about a specific agent.

### `POST /agents/{id}/start`
Start a specific agent.

### `POST /agents/{id}/stop`
Stop a specific agent.

---

## Skills Endpoints

### `GET /skills`
List all registered security skills with metadata.

### `GET /skills/{id}`
Get detailed information about a specific skill (parameters, MITRE mapping, OWASP categories).

### `GET /skills/search`
Search skills by name, category, or MITRE technique.

**Query Parameters:** `?q=sql&category=web`

### `POST /skills/execute/{id}`
Execute a specific skill against a target.

### `POST /skills/install`
Install a skill from a package or registry path.

### `DELETE /skills/{id}`
Uninstall a skill.

### `GET /skills/categories`
List all skill categories.

### `GET /skills/mitre`
List skills mapped to specific MITRE ATT&CK techniques.

---

## Payload Endpoints

### `GET /payload/search`
Search indexed payloads using FTS5 full-text search.

**Query Parameters:** `?q=sql+injection&limit=20&policy=safe`

### `GET /payload/stats`
Get payload repository statistics (total count, by category, by policy level).

### `POST /payload/mutate`
Mutate a payload using specified techniques.

**Request Body:**
```json
{
  "payload": "<script>alert(1)</script>",
  "techniques": ["url_encode", "unicode"],
  "count": 10
}
```

### `GET /payload/techniques`
List available mutation techniques with descriptions.

### `POST /payload/feedback`
Submit feedback on payload effectiveness.

---

## Workflow Endpoints

### `GET /workflows`
List all defined workflow templates.

### `POST /workflows`
Create a new workflow (DAG definition).

### `POST /workflows/{id}/execute`
Execute a workflow by ID.

### `GET /workflows/{id}/status`
Get workflow execution status (running, completed, failed, paused).

---

## Reasoning Endpoints

### `POST /goals`
Create a new reasoning goal.

**Request Body:**
```json
{
  "type": "vulnerability_detection",
  "target": "https://example.com",
  "parameters": {
    "depth": "full",
    "ai_provider": "openai",
    "confidence_threshold": 0.7
  }
}
```

### `GET /goals/{id}`
Get goal status and results.

---

## System Endpoints

### `GET /health`
System health check.

```json
{
  "status": "healthy",
  "version": "6.0.0",
  "uptime_seconds": 3600,
  "agents_online": 10,
  "skills_registered": 41
}
```

### `GET /version`
Get platform version information.

```json
{
  "version": "6.0.0",
  "build": "release",
  "python": "3.11.9"
}
```

### `GET /config`
Get current runtime configuration (sensitive values sanitized).

### `PUT /config`
Update configuration at runtime (subset of parameters).

### `GET /config/schema`
Get the configuration schema for validation.

---

## Python SDK Example

```python
import requests
import time
import json

BASE = "http://localhost:8443"

# Submit scan
resp = requests.post(f"{BASE}/scan", json={
    "url": "https://example.com",
    "profile": "bounty",
    "options": {"stealth": "medium"}
})
job = resp.json()
print(f"Job submitted: {job['job_id']}")

# Poll until complete
while True:
    status = requests.get(f"{BASE}/scan/{job['job_id']}").json()
    print(f"Status: {status['status']} ({status.get('progress', 0)}%)")
    if status["status"] in ("completed", "failed"):
        break
    time.sleep(2)

# Print findings
if status["status"] == "completed":
    for result in status.get("results", []):
        print(f"[{result['severity']}] {result['type']}: {result['url']} "
              f"(confidence: {result['confidence']})")
```

---

## Error Handling

All endpoints return consistent error responses:

```json
{
  "detail": {
    "code": "SCAN_NOT_FOUND",
    "message": "No scan job found with the provided ID",
    "params": {"job_id": "invalid-id"}
  }
}
```

| HTTP Code | Meaning |
|---|---|
| 200 | Success |
| 201 | Created |
| 400 | Bad request (invalid parameters) |
| 404 | Resource not found |
| 409 | Conflict (scan already running) |
| 422 | Validation error |
| 500 | Internal server error |

---

## Environment Variables

| Variable | Config Path | Default | Description |
|---|---|---|---|
| `HX_API_PORT` | api.port | 8443 | API server port |
| `HX_API_HOST` | api.host | 0.0.0.0 | API server bind address |
| `HX_TIMEOUT` | scan.timeout | 30 | Request timeout in seconds |
| `HX_THREADS` | scan.threads | 5 | Concurrent thread count |
| `HX_MAX_RPS` | scan.max_rps | 10.0 | Max requests per second |
| `HX_AI_ENABLED` | ai.enabled | false | Enable AI analysis |
| `HX_AI_PROVIDER` | ai.provider | openai | AI provider name |
| `HX_AI_MODEL` | ai.model | gpt-4 | AI model name |
| `HX_LOG_LEVEL` | logging.level | INFO | Logging verbosity |
