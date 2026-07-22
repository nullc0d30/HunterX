---
layout: default
title: Features — HunterX Vulnerability Assessment Framework
description: >-
  Complete feature breakdown of HunterX: 4-stage reasoning pipeline, 200+
  vulnerability signatures, REST API, AI/ML analysis, WebSocket and GraphQL
  protocol testing, OOB detection, plugin system, and Docker deployment.
---

# Features Overview

HunterX is a production-grade [vulnerability assessment](https://en.wikipedia.org/wiki/Vulnerability_assessment) and [penetration testing](https://en.wikipedia.org/wiki/Penetration_test) framework designed for professional Red Teams, bug bounty hunters, and security researchers.

---

## Core Pipeline

HunterX operates on a strictly gated **4-stage pipeline**:

| Stage | Name | Description |
|-------|------|-------------|
| 0 | Passive Intel | Gather target context from headers, detect WAF, WebSocket endpoints, GraphQL |
| 1 | Probe | Send a diverse set of probes across attack categories |
| 2 | Confirm | Deepen probes in categories that showed anomalies |
| 3 | Verify | Safely verify confirmed vulnerabilities with specialized payloads |

Each stage is gated by configurable thresholds (`probe_anomaly_threshold`, `confirm_anomaly_threshold`) and filtered through operator profile constraints.

---

## Detection Signatures

200+ vulnerability signatures across:

| Category | Examples |
|----------|----------|
| **LFI / Path Traversal** | /etc/passwd, win.ini, wp-config.php, AWS keys, SSH keys |
| **RCE / Command Injection** | id output, uname, ipconfig, directory listings, phpinfo |
| **SQL Injection** | MySQL, PostgreSQL, Oracle, MSSQL, SQLite error signatures |
| **SSTI** | Jinja2, Twig, Freemarker, Velocity test patterns |
| **SSRF** | Internal IP probing, cloud metadata access |
| **XSS** | Reflected, stored, DOM-based patterns |
| **Open Redirect** | URL validation bypasses |
| **XXE** | XML entity expansion, file disclosure |

---

## REST API

FastAPI-based REST server with:

- `POST /scan` — Submit async scan job
- `GET /scan/{id}` — Poll job status and results
- `GET /health` — Server health check
- `GET /info` — Legal metadata
- Thread-safe in-memory job queue
- Configurable via environment variables

---

## AI/ML Integration

- **LLM Analysis** (Ollama): Automated finding review, remediation suggestions
- **Anomaly Clustering** (scikit-learn): DBSCAN-based result deduplication
- Graceful fallback when dependencies are unavailable

---

## Protocol Support

- **WebSocket**: Endpoint discovery, message fuzzing, connection testing
- **GraphQL**: Introspection query, batch attack, depth-limit testing
- **OOB**: Blind XXE, SSRF, RCE via external collaborator

---

## Authentication

| Type | Details |
|------|---------|
| Basic | HTTP Basic Auth with username/password |
| Bearer | Token-based Authorization header |
| Cookie Jar | Load cookies from JSON file |
| Form Login | POST-based login with session capture |

---

## Plugin System

Decorate functions to create:

```python
# Detector plugin
@detector("my_detector")
def analyze(response_text):
    if "secret" in response_text:
        return [("High", "Secret detected")]

# Reporter plugin
@reporter("csv")
def export(results):
    # Generate CSV output
    pass

# Hook plugin
@hook("after_scan")
def notify(results, url):
    # Send webhook notification
    pass
```

---

## Reporting

| Format | Use Case |
|--------|----------|
| Markdown | Human-readable summary |
| JSON | Machine parsing, API responses |
| SARIF 2.1 | VS Code, GitHub CodeQL, CI/CD |
| HTML | Visual dashboard |
| ZIP | Evidence package |

---

## Deployment

- **Docker**: 271MB multi-stage image, non-root user, OCI labels
- **CI/CD**: GitHub Actions matrix (3.11/3.12/3.13) with Docker smoke test
- **Python Package**: pyproject.toml, pip installable
