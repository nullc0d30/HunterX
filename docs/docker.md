---
layout: default
title: Docker Guide — HunterX Container Deployment
description: >-
  Deploy HunterX vulnerability scanner with Docker. Multi-stage build, 271MB
  optimized image, non-root user, production deployment best practices, CI/CD
  integration.
---

# Docker Guide

Deploy HunterX as a secure, isolated container.

---

## Quick Start

```bash
# Pull the image
docker pull nullc0d30/hunterx:latest

# Run a scan
docker run --rm \
  -v $(pwd)/reports:/data \
  nullc0d30/hunterx:latest \
  -u https://example.com \
  --profile bounty \
  -o /data

# API mode
docker run --rm -p 8443:8443 nullc0d30/hunterx:latest api --port 8443
```

---

## Image Specifications

| Metric | Value |
|--------|-------|
| Base Image | python:3.11-slim |
| Image Size | 271MB (reduced from 700MB) |
| User | hunterx (non-root, UID 999) |
| Build | Multi-stage (builder → runtime) |
| License Labels | OCI-compliant, Apache 2.0 |

---

## Available Tags

| Tag | Description |
|-----|-------------|
| `latest` | Most recent stable release |
| `4.0.1` | Version-specific tag |

---

## Production Deployment

### Report Persistence

```bash
mkdir -p reports && chmod 777 reports

docker run --rm \
  -v "$(pwd)/reports:/data" \
  nullc0d30/hunterx:latest \
  -u https://example.com \
  -o /data
```

### Stealth Operation

```bash
docker run --rm \
  -v "$(pwd)/reports:/data" \
  nullc0d30/hunterx:latest \
  -u https://example.com \
  --profile gov \
  --passive-only \
  -o /data
```

---

## CI/CD Integration

Example GitHub Actions step:

```yaml
- name: Run HunterX scan
  run: |
    docker run --rm \
      -v {% raw %}${{ github.workspace }}{% endraw %}/reports:/data \
      nullc0d30/hunterx:latest \
      -u https://staging.example.com \
      --profile internal \
      -o /data
```

---

## Security Notes

- Container runs as **non-root** user (`hunterx`)
- No background services or exposed ports by default
- Reports volume should be writable by UID 999
- Always use tagged images (not `latest`) in production
- Keep the image updated for latest security patches
