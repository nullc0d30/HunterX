---
layout: default
title: Deploying HunterX in Production with Docker
description: >-
  Best practices for deploying HunterX in production Docker environments.
  Secure configuration, resource limits, CI/CD integration, and container
  orchestration.
date: 2026-07-19
author: Ahmed Awad (NullC0d3)
categories: [technical, devops]
---

## Deploying HunterX in Production with Docker

HunterX provides an optimized 271MB multi-stage Docker image running as a non-root user.

## Quick Start

```bash
docker run --rm nullc0d30/hunterx:latest scan http://example.com --profile bounty
```

## Production Deployment

### Volume Mounting

```bash
docker run --rm \
  -v $(pwd)/hunterx.yaml:/app/hunterx.yaml:ro \
  -v $(pwd)/reports:/data \
  nullc0d30/hunterx:latest \
  scan http://example.com -o /data
```

### Resource Limits

```bash
docker run --rm \
  --memory="512m" \
  --cpus="2" \
  nullc0d30/hunterx:latest scan http://example.com
```

### API Server

```bash
docker run --rm \
  -p 8443:8443 \
  -v $(pwd)/reports:/data \
  nullc0d30/hunterx:latest api --port 8443
```

## CI/CD Integration

### GitHub Actions

```yaml
jobs:
  scan:
    runs-on: ubuntu-latest
    container:
      image: nullc0d30/hunterx:latest
    steps:
      - run: hunterx scan {% raw %}${{ secrets.TARGET_URL }}{% endraw %} \
          -o /data/report.sarif
```

### GitLab CI

```yaml
scan:
  image: nullc0d30/hunterx:latest
  script:
    - hunterx scan $TARGET_URL -o report.sarif
  artifacts:
    paths: [report.sarif]
```

## Security

- Container runs as **non-root user** (UID 1000)
- Read-only root filesystem recommended
- Use Docker secrets for credentials
- Enable Docker Content Trust

## Image Tags

- `latest`: Most recent stable release
- `6.0.0`: Specific version
- `dev`: Development build (unstable)
