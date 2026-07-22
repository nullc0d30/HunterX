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

# Deploying HunterX in Production with Docker

HunterX provides an optimized 271MB multi-stage Docker image running as a non-root user.

## Quick Start

```bash
docker run nullc0d30/hunterx scan -u http://example.com
```

## Production Deployment

### Volume Mounting

```bash
docker run \
  -v $(pwd)/config:/config \
  -v $(pwd)/reports:/reports \
  nullc0d30/hunterx \
  scan -c /config/hunterx.yaml -u http://example.com -o /reports/report.md
```

### Resource Limits

```bash
docker run \
  --memory="512m" \
  --cpus="2" \
  nullc0d30/hunterx scan -u http://example.com
```

### API Server

```bash
docker run \
  -p 8443:8443 \
  -v $(pwd)/reports:/reports \
  nullc0d30/hunterx api --port 8443
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
      - run: hunterx scan -u {% raw %}${{ secrets.TARGET_URL }}{% endraw %} \
          -o /reports/report.sarif --format sarif
```

### GitLab CI

```yaml
scan:
  image: nullc0d30/hunterx:latest
  script:
    - hunterx scan -u $TARGET_URL -o report.sarif --format sarif
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
- `4.0.1`: Specific version
- `dev`: Development build (unstable)
