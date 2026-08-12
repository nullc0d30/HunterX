---
layout: post
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

> **Version note.** This article was published before HunterX v7.0.0 and uses
> the v6-era CLI (`hunterx scan`). In v7, assessments are organized as
> missions: `hunterx hunt <objective> <target>` creates and starts a mission,
> and findings are managed with `hunterx finding` / `hunterx report`. See the
> [Quickstart]({{ '/quickstart/' | relative_url }}) and
> [CLI Reference]({{ '/cli/' | relative_url }}) for current usage.
> The image tags now follow v7 (`7`, `7.0`, `7.0.0`, `latest`, `stable`).

HunterX provides an optimized multi-stage Docker image running as a non-root user.

## Quick Start

```bash
docker run --rm nullc0d30/hunterx:latest version
docker run --rm nullc0d30/hunterx:latest hunt full_security_assessment https://example.com
```

## Production Deployment

### Volume Mounting

```bash
docker run --rm \
  -v $(pwd)/reports:/data \
  nullc0d30/hunterx:latest \
  hunt full_security_assessment https://example.com
```

### Resource Limits

```bash
docker run --rm \
  --memory="512m" \
  --cpus="2" \
  nullc0d30/hunterx:latest hunt full_security_assessment https://example.com
```

### API Server

```bash
docker run --rm \
  -p 8080:8080 \
  --entrypoint uvicorn nullc0d30/hunterx:latest \
  --factory hunterx.api.app:create_app --host 0.0.0.0 --port 8080
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
      - run: hunterx hunt full_security_assessment {% raw %}${{ secrets.TARGET_URL }}{% endraw %}
```

### GitLab CI

```yaml
scan:
  image: nullc0d30/hunterx:latest
  script:
    - hunterx hunt full_security_assessment $TARGET_URL
  artifacts:
    paths: [artifacts/reports/]
```

## Security

- Container runs as **non-root user** (UID 1000)
- Read-only root filesystem recommended
- Use Docker secrets for credentials
- Enable Docker Content Trust

## Image Tags

- `latest`: Most recent stable release
- `7.0.0`: Specific version
- `stable`: Latest stable release
