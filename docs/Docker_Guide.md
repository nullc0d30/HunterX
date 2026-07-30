---
layout: default
title: Docker Guide — HunterX v6.0.0
description: >-
  Production-grade Docker deployment guide for HunterX v6.0.0 vulnerability
  scanner. Multi-stage build, multi-architecture (amd64/arm64), non-root user,
  volumes, environment variables, Docker Compose, security best practices, and
  CI/CD publishing for containerized penetration testing.
permalink: /docker/
---

## Docker Guide

HunterX provides an official Docker image published at **`nullc0d30/hunterx`** on Docker Hub. The image is built with multi-stage Dockerfiles for minimal size, runs as a non-root user, and supports `linux/amd64` and `linux/arm64` architectures.

---

## Quick Start

Pull the latest image:

```bash
docker pull nullc0d30/hunterx:latest
```

Verify the image works:

```bash
docker run --rm nullc0d30/hunterx:latest --help
```

---

## Running Scans

### Basic Scan

```bash
docker run --rm \
  -v "$(pwd)/reports:/data" \
  nullc0d30/hunterx:latest \
  -u https://target.com --profile bounty -o /data
```

### Full Scan with All Skills

```bash
docker run --rm \
  -v "$(pwd)/reports:/data" \
  nullc0d30/hunterx:latest \
  -u https://target.com --preset full -o /data
```

### Stealth Scan

```bash
docker run --rm \
  -v "$(pwd)/reports:/data" \
  nullc0d30/hunterx:latest \
  -u https://target.com --stealth high --threads 2 --delay 3 -o /data
```

### AI-Assisted Scan

```bash
docker run --rm \
  -v "$(pwd)/reports:/data" \
  -e OLLAMA_HOST=http://host.docker.internal:11434 \
  nullc0d30/hunterx:latest \
  -u https://target.com --ai --ai-model llama3.2 -o /data
```

### With External Configuration

```bash
docker run --rm \
  -v "$(pwd)/reports:/data" \
  -v "$(pwd)/hunterx.yaml:/app/hunterx.yaml:ro" \
  nullc0d30/hunterx:latest \
  -u https://target.com --profile internal -o /data
```

---

## API Server Mode

Start the REST API server:

```bash
docker run --rm -p 8443:8443 \
  -v "$(pwd)/reports:/data" \
  nullc0d30/hunterx:latest api --port 8443
```

Verify the API is running:

```bash
curl http://localhost:8443/health
```

Submit a scan job:

```bash
curl -X POST http://localhost:8443/scan \
  -H "Content-Type: application/json" \
  -d '{"url": "https://target.com", "profile": "bounty"}'
```

---

## Docker Compose

### CLI Mode (Run a Scan)

```bash
docker compose run --rm hunterx -u https://target.com --profile bounty
```

### API Mode (Persistent Server)

```bash
docker compose --profile api up -d
```

### docker-compose.yml

The included `docker-compose.yml` supports both modes:

```yaml
services:
  hunterx:
    image: nullc0d30/hunterx:latest
    profiles: [cli]
    volumes:
      - ./reports:/data
      - ./hunterx.yaml:/app/hunterx.yaml:ro
    cap_drop: [ALL]
    security_opt: [no-new-privileges:true]

  hunterx-api:
    image: nullc0d30/hunterx:latest
    profiles: [api]
    ports: ["8443:8443"]
    volumes:
      - ./reports:/data
      - ./hunterx.yaml:/app/hunterx.yaml:ro
    command: ["api", "--port", "8443"]
    restart: unless-stopped
    deploy:
      resources:
        limits:
          memory: 2g
          cpus: "2"
```

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `HX_LOG_LEVEL` | `INFO` | Logging verbosity (`DEBUG`, `INFO`, `WARNING`, `ERROR`) |
| `HX_API_PORT` | `8443` | API server port |
| `HX_API_HOST` | `0.0.0.0` | API server bind address |
| `HX_AI_PROVIDER` | — | AI provider name (`openai`, `ollama`) |
| `HX_AI_API_KEY` | — | API key for the AI provider |
| `HX_AI_MODEL` | — | AI model name |
| `HX_THREADS` | `5` | Max concurrent threads |
| `HX_TIMEOUT` | `30` | Request timeout in seconds |
| `HX_MAX_RPS` | `10.0` | Max requests per second |
| `OPENAI_API_KEY` | — | OpenAI API key |
| `OLLAMA_HOST` | — | Ollama server URL |
| `CONFIG_PATH` | `hunterx.yaml` | Path to config file |
| `REPORT_PATH` | `reports/` | Report output directory |

---

## Volumes

| Mount | Purpose | Required |
|---|---|---|
| `/data` | Report output directory | Recommended |
| `/app/hunterx.yaml` | Configuration file (mount as `:ro`) | Optional |
| `/app/payloads/` | Custom payloads directory | Optional |
| `/app/skills/` | Custom skills directory | Optional |

---

## Building Locally

```bash
git clone https://github.com/nullc0d30/HunterX.git
cd HunterX
docker build -t hunterx:local .
docker run --rm hunterx:local -u https://target.com --profile bounty
```

Build with version metadata:

```bash
docker build \
  --build-arg VERSION=6.0.0 \
  --build-arg BUILD_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ) \
  --build-arg VCS_REF=$(git rev-parse --short HEAD) \
  -t hunterx:local .
```

---

## Image Tags

| Tag | Description |
|---|---|
| `latest` | Most recent stable release |
| `stable` | Latest tagged release |
| `6.0.0` | Specific version |
| `6.0` | Major.minor version |
| `6` | Major version |
| `sha-xxxxxx` | Commit-specific build |
| `main` | Latest main branch build (unstable) |

All tags are published to `nullc0d30/hunterx` on Docker Hub.

---

## Security

The container is hardened with security best practices:

- **Non-root user**: Runs as `hunterx` (UID 999). No package installation or system modification.
- **No privileged mode**: Do not use `--privileged`.
- **Capability dropping**: `docker-compose.yml` drops all Linux capabilities.
- **No-new-privileges**: Security opt set in compose configuration.
- **Read-only mounts**: Mount configuration files as `:ro`.
- **Resource limits**: Set memory and CPU limits in production:

```bash
docker run --rm \
  --memory="2g" --cpus="2" \
  -v "$(pwd)/reports:/data" \
  nullc0d30/hunterx:latest \
  -u https://target.com --profile bounty -o /data
```

- **No exposed ports by default**: Only the API server mode exposes port 8443.
- **Image signing** (recommended): Use Cosign to sign images in CI/CD:

```bash
cosign sign --key cosign.key nullc0d30/hunterx:6.0.0
```

---

## CI/CD Integration

### GitHub Actions

```yaml
jobs:
  scan:
    runs-on: ubuntu-latest
    container:
      image: nullc0d30/hunterx:latest
    steps:
      - run: hunterx.py -u ${{ secrets.TARGET_URL }} -o /data --format sarif
```

### GitLab CI

```yaml
scan:
  image: nullc0d30/hunterx:latest
  script:
    - hunterx -u $TARGET_URL -o report.sarif
  artifacts:
    paths: [report.sarif]
```

---

## Troubleshooting

### Permission Denied on /data

The container user `hunterx` needs write access to the host-mounted directory:

```bash
mkdir -p reports && chmod 777 reports
```

Or match the UID:

```bash
docker run --rm -u $(id -u):$(id -g) -v "$(pwd)/reports:/data" nullc0d30/hunterx:latest --help
```

### DNS Resolution Failures

Ensure Docker has working DNS:

```bash
docker run --rm --dns 8.8.8.8 nullc0d30/hunterx:latest --help
```

### Module Not Found Errors

If you built locally with a different Python version, rebuild with the correct base image:

```bash
docker build --build-arg PYTHON_VERSION=3.11 -t hunterx:local .
```

---

## Docker Hub Metadata

- **Image**: `nullc0d30/hunterx`
- **License**: Apache 2.0
- **Base Image**: `python:3.11-slim`
- **Architectures**: `linux/amd64`, `linux/arm64`
- **Source**: [github.com/nullc0d30/HunterX](https://github.com/nullc0d30/HunterX)
- **Documentation**: [nullc0d30.github.io/HunterX](https://nullc0d30.github.io/HunterX)

---

## Responsible Use

HunterX is a tool for authorized security assessments only. Users must obtain explicit written permission before testing any target. The authors accept no liability for misuse. See the [Responsible Use policy]({{ '/responsible-use' | relative_url }}) for full terms.
