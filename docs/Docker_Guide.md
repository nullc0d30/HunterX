# HunterX v6.0.0 Docker Guide

This guide covers running HunterX in Docker containers, including quick start, API mode, building locally, and production considerations.

---

## Quick Start

Pull the latest image:

```bash
docker pull nullc0d30/hunterx:latest
```

Verify the image:

```bash
docker run --rm nullc0d30/hunterx --help
```

Run HunterX with a volume mount for reports:

```bash
docker run --rm \
  -v "$(pwd)/reports:/app/reports" \
  -v "$(pwd)/config.yaml:/app/config.yaml:ro" \
  nullc0d30/hunterx:latest
```

---

## API Mode

Start HunterX in API server mode, exposing port 8443:

```bash
docker run --rm \
  -p 8443:8443 \
  -v "$(pwd)/config.yaml:/app/config.yaml:ro" \
  nullc0d30/hunterx:latest --api
```

Access the API at `https://localhost:8443`.

---

## Building Locally

Build from source:

```bash
git clone https://github.com/NullC0d3/HunterX.git
cd HunterX
docker build -t hunterx .
```

Run your local build:

```bash
docker run --rm hunterx --help
```

---

## Docker Compose

Example `docker-compose.yml`:

```yaml
version: "3.8"

services:
  hunterx:
    image: nullc0d30/hunterx:latest
    container_name: hunterx
    ports:
      - "8443:8443"
    volumes:
      - ./reports:/app/reports
      - ./config.yaml:/app/config.yaml:ro
    environment:
      - HX_AI_PROVIDER=openai
      - HX_AI_API_KEY=${HX_AI_API_KEY}
      - HX_LOG_LEVEL=INFO
    restart: unless-stopped
```

Start with:

```bash
export HX_AI_API_KEY=sk-...
docker compose up -d
```

---

## Production Architecture

The Docker container is engineered for **isolation** and **safety**:

- **User**: Runs as non-root user `hunterx` (UID 999/1000).
- **Network**: Requires egress for target scanning. No ingress ports exposed.
- **Storage**: Maps `/data` volume for reports and logs.
- **Base**: `python:3.11-slim` (Minimal attack surface).
- **Build**: Multi-stage build for minimal image size.
- **Image size**: Approximately 271 MB.
- **Installed packages**: Only runtime dependencies; build tools are excluded in the final stage.
- **Entrypoint**: `hunterx` binary (installed via pip).

### Usage Commands

#### Standard Scan (Bounty Profile)

```bash
docker run --rm \
    -v "$(pwd)/reports:/data" \
    nullc0d30/hunterx \
    -u https://target.com \
    --profile bounty \
    -o /data
```

#### Advanced Profile (Bug Bounty)

```bash
docker run --rm -v $(pwd)/reports:/data nullc0d30/hunterx -u https://target.com --profile bounty --auto -o /data
```

#### High-Stealth Operation

Run as a passive observer with extreme stealth:

```bash
docker run --rm \
    -v "$(pwd)/reports:/data" \
    nullc0d30/hunterx \
    -u https://target.com \
    --profile gov \
    --passive-only \
    -o /data
```

#### Interactive CLI Mode

For debugging (not recommended for automation):

```bash
docker run --rm -it --entrypoint /bin/bash nullc0d30/hunterx
```

*Note: This will still drop you into the restricted `hunterx` user shell.*

---

## Volumes

| Mount Point        | Purpose                          | Required |
|--------------------|----------------------------------|----------|
| `/app/reports`     | Report output directory           | No       |
| `/app/config.yaml` | Configuration file (read-only)    | No       |
| `/app/data`        | Persistent data (payloads, cache) | No       |
| `/app/skills`      | Custom skills directory           | No       |
| `/data`            | Map this volume to persist reports (JSON, HTML) and logs | No |

---

## Environment Variables

Pass HunterX configuration via environment variables prefixed with `HX_`:

| Variable              | Description                    | Example                     |
|-----------------------|--------------------------------|-----------------------------|
| `HX_AI_PROVIDER`      | AI provider to use             | `openai`                    |
| `HX_AI_API_KEY`       | API key for the AI provider    | `sk-...`                    |
| `HX_AI_MODEL`         | Model name                     | `gpt-4o`                    |
| `HX_LOG_LEVEL`        | Log level                      | `INFO`, `DEBUG`             |
| `HX_API_PORT`         | API server port                | `8443`                      |
| `HX_API_HOST`         | API server bind address        | `0.0.0.0`                   |
| `HX_THREAD_POOL_SIZE` | Max concurrent threads         | `10`                        |
| `HX_POLICY_LEVEL`     | Safety policy level            | `default`                   |

---

## Security

- **Run as non-root:** The container runs as the `hunterx` user (UID 1000/999) by default. You cannot install packages or modify system files.
- **Resource limits:** Set Docker memory and CPU limits to prevent resource exhaustion:

```bash
docker run --rm \
  --memory="2g" \
  --cpus="2" \
  nullc0d30/hunterx:latest
```

- **Read-only volumes:** Mount configuration files as read-only (`:ro`).
- **No privileged mode:** Do not run with `--privileged`.
- **No background services or exposed ports:** The container has no exposed ports by default.
- **Volume Permissions:** Ensure your host `reports` directory is writable by the container user or 'others' (`chmod o+w reports`).

---

## Troubleshooting

**Permission Denied on /data**:
The container user `hunterx` likely doesn't have permissions to write to your host folder.
*Fix*: `mkdir -p reports && chmod 777 reports` before running.

**DNS Resolution Failures**:
Ensure Docker has access to working DNS servers.
*Fix*: Add `--dns 8.8.8.8` to your run command.

---

## Docker Hub Metadata

**Image Name**: `nullc0d30/hunterx`

### Short Description
Safe, reasoning-based Red Team orchestration framework. Non-destructive vulnerability verification.

### Full Description

HunterX is a production-grade orchestration framework designed for professional Red Teams. Unlike traditional scanners that rely on volume and brute force, HunterX operates as a **reasoning engine**. It observes, hypothesizes, and verifies vulnerabilities using a strictly gated, 4-stage pipeline.

This tool is engineered for:
- **Safety**: Non-destructive verification only.
- **Stealth**: Human-like jitter, adaptive backoff, and low-noise profiling.
- **Accuracy**: Context-aware precision to eliminate false positives.

---

## Disclaimer

HunterX is a specialized tool for authorized security auditing. The authors accept no liability for misuse. Ensure you have explicit permission to test any target.
