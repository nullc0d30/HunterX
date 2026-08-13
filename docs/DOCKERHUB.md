# HunterX v7 — AI-Assisted Vulnerability Discovery, Validation & Proof Engine

[![Docker Pulls](https://img.shields.io/docker/pulls/nullc0d30/hunterx)](https://hub.docker.com/r/nullc0d30/hunterx)
[![Docker Stars](https://img.shields.io/docker/stars/nullc0d30/hunterx)](https://hub.docker.com/r/nullc0d30/hunterx)
[![GitHub Release](https://img.shields.io/github/v/release/nullc0d30/HunterX)](https://github.com/nullc0d30/HunterX/releases)
[![License](https://img.shields.io/badge/license-Apache%202.0-green)](https://www.apache.org/licenses/LICENSE-2.0)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/)
[![OWASP Community](https://img.shields.io/badge/OWASP%20Community-listed-green?style=flat-square&logo=owasp)](https://owasp.org/www-community/Vulnerability_Scanning_Tools)

**HunterX** is an open-source, AI-assisted vulnerability discovery, validation and proof engine for authorized security testing. It does not stop at candidate detections: it plans and orchestrates missions, reasons over hypotheses, validates findings with evidence, engineers and replays proofs and PoCs, and produces report-ready output.

This image runs the HunterX v7.0.0 CLI (and REST API) inside a minimal, non-root container.

```text
Discover → Fingerprint → Reason → Hypothesize → Probe → Verify → Prove → PoC → Replay → Correlate → Report
```

---

## Quick Start

```bash
# Pull the current release
docker pull nullc0d30/hunterx:7.0.0

# Verify the version you pulled
docker run --rm nullc0d30/hunterx:7.0.0 version

# Show the command reference
docker run --rm nullc0d30/hunterx:7.0.0 help
```

The image entrypoint is the `hunterx` CLI, which uses subcommands (for example `hunterx version`, `hunterx help`, `hunterx hunt ...`). Running the container with no arguments prints the usage text.

---

## What Is HunterX?

HunterX is an AI-assisted vulnerability discovery, validation and proof engine and red-team framework. It orchestrates the open-source security-tool ecosystem rather than replacing it: HunterX executes tools with structured contracts, normalizes their output, correlates results, reasons over hypotheses, validates with evidence, engineers and replays minimal safe proofs/PoCs, and produces professional reports.

A traditional scanner stops at *"possible SQL injection"*. HunterX is built to investigate the hypothesis, verify the behavior, prove the finding, reproduce the evidence, assess the impact, and turn the result into a report-ready, validated finding:

```text
Detection → Evidence → Verification → Reproduction → PoC → Validated Finding
```

## Key Capabilities

- Autonomous mission orchestration and adaptive mission planning (`hunterx mission`, `hunterx hunt`)
- AI-assisted reasoning through a decoupled AI provider layer — grounded in evidence, never a substitute for it
- Toolchain intelligence layer with 92 registered open-source security tools, machine-readable contracts, structured execution, parsers and normalizers
- Evidence-driven vulnerability validation with proof contracts, replay and reproducibility
- Proof / PoC engineering with minimal safe proofs and evidence-gated confidence and impact
- Target memory and campaign intelligence, including cloud/SaaS attack-surface intelligence and knowledge-graph correlation
- Professional reporting: Markdown, HTML, JSON, SARIF 2.1, PDF and evidence packages
- Persistent mission state (SQLite by default) with the `TIDB` persistence layer
- REST API (FastAPI) with opt-in API-key authentication
- Clean Architecture Python core, Apache-2.0 licensed

---

## Image Tags

| Tag | Purpose |
|---|---|
| `latest` | Most recent build of `main` (currently HunterX v7.0.0) |
| `stable` | Latest tagged stable release (currently HunterX v7.0.0) |
| `7.0.0` | Version-pinned release |
| `7.0` | Minor-version tag |
| `7` | Major-version tag |
| `6.0.0`, `6.0`, `6` | Legacy HunterX v6 images (not current) |
| `4.0.1`, `4.0`, `3.1` | Historical images (not current) |

> **Versioning.** `latest` and `stable` are convenient but move as new builds are pushed. For reproducible deployments, pin a version tag such as `nullc0d30/hunterx:7.0.0`.

---

## Usage

### Verify the installed version

```bash
docker run --rm nullc0d30/hunterx:7.0.0 version
# HunterX v7.0.0
```

### CLI

```bash
# Show the resolved configuration
docker run --rm nullc0d30/hunterx:latest config

# Show platform composition
docker run --rm nullc0d30/hunterx:latest platform

# List the integrated toolchain
docker run --rm nullc0d30/hunterx:latest tools list

# Start a full-spectrum mission against an authorized target
# (requires a target you own or are explicitly authorized to test)
docker run --rm nullc0d30/hunterx:latest hunt full_security_assessment https://YOUR-AUTHORIZED-TARGET
```

Missions, findings, reports and target memory persist to the configured database (SQLite by default), so chained invocations such as `hunterx mission create ...` → `hunterx mission start <mission_id>` work across container runs when the same database volume is mounted.

### REST API

The image ships the FastAPI application. Start it and point a browser at `http://localhost:8080/health`:

```bash
docker run -d --name hunterx-api -p 8080:8080 \
  --entrypoint uvicorn nullc0d30/hunterx:latest \
  --factory hunterx.api.app:create_app --host 0.0.0.0 --port 8080
```

```bash
curl http://localhost:8080/health
# {"status":"ok"}
```

API-key authentication is opt-in. When enabled, every request (except `/health`) requires a valid `X-API-Key` header:

```bash
docker run -d --name hunterx-api -p 8080:8080 \
  -e HUNTERX_API_AUTH_ENABLED=true \
  -e HUNTERX_API_KEY=YOUR_ADMIN_KEY \
  --entrypoint uvicorn nullc0d30/hunterx:latest \
  --factory hunterx.api.app:create_app --host 0.0.0.0 --port 8080
```

### Persistent data

HunterX persists mission state to the database. Mount a volume at `/data` and point the database at it:

```bash
docker run -d --name hunterx-api -p 8080:8080 \
  -v hunterx-data:/data \
  -e HUNTERX_DATABASE_URL=sqlite:////data/hunterx.db \
  --entrypoint uvicorn nullc0d30/hunterx:latest \
  --factory hunterx.api.app:create_app --host 0.0.0.0 --port 8080
```

The container runs as the non-root `hunterx` user and `/data` is writable by it.

### Interactive shell

```bash
docker run -it --rm --entrypoint sh nullc0d30/hunterx:latest
```

### Docker Compose

The repository ships a `docker-compose.yml` with two services:

```bash
docker compose up -d hunterx-api          # API service (port 8080)
docker compose run --rm hunterx help      # CLI service
```

---

## Configuration

Configuration is resolved in this order (each level overrides the previous):

1. Built-in defaults and the bundled `hunterx.yaml` profile
2. A user profile file — `HUNTERX_CONFIG` environment variable, or `hunterx.yaml` in the working directory (`/app`)
3. `HUNTERX_*` environment variables

### Environment variables

| Variable | Default | Description |
|---|---|---|
| `HUNTERX_LOG_LEVEL` | `INFO` | Root logging level |
| `HUNTERX_DATABASE_URL` | `sqlite:///hunterx.db` | SQLAlchemy database URL (e.g. `sqlite:////data/hunterx.db`) |
| `HUNTERX_CACHE_BACKEND` | `memory` | Cache backend (`memory`, `redis`, `null`) |
| `HUNTERX_QUEUE_BACKEND` | `memory` | Queue backend (`memory`, `redis`, `null`) |
| `HUNTERX_API_HOST` | `127.0.0.1` | API bind host |
| `HUNTERX_API_PORT` | `8080` | API port |
| `HUNTERX_API_AUTH_ENABLED` | `false` | Require an API key on every request |
| `HUNTERX_API_KEY` | *(empty)* | Admin API key; when set, authentication is enforced |
| `HUNTERX_API_READ_ONLY_KEY` | *(empty)* | Optional read-only API key |
| `HUNTERX_CONFIG` | *(empty)* | Path to a YAML profile file |
| `HUNTERX_ENVIRONMENT` | `production` | Environment name (`dev`, `staging`, `production`) |

Example:

```bash
docker run --rm \
  -e HUNTERX_LOG_LEVEL=DEBUG \
  -e HUNTERX_DATABASE_URL=sqlite:////data/hunterx.db \
  nullc0d30/hunterx:7.0.0 config
```

> **Secrets.** Do not commit API keys or credentials. Pass secrets at runtime via `HUNTERX_*` environment variables or Docker secrets, and never place real credentials in a checked-in `hunterx.yaml`.

---

## Docker Security

- The container runs as the **non-root** `hunterx` user (UID 999) and exposes a single writable volume at `/data` for persistent state.
- The image is multi-stage, based on `python:3.11-slim`, and publishes OCI labels (source, license, version) for supply-chain inspection.
- Use **pinned image tags** (`nullc0d30/hunterx:7.0.0`) for reproducible deployments.
- Protect API credentials: enable `HUNTERX_API_AUTH_ENABLED`, use a strong `HUNTERX_API_KEY`, and do not expose the API port beyond your trusted network.
- Review anything you mount into the container — mounted host paths are visible to the container process.
- HunterX executes security tooling that can generate active traffic. Only run it against systems you own or are explicitly authorized to test.

---

## Responsible Use

HunterX is intended exclusively for **authorized security testing**: penetration testing, in-scope bug bounty programs, red-team operations, defensive security research, and laboratory environments. You are responsible for obtaining written authorization before testing any system and for complying with all applicable laws and terms of service. HunterX is licensed under Apache 2.0 and provided "AS IS" without warranty.

See [Responsible Use](https://nullc0d30.github.io/HunterX/responsible-use/) and the [Security Policy](https://nullc0d30.github.io/HunterX/security/).

---

## Troubleshooting

| Problem | Likely cause | Action |
|---|---|---|
| `docker run ...` prints usage text | The CLI uses subcommands; no default command was supplied | Use `hunterx help` or a specific command such as `hunterx version` |
| `permission denied` writing state | The database path is not writable by the `hunterx` user | Mount a volume at `/data` and use `HUNTERX_DATABASE_URL=sqlite:////data/hunterx.db` |
| API returns `401` | Authentication is enabled and the request has no/incorrect key | Send a valid `X-API-Key` header |
| Wrong version behavior | Running a legacy `6.x`/`4.x` image or an old `latest` | Pull a v7 tag and run `hunterx version` to confirm |
| Config looks wrong | Env var name or YAML profile error | Run `docker run --rm nullc0d30/hunterx:latest config` to inspect the resolved configuration |

---

## Documentation & Resources

- Repository: [github.com/nullc0d30/HunterX](https://github.com/nullc0d30/HunterX)
- Documentation: [nullc0d30.github.io/HunterX](https://nullc0d30.github.io/HunterX/)
- Quickstart: [Quickstart](https://nullc0d30.github.io/HunterX/quickstart/)
- Installation: [Installation](https://nullc0d30.github.io/HunterX/installation/)
- CLI Reference: [CLI Reference](https://nullc0d30.github.io/HunterX/cli/)
- Configuration: [Configuration](https://nullc0d30.github.io/HunterX/configuration/)
- Architecture: [Architecture](https://nullc0d30.github.io/HunterX/architecture/)
- PoC & Validation: [PoC & Validation](https://nullc0d30.github.io/HunterX/poc-validation/)
- Tool Ecosystem: [Tool Ecosystem](https://nullc0d30.github.io/HunterX/tool-ecosystem/)
- What's New in v7: [v7 Release](https://nullc0d30.github.io/HunterX/v7-release/)
- FAQ: [FAQ](https://nullc0d30.github.io/HunterX/faq/)
- Changelog: [Changelog](https://nullc0d30.github.io/HunterX/changelog/)
- Security: [Security Policy](https://nullc0d30.github.io/HunterX/security/)
- Responsible Use: [Responsible Use](https://nullc0d30.github.io/HunterX/responsible-use/)
- Report issues: [GitHub Issues](https://github.com/nullc0d30/HunterX/issues)

HunterX is created and maintained by [Ahmed Awad (NullC0d3)](https://github.com/nullc0d30), released under the Apache License 2.0.
