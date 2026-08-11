<div align="center">

<img src="logo.png" alt="HunterX Official Logo" width="200" height="auto">

# HunterX

**AI-Powered Security Orchestration &amp; Intelligence Platform**

HunterX v7 plans, orchestrates, executes, validates, correlates and reports
security assessments by integrating open-source security tools. It is an
authorized cybersecurity testing and research platform.

[![GitHub Release](https://img.shields.io/github/v/release/nullc0d30/HunterX?style=flat-square&logo=github)](https://github.com/nullc0d30/HunterX/releases)
[![PyPI Version](https://img.shields.io/pypi/v/hunterx?style=flat-square&logo=pypi)](https://pypi.org/project/hunterx/)
[![Python Version](https://img.shields.io/pypi/pyversions/hunterx?style=flat-square&logo=python)](https://python.org)
[![License](https://img.shields.io/badge/license-Apache%202.0-green?style=flat-square)](https://www.apache.org/licenses/LICENSE-2.0)
[![Tests](https://img.shields.io/github/actions/workflow/status/nullc0d30/HunterX/test.yml?style=flat-square&label=tests)](https://github.com/nullc0d30/HunterX/actions)
[![Docker](https://img.shields.io/badge/docker-multi--stage-2496ED?style=flat-square&logo=docker)](https://hub.docker.com/r/nullc0d30/hunterx)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macOS%20%7C%20windows-lightgrey?style=flat-square)](https://github.com/nullc0d30/HunterX)

</div>

> **Responsible use.** HunterX is an authorized cybersecurity testing and
> research platform. You are responsible for obtaining appropriate
> authorization before testing any system. The author is not responsible for
> misuse, unauthorized access, illegal activity, or damage caused by the
> software. See [Responsible Use](#responsible-use) and
> [SECURITY.md](SECURITY.md).

## Overview

HunterX v7 is a Clean Architecture Python platform for planning and running
authorized security-assessment missions. It integrates open-source security
tools (100+ registered), normalizes their output into a unified model, plans
and chains tool executions, validates hypotheses with evidence, engineers
proofs and PoCs, and produces professional reports.

## Capabilities

- **Autonomous mission orchestration** — create, run, checkpoint and resume
  full-spectrum security-assessment missions (`hunterx mission`, `hunterx hunt`).
- **Adaptive mission planning** — attack-path planning, replanning and
  explainable next-best-action selection.
- **Toolchain intelligence** — machine-readable tool contracts, structured
  execution, output parsing/normalization and dependency-aware chaining
  (`hunterx tools`).
- **Evidence-driven validation** — hypothesis testing, validation verdicts,
  and controlled, safe proof/PoC engineering (`hunterx finding`).
- **Professional reporting** — findings, evidence bundles, remediation plans
  and multi-format exports: markdown, HTML, JSON, SARIF, PDF and package
  (`hunterx report`).
- **Target memory & campaign intelligence** — target snapshots, diffs, coverage
  and revalidation planning (`hunterx target`, `hunterx campaign`).
- **TIDB persistence** — SQL storage with Alembic migrations, events, audit and
  versioning.
- **Security model** — scope and authorization guards, sandboxing,
  evidence-gated confidence, secret masking and hardened XML parsing.

## Installation

Requirements: **Python 3.11+** on Linux, macOS or Windows.

```bash
# Installer script (Linux/macOS)
curl -sSL https://raw.githubusercontent.com/nullc0d30/HunterX/main/install.sh | sudo bash

# Or from PyPI
python -m pip install "hunterx[api,db]"

# Or from source
git clone https://github.com/nullc0d30/HunterX.git
cd HunterX
python -m pip install -e ".[api,db,dev]"
```

Verify:

```bash
hunterx version     # HunterX v7.0.0
hunterx help        # command list
hunterx platform    # platform composition
hunterx config      # resolved configuration
```

See [docs/installation](docs/installation/index.md) for details, including
database initialization (`alembic upgrade head`) and Docker.

## Usage

HunterX v7 organizes work as **missions**. Start with an authorized target:

```bash
# Plan and start a full-spectrum hunt mission
hunterx hunt full_security_assessment https://example.com

# Track it
hunterx hunt status <mission_id>
hunterx hunt surface <mission_id>

# Inspect the toolchain
hunterx tools list
hunterx tools capabilities
hunterx tools health

# Findings and reports
hunterx finding list <mission_id>
hunterx report generate <finding_id>
hunterx report export <report_id> markdown
```

Missions persist to the configured database (SQLite by default), so
`hunterx mission create <objective> <target>` followed by
`hunterx mission start <mission_id>` works across CLI invocations.

## Quick Start

```bash
hunterx help                          # all commands
hunterx platform                      # what is composed
hunterx tools list                    # registered tools
hunterx mission create full_security_assessment https://example.com
hunterx mission start <mission_id>
hunterx mission status <mission_id>
hunterx finding list <mission_id>
hunterx report generate <finding_id>
hunterx report export <report_id> sarif
```

## Configuration

HunterX v7 resolves settings from defaults, an optional profile file
(`HUNTERX_CONFIG` or `hunterx.yaml` in the working directory) and `HUNTERX_*`
environment variables:

```bash
export HUNTERX_DATABASE_URL="postgresql+psycopg://user:pass@host/hunterx"
export HUNTERX_LOG_LEVEL=DEBUG
export HUNTERX_API_PORT=8080
hunterx config
```

See [docs/configuration](docs/configuration/index.md) for the full reference.

## REST API

The v7 REST API is a FastAPI application (`hunterx.api.app:create_app`).
Install the `api` extra and run:

```bash
python -m pip install "hunterx[api]"
uvicorn hunterx.api.app:create_app --host 127.0.0.1 --port 8080
```

API-key authentication is opt-in (admin/read-only roles). See
[docs](docs/documentation.md).

## Docker

```bash
docker build -t nullc0d30/hunterx:7.0.0 .
docker compose up -d hunterx-api
```

The container runs as a non-root user. See
[docs/v7-release-guide.md](docs/v7-release-guide.md).

## Architecture

The v7 core is a Clean Architecture package under `src/hunterx`:

- `domain` — pure domain layer (entities, ports, services)
- `application` — use-case services
- `infrastructure` — adapters (db, cache, queue, secrets, sandbox)
- `engines` — engine facades (mission, workflow, planner, orchestration)
- `tools` — tool adapters and the toolchain intelligence layer
- `agents` — multi-agent platform
- `reporting`, `config`, `cli`, `api` — delivery layers

See [docs/architecture](docs/architecture/README.md) and
[docs/v7-foundation.md](docs/v7-foundation.md).

## Testing & Quality

```bash
pytest -m "not tools"        # full default suite
ruff check src eng tests alembic
mypy eng src/hunterx/shared
python -m bandit -r src/hunterx
python -m eng.gates          # all quality gates
```

## Documentation

- [Documentation Hub](docs/documentation.md)
- [Installation](docs/installation/index.md)
- [CLI Reference](docs/cli/index.md)
- [Quickstart](docs/quickstart.md)
- [Security](docs/security.md)
- [Responsible Use](docs/responsible-use.md)

## License

Copyright (c) 2026 Ahmed Awad (AKA NullC0d3). All rights reserved.

Released under the **Apache License, Version 2.0**. See [LICENSE](LICENSE) and
[NOTICE](NOTICE). Third-party attribution is in
[THIRD_PARTY_NOTICES](THIRD_PARTY_NOTICES).

## Responsible Use

HunterX is an authorized cybersecurity testing and research platform. It is
designed to be used **only** against systems you own or are explicitly
authorized to test. You are responsible for:

- Obtaining **appropriate authorization** (written permission) before testing
  any system.
- Complying with all applicable laws, regulations, and terms of service.
- Handling any data discovered during testing responsibly.

**Disclaimer:** The developer/author (Ahmed Awad / NullC0d3) is not responsible
for misuse, unauthorized access, illegal activity, damage, or any other
unethical use of the software. The software is provided "AS IS" without
warranty of any kind. See [docs/responsible-use.md](docs/responsible-use.md).

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md),
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md), and the
[Development Bible](docs/bible/README.md).
